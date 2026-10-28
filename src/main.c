#define _GNU_SOURCE
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <rte_cycles.h>
#include <rte_pause.h>
#include "config.h"
#include "runtime.h"
#include "daemon.h"
#include "admin_service.h"

static atomic_int stopping;

static void request_stop(int signo)
{
    (void)signo;
    atomic_store_explicit(&stopping, 1, memory_order_relaxed);
}

static int capacity(const char *text, unsigned limit, unsigned *out)
{
    if (!*text) return -1;
    for (const char *p = text; *p; p++) if (*p < '0' || *p > '9') return -1;
    char *end;
    errno = 0;
    unsigned long n = strtoul(text, &end, 10);
    if (errno || *end || !n || n > limit) return -1;
    *out = (unsigned)n;
    return 0;
}

int main(int argc, char **argv)
{
    _Static_assert(DAEMON_SOCKET_MAX == PS_SOCKET_MAX, "control map must hold the whole core registry");
    if (argc < 2) goto usage;
    const char *path = PS_DEFAULT_SOCKET;
    const char *admin_path = NULL;
    char derived_admin[108];
    unsigned max_clients = DAEMON_CLIENT_MAX, max_sockets = PS_SOCKET_MAX;
    for (int i = 2; i < argc; i += 2) {
        if (i + 1 == argc) goto usage;
        if (!strcmp(argv[i], "--socket")) path = argv[i + 1];
        else if (!strcmp(argv[i], "--admin-socket")) admin_path = argv[i + 1];
        else if (!strcmp(argv[i], "--max-sockets")) {
            if (capacity(argv[i + 1], PS_SOCKET_MAX, &max_sockets)) goto usage;
        } else if (!strcmp(argv[i], "--max-clients")) {
            if (capacity(argv[i + 1], DAEMON_CLIENT_MAX, &max_clients)) goto usage;
        } else goto usage;
    }
    if (!admin_path) {
        if (!strcmp(path, PS_DEFAULT_SOCKET)) admin_path = ADMIN_DEFAULT_SOCKET;
        else {
            if (snprintf(derived_admin, sizeof(derived_admin), "%s.admin", path) >= (int)sizeof(derived_admin)) goto usage;
            admin_path = derived_admin;
        }
    }
    struct app_config conf;
    static struct app_runtime rt;
    char error[256];
    if (app_config_load(argv[1], &conf, error, sizeof(error))) {
        fprintf(stderr, "failed to load config: %s\n", error);
        return 1;
    }
    struct daemon_service *service = calloc(1, sizeof(*service));
    if (!service) return 1;
    int rc = daemon_prepare(service, path, max_clients, max_sockets);
    if (rc) {
        fprintf(stderr, "IPC startup failed: %s\n", strerror(-rc));
        daemon_release(service);
        free(service);
        return 1;
    }
    cpu_set_t allowed;
    if (sched_getaffinity(0, sizeof(allowed), &allowed)) {
        daemon_release(service);
        free(service);
        return 1;
    }
    service->control_cpus = allowed;
    if (conf.lcore < CPU_SETSIZE) CPU_CLR(conf.lcore, &service->control_cpus);
    if (!CPU_COUNT(&service->control_cpus)) service->control_cpus = allowed;
    struct sigaction action = { .sa_handler = request_stop };
    sigemptyset(&action.sa_mask);
    sigaction(SIGINT, &action, NULL);
    sigaction(SIGTERM, &action, NULL);
    if (app_init(argv[0], &conf, &rt)) {
        fprintf(stderr, "netstack initialization failed\n");
        daemon_release(service);
        free(service);
        return 1;
    }
    struct admin_service *admin = calloc(1, sizeof(*admin));
    if (!admin) { app_fini(&rt); daemon_release(service); free(service); return 1; }
    rc = net_config_init(&rt);
    if (!rc) rc = admin_prepare(admin, admin_path, service);
    else { free(admin); admin = NULL; }
    if (!rc && chmod(path, 0666)) rc = -errno;
    if (rc) {
        fprintf(stderr, "management startup failed: %s\n", strerror(-rc));
        if (admin) { admin_release(admin); free(admin); }
        app_fini(&rt); daemon_release(service); free(service); return 1;
    }
    rt.admin_started = rte_get_timer_cycles();
    rt.sockets.capacity = max_sockets;
    rc = daemon_start(service);
    if (rc) {
        fprintf(stderr, "control thread startup failed: %s\n", strerror(-rc));
        admin_release(admin); free(admin);
        app_fini(&rt);
        daemon_release(service);
        free(service);
        return 1;
    }
    rc = admin_start(admin);
    if (rc) {
        atomic_store(&service->stopping, 1);
        while (!atomic_load(&service->done)) { daemon_progress(service, &rt); app_step(&rt); }
        pthread_join(service->thread, NULL);
        admin_release(admin); free(admin); app_fini(&rt); daemon_release(service); free(service); return 1;
    }
    printf("management listening on %s\n", admin_path);
    if (rt.port_count == 1) puts("initialized one DPDK port; entering host input loop");
    else printf("initialized %u DPDK ports; entering host input loop\n", rt.port_count);
    printf("IPC listening on %s; max_sockets=%u max_clients=%u\n", path, max_sockets, max_clients);
    fflush(stdout);
    while (!atomic_load_explicit(&stopping, memory_order_relaxed) && !atomic_load(&service->failed) && !atomic_load(&admin->failed)) {
        unsigned commands = daemon_progress(service, &rt) + admin_progress(admin, &rt);
        if (!app_step(&rt) && !commands) rte_pause();
    }
    atomic_store_explicit(&admin->stopping, 1, memory_order_release);
    while (!atomic_load_explicit(&admin->done, memory_order_acquire)) { admin_progress(admin, &rt); app_step(&rt); }
    pthread_join(admin->thread, NULL);
    atomic_store_explicit(&service->stopping, 1, memory_order_release);
    while (!atomic_load_explicit(&service->done, memory_order_acquire)) {
        daemon_progress(service, &rt);
        app_step(&rt);
    }
    pthread_join(service->thread, NULL);
    uint64_t start = rte_get_timer_cycles();
    while (rte_get_timer_cycles() - start < rte_get_timer_hz()) app_step(&rt);
    neighbour_fini(&rt);
    app_dump_stats(&rt);
    rc = atomic_load(&service->failed) || atomic_load(&admin->failed);
    admin_release(admin); free(admin);
    app_fini(&rt);
    daemon_release(service);
    free(service);
    return rc ? 1 : 0;
usage:
    fprintf(stderr, "usage: %s <config.conf> [--socket PATH] [--admin-socket PATH] [--max-sockets 1..%u] [--max-clients 1..%u]\n",
            argv[0], PS_SOCKET_MAX, DAEMON_CLIENT_MAX);
    return 2;
}
