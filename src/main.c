#include <signal.h>
#include <stdio.h>
#include "config.h"
#include "runtime.h"

static struct app_runtime *active_runtime;

static void request_stop(int signo)
{
    (void)signo;
    if (active_runtime) active_runtime->stop = 1;
}

int main(int argc, char **argv)
{
    if (argc != 2) { fprintf(stderr, "usage: %s <config.conf>\n", argv[0]); return 2; }
    struct app_config conf;
    static struct app_runtime rt;
    char err[256];
    if (app_config_load(argv[1], &conf, err, sizeof(err)) < 0) {
        fprintf(stderr, "failed to load config: %s\n", err);
        return 1;
    }
    if (app_init(argv[0], &conf, &rt) < 0) {
        fprintf(stderr, "netstack initialization failed\n");
        return 1;
    }
    active_runtime = &rt;
    signal(SIGINT, request_stop);
    signal(SIGTERM, request_stop);
    if (rt.port_count == 1) puts("initialized one DPDK port; entering host input loop");
    else printf("initialized %u DPDK ports; entering host input loop\n", rt.port_count);
    fflush(stdout);
    int rc = app_run(&rt);
    app_dump_stats(&rt);
    app_fini(&rt);
    active_runtime = NULL;
    return rc ? 1 : 0;
}
