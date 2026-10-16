#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include "config.h"
#include "runtime.h"
#include "ps_socket.h"

static struct app_runtime rt;

static void request_stop(int signo)
{
    (void)signo;
    rt.stop = 1;
}

int main(int argc, char **argv)
{
    if (argc != 2) { fprintf(stderr, "usage: %s <config.conf>\n", argv[0]); return 2; }
    struct app_config conf;
    char error[256];
    if (app_config_load(argv[1], &conf, error, sizeof(error)) < 0) {
        fprintf(stderr, "failed to load config: %s\n", error);
        return 1;
    }
    if (app_init(argv[0], &conf, &rt) < 0) return 1;
    ps_fd_t udp_fd = ps_socket(PS_AF_INET, PS_SOCK_DGRAM, 0);
    if (udp_fd < 0 || ps_bind(udp_fd, &(struct ps_sockaddr){ .port = 9000 }) < 0) { app_fini(&rt); return 1; }
    signal(SIGINT, request_stop);
    signal(SIGTERM, request_stop);
    if (rt.port_count == 1) puts("initialized one DPDK port; entering host input loop");
    else printf("initialized %u DPDK ports; entering host input loop\n", rt.port_count);
    puts("udp_echo: bound UDP port 9000");
    fflush(stdout);
    while (!rt.stop) {
        app_step(&rt);
        for (unsigned i = 0; i < PS_DGRAM_QUEUE_SIZE; i++) {
            uint8_t payload[PS_DGRAM_MAX_PAYLOAD];
            struct ps_sockaddr peer;
            ssize_t length = ps_recvfrom(udp_fd, payload, sizeof(payload), &peer);
            if (length == -EAGAIN) break;
            if (length < 0) { fprintf(stderr, "UDP receive failed: %zd\n", length); break; }
            ssize_t sent = ps_sendto(udp_fd, payload, (size_t)length, &peer);
            if (sent < 0) fprintf(stderr, "UDP send failed: %zd\n", sent);
        }
    }
    ps_close(udp_fd);
    neighbour_fini(&rt);
    app_dump_stats(&rt);
    app_fini(&rt);
    return 0;
}
