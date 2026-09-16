#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include "config.h"
#include "runtime.h"
#include "ps_udp.h"

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
    if (ps_udp_bind(&rt, 9000) < 0) { app_fini(&rt); return 1; }
    signal(SIGINT, request_stop);
    signal(SIGTERM, request_stop);
    puts("initialized one DPDK port; entering host input loop");
    puts("udp_echo: bound UDP port 9000");
    fflush(stdout);
    while (!rt.stop) {
        app_step(&rt);
        for (unsigned i = 0; i < PS_UDP_RX_QUEUE_SIZE; i++) {
            uint8_t payload[PS_UDP_MAX_PAYLOAD];
            struct ps_addr peer;
            ssize_t length = ps_udp_recvfrom(&rt, 9000, payload, sizeof(payload), &peer);
            if (length == -EAGAIN) break;
            if (length < 0) { fprintf(stderr, "UDP receive failed: %zd\n", length); break; }
            ssize_t sent = ps_udp_sendto(&rt, 9000, payload, (size_t)length, &peer);
            if (sent < 0) fprintf(stderr, "UDP send failed: %zd\n", sent);
        }
    }
    app_dump_stats(&rt);
    app_fini(&rt);
    return 0;
}
