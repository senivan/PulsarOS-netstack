#include <arpa/inet.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <rte_cycles.h>
#include "config.h"
#include "runtime.h"
#include "ps_udp.h"

int main(int argc, char **argv)
{
    if (argc != 3) return 2;
    struct app_config conf;
    static struct app_runtime rt;
    char error[256];
    struct ps_addr dst = { .port = 9001 };
    if (inet_pton(AF_INET, argv[2], &dst.ip_be) != 1 ||
        app_config_load(argv[1], &conf, error, sizeof(error))) return 2;
    if (app_init(argv[0], &conf, &rt)) return 1;
    const char payload[] = "active-arp";
    int rc = 1;
    if (ps_udp_bind(&rt, 9000) ||
        ps_udp_sendto(&rt, 9000, payload, sizeof(payload) - 1, &dst) != sizeof(payload) - 1) goto done;
    uint64_t start = rte_get_timer_cycles();
    while (rte_get_timer_cycles() - start < 5 * rte_get_timer_hz()) {
        app_step(&rt);
        char response[32];
        struct ps_addr peer;
        ssize_t n = ps_udp_recvfrom(&rt, 9000, response, sizeof(response), &peer);
        if (n == -EAGAIN) continue;
        if (n == sizeof(payload) - 1 && !memcmp(payload, response, (size_t)n) &&
            peer.ip_be == dst.ip_be && peer.port == dst.port) rc = 0;
        break;
    }
done:
    neighbour_fini(&rt);
    app_dump_stats(&rt);
    app_fini(&rt);
    return rc;
}
