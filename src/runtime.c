#include <stdio.h>
#include <string.h>
#include <rte_eal.h>
#include <rte_pause.h>
#include "dpdk_port.h"

int app_init(const char *progname, const struct app_config *conf, struct app_runtime *rt)
{
    memset(rt, 0, sizeof(*rt));
    if (eal_init(progname, conf) < 0) return -1;
    if (port_init(conf, rt) < 0 || graph_init(rt) < 0) {
        app_fini(rt);
        return -1;
    }
    return 0;
}

int app_run(struct app_runtime *rt)
{
    while (!rt->stop) {
        struct node_frame frame = {0};
        frame.count = rte_eth_rx_burst(rt->port.port_id, 0, frame.pkts, GRAPH_FRAME_SIZE);
        if (!frame.count) { rte_pause(); continue; }
        for (uint16_t i = 0; i < frame.count; i++)
            frame.ctxs[i].ingress_port_id = rt->port.port_id;
        graph_submit(rt, NODE_ETH_INPUT, &frame);
    }
    return 0;
}

void app_dump_stats(const struct app_runtime *rt)
{
    graph_dump_stats(rt);
    printf("neighbour learn failures: %llu\n", (unsigned long long)rt->neighbour_learn_failures);
    printf("transmitted packets: %llu\n", (unsigned long long)rt->tx_packets);
    struct rte_eth_stats stats;
    if (rte_eth_stats_get(rt->port.port_id, &stats) == 0)
        printf("port: rx=%llu tx=%llu missed=%llu rx_errors=%llu tx_errors=%llu no_mbuf=%llu\n",
               (unsigned long long)stats.ipackets, (unsigned long long)stats.opackets,
               (unsigned long long)stats.imissed, (unsigned long long)stats.ierrors,
               (unsigned long long)stats.oerrors, (unsigned long long)stats.rx_nombuf);
}

void app_fini(struct app_runtime *rt)
{
    port_fini(rt);
    rte_eal_cleanup();
}
