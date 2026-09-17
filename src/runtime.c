#include <stdio.h>
#include <string.h>
#include <rte_eal.h>
#include <rte_pause.h>
#include "dpdk_port.h"

struct port_state *netif_by_dpdk_port(struct app_runtime *rt, uint16_t id)
{
    for (uint16_t i = 0; i < rt->port_count; i++)
        if (rt->ports[i].configured && rt->ports[i].port_id == id) return &rt->ports[i];
    return NULL;
}

const struct port_state *netif_by_id(const struct app_runtime *rt, uint16_t id)
{
    for (uint16_t i = 0; i < rt->port_count; i++)
        if (rt->ports[i].configured && rt->ports[i].id == id) return &rt->ports[i];
    return NULL;
}

int netif_is_local_ip(const struct app_runtime *rt, uint32_t ip_be)
{
    for (uint16_t i = 0; i < rt->port_count; i++)
        if (rt->ports[i].configured && rt->ports[i].ip_be == ip_be) return 1;
    return 0;
}

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

unsigned app_step(struct app_runtime *rt)
{
    unsigned received = 0;
    for (uint16_t p = 0; p < rt->port_count; p++) {
        struct port_state *port = &rt->ports[p];
        if (!port->configured || !port->started) continue;
        struct node_frame frame = {0};
        frame.count = rte_eth_rx_burst(port->port_id, 0, frame.pkts, GRAPH_FRAME_SIZE);
        for (uint16_t i = 0; i < frame.count; i++)
            frame.ctxs[i].ingress_port_id = port->port_id;
        received += frame.count;
        port->rx_packets += frame.count;
        if (frame.count) graph_submit(rt, NODE_ETH_INPUT, &frame);
    }
    return received;
}

int app_run(struct app_runtime *rt)
{
    while (!rt->stop) if (!app_step(rt)) rte_pause();
    return 0;
}

void app_dump_stats(const struct app_runtime *rt)
{
    graph_dump_stats(rt);
    printf("neighbour learn failures: %llu\n", (unsigned long long)rt->neighbour_learn_failures);
    printf("transmitted packets: %llu\n", (unsigned long long)rt->tx_packets);
    for (uint16_t i = 0; i < rt->port_count; i++) {
        const struct port_state *port = &rt->ports[i];
        printf("interface %u (DPDK %u): rx=%llu tx=%llu tx_drops=%llu\n", port->id, port->port_id,
               (unsigned long long)port->rx_packets, (unsigned long long)port->tx_packets,
               (unsigned long long)port->tx_drops);
        struct rte_eth_stats stats;
        if (rte_eth_stats_get(port->port_id, &stats) == 0)
            printf("port %u: rx=%llu tx=%llu missed=%llu rx_errors=%llu tx_errors=%llu no_mbuf=%llu\n", port->port_id,
               (unsigned long long)stats.ipackets, (unsigned long long)stats.opackets,
               (unsigned long long)stats.imissed, (unsigned long long)stats.ierrors,
               (unsigned long long)stats.oerrors, (unsigned long long)stats.rx_nombuf);
    }
}

void app_fini(struct app_runtime *rt)
{
    port_fini(rt);
    rte_eal_cleanup();
}
