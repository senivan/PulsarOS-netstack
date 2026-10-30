#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <rte_eal.h>
#include <rte_pause.h>
#include <rte_cycles.h>
#include "dpdk_port.h"

struct port_state *netif_by_dpdk_port(struct app_runtime *rt, uint16_t id)
{
    for (uint16_t i = 0; i < rt->port_count; i++)
        if (rt->ports[i].configured && rt->ports[i].port_id == id) return &rt->ports[i];
    return NULL;
}

const struct port_state *netif_by_id(const struct app_runtime *rt, uint16_t id)
{
    if (id < rt->port_count && rt->ports[id].configured && rt->ports[id].id == id) return &rt->ports[id];
    for (uint16_t i = 0; i < rt->port_count; i++)
        if (rt->ports[i].configured && rt->ports[i].id == id) return &rt->ports[i];
    return NULL;
}

int netif_is_local_ip(const struct app_runtime *rt, uint32_t ip_be)
{
    if (rt->network) {
        for (unsigned i = 0; i < rt->network->address_count; i++) {
            const struct net_address *a = &rt->network->addresses[i];
            if (a->ip == ip_be && netif_by_id(rt, a->dev)) return 1;
        }
        return 0;
    }
    for (uint16_t i = 0; i < rt->port_count; i++)
        if (rt->ports[i].configured && net_address_on(rt, rt->ports[i].id, ip_be)) return 1;
    return 0;
}

int app_init(const char *progname, const struct app_config *conf, struct app_runtime *rt)
{
    memset(rt, 0, sizeof(*rt));
    rt->ipv4_forwarding = conf->ipv4_forwarding;
    if (eal_init(progname, conf) < 0) return -1;
    if (port_init(conf, rt) < 0 || graph_init(rt) < 0 || socket_subsystem_init(rt) < 0) {
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
        if (!port->configured || !port->started || port->admin_down) continue;
        struct node_frame frame = {0};
        frame.count = rte_eth_rx_burst(port->port_id, 0, frame.pkts, GRAPH_FRAME_SIZE);
        for (uint16_t i = 0; i < frame.count; i++)
            frame.ctxs[i].ingress_port_id = port->port_id;
        received += frame.count;
        port->rx_packets += frame.count;
        for (unsigned i = 0; i < frame.count; i++) port->rx_bytes += rte_pktmbuf_pkt_len(frame.pkts[i]);
        if (frame.count) graph_submit(rt, NODE_ETH_INPUT, &frame);
    }
    uint64_t now = rte_get_timer_cycles();
    neighbour_tick(rt, now);
    tcp_tick(rt, now);
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
    printf("ICMP errors: generated=%llu suppressed=%llu rate_limited=%llu failed=%llu\n",
           (unsigned long long)rt->icmp_errors.generated,
           (unsigned long long)rt->icmp_errors.suppressed,
           (unsigned long long)rt->icmp_errors.rate_limited,
           (unsigned long long)rt->icmp_errors.failed);
    printf("TCP: syns=%llu established=%llu closed=%llu resets=%llu retransmissions=%llu timeouts=%llu\n",
           (unsigned long long)rt->tcp_stats.syns, (unsigned long long)rt->tcp_stats.established,
           (unsigned long long)rt->tcp_stats.closed, (unsigned long long)rt->tcp_stats.resets,
           (unsigned long long)rt->tcp_stats.retransmissions, (unsigned long long)rt->tcp_stats.timeouts);
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
    socket_subsystem_fini(rt);
    neighbour_fini(rt);
    free(rt->network);
    rt->network = NULL;
    port_fini(rt);
    rte_eal_cleanup();
}
