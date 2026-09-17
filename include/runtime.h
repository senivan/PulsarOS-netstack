#pragma once

#include <signal.h>
#include <rte_ethdev.h>
#include "app.h"
#include "graph.h"
#include "neighbour.h"
#include "udp.h"
#include "route.h"

struct port_state {
    uint16_t id, port_id, mtu;
    uint32_t ip_be;
    uint8_t prefix_len, configured, started;
    struct rte_ether_addr mac;
    uint64_t rx_packets, tx_packets, tx_drops;
};

struct app_runtime {
    struct rte_mempool *mbuf_pool;
    struct port_state ports[NETIF_MAX];
    uint16_t port_count;
    struct route_table routes;
    struct dp_graph graph;
    struct neighbour_table neighbours;
    struct udp_endpoints udp;
    uint64_t neighbour_learn_failures;
    uint16_t next_ip_id;
    struct node_output *active_output;
    volatile sig_atomic_t stop;
    uint64_t tx_packets;
};

struct port_state *netif_by_dpdk_port(struct app_runtime *rt, uint16_t port_id);
const struct port_state *netif_by_id(const struct app_runtime *rt, uint16_t id);
int netif_is_local_ip(const struct app_runtime *rt, uint32_t ip_be);
int app_init(const char *progname, const struct app_config *conf, struct app_runtime *rt);
/* Process one RX burst without blocking. Call application APIs between steps,
 * on the same lcore; the graph is completely drained before this returns. */
unsigned app_step(struct app_runtime *rt);
int app_run(struct app_runtime *rt);
void app_fini(struct app_runtime *rt);
void app_dump_stats(const struct app_runtime *rt);
