#pragma once

#include <signal.h>
#include <rte_ethdev.h>
#include "app.h"
#include "graph.h"
#include "neighbour.h"

struct port_state {
    uint16_t port_id, mtu;
    uint32_t ip_be;
    uint8_t prefix_len, configured, started;
    struct rte_ether_addr mac;
};

struct app_runtime {
    struct rte_mempool *mbuf_pool;
    struct port_state port;
    struct dp_graph graph;
    struct neighbour_table neighbours;
    uint64_t neighbour_learn_failures;
    uint16_t next_ip_id;
    struct node_output *active_output;
    volatile sig_atomic_t stop;
    uint64_t tx_packets;
};

int app_init(const char *progname, const struct app_config *conf, struct app_runtime *rt);
int app_run(struct app_runtime *rt);
void app_fini(struct app_runtime *rt);
void app_dump_stats(const struct app_runtime *rt);
