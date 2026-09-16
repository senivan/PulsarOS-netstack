#pragma once

#include "runtime.h"

static inline void node_drop(struct app_runtime *rt, enum node_id node,
                             struct rte_mbuf *m, struct packet_ctx *ctx,
                             enum drop_reason reason, int error)
{
    graph_drop(rt, node, m, ctx, reason, error);
}

void drop_node_run(struct app_runtime *, const struct node_frame *, struct node_output *);
void eth_input_node_run(struct app_runtime *, const struct node_frame *, struct node_output *);
void arp_input_node_run(struct app_runtime *, const struct node_frame *, struct node_output *);
void ipv4_input_node_run(struct app_runtime *, const struct node_frame *, struct node_output *);
void icmp_input_node_run(struct app_runtime *, const struct node_frame *, struct node_output *);
void udp_input_node_run(struct app_runtime *, const struct node_frame *, struct node_output *);
void tcp_input_node_run(struct app_runtime *, const struct node_frame *, struct node_output *);
void tx_node_run(struct app_runtime *, const struct node_frame *, struct node_output *);
void ipv4_output_node_run(struct app_runtime *, const struct node_frame *, struct node_output *);
void eth_output_node_run(struct app_runtime *, const struct node_frame *, struct node_output *);
void udp_output_node_run(struct app_runtime *, const struct node_frame *, struct node_output *);
