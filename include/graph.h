#pragma once
#ifndef GRAPH_H
#define GRAPH_H

#include <stdint.h>
#include <rte_ether.h>
#include <rte_mbuf.h>
#include "constants.h"
#include "node.h"
#include "packet.h"

struct app_runtime;

struct node_frame {
    struct rte_mbuf *pkts[GRAPH_FRAME_SIZE];
    struct packet_ctx ctxs[GRAPH_FRAME_SIZE];
    uint16_t count;
};

struct graph_frame_slot { struct node_frame frame; enum node_id node; uint8_t used; };
struct dp_graph {
    struct dp_node nodes[NODE_MAX];
    struct graph_frame_slot slots[GRAPH_FRAME_POOL_SIZE];
    uint16_t queue[GRAPH_FRAME_POOL_SIZE];
    uint16_t q_head, q_tail, q_count;
    uint64_t drop_reasons[DROP_REASON_MAX];
};

struct node_output { struct app_runtime *rt; uint16_t pending[NODE_MAX]; };

int graph_init(struct app_runtime *rt);
int graph_submit(struct app_runtime *rt, enum node_id node, const struct node_frame *frame);
int node_enqueue(struct node_output *out, enum node_id node, struct rte_mbuf *m,
                 const struct packet_ctx *ctx);
void graph_drop(struct app_runtime *rt, enum node_id owner, struct rte_mbuf *m,
                struct packet_ctx *ctx, enum drop_reason reason, int error);
void graph_dump_stats(const struct app_runtime *rt);
void nodes_register(struct app_runtime *rt);

#endif
