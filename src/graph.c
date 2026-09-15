#include <stdio.h>
#include <string.h>
#include "runtime.h"

static int slot_alloc(struct dp_graph *g)
{
    for (uint16_t i = 0; i < GRAPH_FRAME_POOL_SIZE; i++) {
        if (!g->slots[i].used) {
            g->slots[i].used = 1;
            g->slots[i].frame.count = 0;
            return i;
        }
    }
    return -1;
}

static int queue_slot(struct dp_graph *g, uint16_t slot)
{
    if (g->q_count == GRAPH_FRAME_POOL_SIZE) return -1;
    g->queue[g->q_tail] = slot;
    g->q_tail = (uint16_t)((g->q_tail + 1) % GRAPH_FRAME_POOL_SIZE);
    g->q_count++;
    return 0;
}

static int flush_pending(struct node_output *out, enum node_id node)
{
    uint16_t slot = out->pending[node];
    if (slot == UINT16_MAX) return 0;
    out->pending[node] = UINT16_MAX;
    if (queue_slot(&out->rt->graph, slot) == 0) return 0;
    struct node_frame *f = &out->rt->graph.slots[slot].frame;
    for (uint16_t i = 0; i < f->count; i++) rte_pktmbuf_free(f->pkts[i]);
    out->rt->graph.slots[slot].used = 0;
    out->rt->graph.drop_reasons[DROP_GRAPH_FULL] += f->count;
    out->rt->graph.nodes[node].stats.drops += f->count;
    out->rt->graph.nodes[node].stats.errors += f->count;
    return -1;
}

int node_enqueue(struct node_output *out, enum node_id node, struct rte_mbuf *m,
                 const struct packet_ctx *ctx)
{
    if (!m || (unsigned)node >= NODE_MAX) return -1;
    uint16_t slot = out->pending[node];
    if (slot == UINT16_MAX) {
        int allocated = slot_alloc(&out->rt->graph);
        if (allocated < 0) {
            out->rt->graph.drop_reasons[DROP_GRAPH_FULL]++;
            out->rt->graph.nodes[node].stats.drops++;
            out->rt->graph.nodes[node].stats.errors++;
            rte_pktmbuf_free(m);
            return -1;
        }
        slot = (uint16_t)allocated;
        out->pending[node] = slot;
        out->rt->graph.slots[slot].node = node;
    }
    struct node_frame *f = &out->rt->graph.slots[slot].frame;
    f->pkts[f->count] = m;
    f->ctxs[f->count] = *ctx;
    f->count++;
    if (f->count == GRAPH_FRAME_SIZE) return flush_pending(out, node);
    return 0;
}

void graph_drop(struct app_runtime *rt, enum node_id owner, struct rte_mbuf *m,
                struct packet_ctx *ctx, enum drop_reason reason, int error)
{
    ctx->drop_reason = (uint8_t)reason;
    rt->graph.nodes[owner].stats.drops++;
    if (error) rt->graph.nodes[owner].stats.errors++;
    if (rt->active_output) { node_enqueue(rt->active_output, NODE_DROP, m, ctx); return; }
    struct node_output out = { .rt = rt };
    for (unsigned n = 0; n < NODE_MAX; n++) out.pending[n] = UINT16_MAX;
    if (node_enqueue(&out, NODE_DROP, m, ctx) == 0) flush_pending(&out, NODE_DROP);
}

int graph_init(struct app_runtime *rt)
{
    memset(&rt->graph, 0, sizeof(rt->graph));
    nodes_register(rt);
    for (unsigned i = 0; i < NODE_MAX; i++) if (!rt->graph.nodes[i].run) return -1;
    return 0;
}

int graph_submit(struct app_runtime *rt, enum node_id node, const struct node_frame *frame)
{
    if ((unsigned)node >= NODE_MAX || !frame || frame->count > GRAPH_FRAME_SIZE) return -1;
    struct node_output seed = { .rt = rt };
    for (unsigned n = 0; n < NODE_MAX; n++) seed.pending[n] = UINT16_MAX;
    for (uint16_t i = 0; i < frame->count; i++) {
        if (node_enqueue(&seed, node, frame->pkts[i], &frame->ctxs[i]) < 0) {
            continue;
        }
    }
    flush_pending(&seed, node);

    while (rt->graph.q_count) {
        uint16_t slot = rt->graph.queue[rt->graph.q_head];
        rt->graph.q_head = (uint16_t)((rt->graph.q_head + 1) % GRAPH_FRAME_POOL_SIZE);
        rt->graph.q_count--;
        struct graph_frame_slot *s = &rt->graph.slots[slot];
        struct dp_node *dpn = &rt->graph.nodes[s->node];
        for (uint16_t i = 0; i < s->frame.count; i++) {
            dpn->stats.packets++;
            dpn->stats.bytes += rte_pktmbuf_pkt_len(s->frame.pkts[i]);
        }
        struct node_output out = { .rt = rt };
        for (unsigned n = 0; n < NODE_MAX; n++) out.pending[n] = UINT16_MAX;
        rt->active_output = &out;
        dpn->run(rt, &s->frame, &out);
        rt->active_output = NULL;
        s->used = 0;
        for (unsigned n = 0; n < NODE_MAX; n++) flush_pending(&out, (enum node_id)n);
    }
    return 0;
}

void graph_dump_stats(const struct app_runtime *rt)
{
    static const char *const reasons[DROP_REASON_MAX] = {
        "none", "port_binding", "truncated_eth", "unsupported_ethertype", "invalid_arp",
        "invalid_ipv4", "ipv4_fragment", "not_local", "ipv4_options", "invalid_icmp",
        "unsupported_icmp", "unsupported_protocol", "graph_full", "tx_failed",
        "mtu", "no_tailroom", "noncontiguous", "invalid_source"
    };
    puts("node statistics:");
    for (unsigned i = 0; i < NODE_MAX; i++) {
        const struct dp_node *n = &rt->graph.nodes[i];
        printf("  %-24s packets=%llu bytes=%llu drops=%llu errors=%llu\n", n->name,
               (unsigned long long)n->stats.packets, (unsigned long long)n->stats.bytes,
               (unsigned long long)n->stats.drops, (unsigned long long)n->stats.errors);
    }
    puts("drop reasons:");
    for (unsigned i = 1; i < DROP_REASON_MAX; i++)
        if (rt->graph.drop_reasons[i]) printf("  %-24s %llu\n", reasons[i],
            (unsigned long long)rt->graph.drop_reasons[i]);
}
