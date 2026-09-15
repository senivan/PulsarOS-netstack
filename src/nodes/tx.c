#include <string.h>
#include "internal.h"

void tx_node_run(struct app_runtime *rt, const struct node_frame *in, struct node_output *out)
{
    (void)out;
    struct rte_mbuf *packets[GRAPH_FRAME_SIZE];
    struct packet_ctx contexts[GRAPH_FRAME_SIZE];
    uint16_t count = 0;
    for (uint16_t i = 0; i < in->count; i++) {
        struct rte_mbuf *m = in->pkts[i];
        struct packet_ctx ctx = in->ctxs[i];
        if (ctx.egress_port_id != rt->port.port_id) {
            node_drop(rt, NODE_TX, m, &ctx, DROP_PORT_BINDING, 1);
            continue;
        }
        if (rte_pktmbuf_pkt_len(m) < RTE_ETHER_MIN_LEN - RTE_ETHER_CRC_LEN) {
            uint16_t padding = RTE_ETHER_MIN_LEN - RTE_ETHER_CRC_LEN - rte_pktmbuf_pkt_len(m);
            char *tail = rte_pktmbuf_append(m, padding);
            if (!tail) { node_drop(rt, NODE_TX, m, &ctx, DROP_NO_TAILROOM, 1); continue; }
            memset(tail, 0, padding);
        }
        /* All checksums are computed in software; do not reuse RX offload metadata. */
        m->ol_flags = 0;
        m->tx_offload = 0;
        packets[count] = m;
        contexts[count++] = ctx;
    }
    if (!count) return;
    uint16_t sent = rte_eth_tx_burst(rt->port.port_id, 0, packets, count);
    rt->tx_packets += sent;
    for (uint16_t i = sent; i < count; i++)
        node_drop(rt, NODE_TX, packets[i], &contexts[i], DROP_TX_FAILED, 1);
}
