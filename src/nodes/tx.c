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
        struct port_state *port = netif_by_dpdk_port(rt, ctx.egress_port_id);
        if (!port || !port->started) {
            node_drop(rt, NODE_TX, m, &ctx, DROP_INVALID_EGRESS, 1);
            continue;
        }
        if (rte_pktmbuf_pkt_len(m) < RTE_ETHER_MIN_LEN - RTE_ETHER_CRC_LEN) {
            uint16_t padding = RTE_ETHER_MIN_LEN - RTE_ETHER_CRC_LEN - rte_pktmbuf_pkt_len(m);
            char *tail = rte_pktmbuf_append(m, padding);
            if (!tail) {
                port->tx_drops++;
                node_drop(rt, NODE_TX, m, &ctx, DROP_NO_TAILROOM, 1);
                continue;
            }
            memset(tail, 0, padding);
        }
        /* All checksums are computed in software; do not reuse RX offload metadata. */
        m->ol_flags = 0;
        m->tx_offload = 0;
        packets[count] = m;
        contexts[count++] = ctx;
    }
    for (uint16_t p = 0; p < rt->port_count; p++) {
        struct port_state *port = &rt->ports[p];
        if (!port->configured || !port->started) continue;
        struct rte_mbuf *batch[GRAPH_FRAME_SIZE];
        uint16_t indices[GRAPH_FRAME_SIZE], n = 0;
        for (uint16_t i = 0; i < count; i++) {
            if (contexts[i].egress_port_id != port->port_id) continue;
            indices[n] = i;
            batch[n++] = packets[i];
        }
        if (!n) continue;
        uint16_t sent = rte_eth_tx_burst(port->port_id, 0, batch, n);
        rt->tx_packets += sent;
        port->tx_packets += sent;
        port->tx_drops += n - sent;
        for (uint16_t i = sent; i < n; i++)
            node_drop(rt, NODE_TX, batch[i], &contexts[indices[i]], DROP_TX_FAILED, 1);
    }
}
