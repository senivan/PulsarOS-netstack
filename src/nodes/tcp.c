#include <rte_cycles.h>
#include <rte_ip.h>
#include <rte_tcp.h>
#include "internal.h"

void tcp_input_node_run(struct app_runtime *rt, const struct node_frame *in, struct node_output *out)
{
    (void)out;
    for (uint16_t i = 0; i < in->count; i++) {
        struct rte_mbuf *m = in->pkts[i];
        struct packet_ctx ctx = in->ctxs[i];
        uint16_t length = rte_pktmbuf_pkt_len(m) - ctx.l4_offset;
        if (length < sizeof(struct rte_tcp_hdr)) {
            node_drop(rt, NODE_TCP_INPUT, m, &ctx, DROP_INVALID_TCP, 1);
            continue;
        }
        const struct rte_tcp_hdr *tcp = rte_pktmbuf_mtod_offset(m, const struct rte_tcp_hdr *, ctx.l4_offset);
        uint16_t header_len = (tcp->data_off >> 4) * 4;
        if (header_len < sizeof(*tcp) || header_len > length ||
            (tcp->tcp_flags & RTE_TCP_URG_FLAG) ||
            ((tcp->tcp_flags & RTE_TCP_SYN_FLAG) && (tcp->tcp_flags & (RTE_TCP_FIN_FLAG | RTE_TCP_RST_FLAG)))) {
            node_drop(rt, NODE_TCP_INPUT, m, &ctx, DROP_INVALID_TCP, 1);
            continue;
        }
        const struct rte_ipv4_hdr *ip = rte_pktmbuf_mtod_offset(m, const struct rte_ipv4_hdr *, ctx.l3_offset);
        if (rte_ipv4_udptcp_cksum(ip, tcp) != 0) {
            node_drop(rt, NODE_TCP_INPUT, m, &ctx, DROP_TCP_BAD_CHECKSUM, 1);
            continue;
        }
        uint16_t mss = 536;
        const uint8_t *options = (const uint8_t *)(tcp + 1);
        unsigned offset = sizeof(*tcp);
        int invalid_options = 0;
        while (offset < header_len) {
            uint8_t kind = *options;
            if (!kind) break;
            if (kind == 1) { options++; offset++; continue; }
            if (header_len - offset < 2 || options[1] < 2 || options[1] > header_len - offset ||
                (kind == 2 && options[1] != 4)) { invalid_options = 1; break; }
            if (kind == 2 && options[1] == 4 && (tcp->tcp_flags & RTE_TCP_SYN_FLAG)) {
                uint16_t value = (uint16_t)options[2] << 8 | options[3];
                if (value) mss = value;
            }
            offset += options[1];
            options += options[1];
        }
        if (invalid_options) {
            node_drop(rt, NODE_TCP_INPUT, m, &ctx, DROP_INVALID_TCP, 1);
            continue;
        }
        enum drop_reason reason = tcp_input(rt, &ctx, tcp, header_len, length - header_len,
                                            mss, rte_get_timer_cycles());
        if (reason != DROP_NONE) node_drop(rt, NODE_TCP_INPUT, m, &ctx, reason,
                                          reason == DROP_TCP_INVALID_STATE);
        else rte_pktmbuf_free(m);
    }
}
