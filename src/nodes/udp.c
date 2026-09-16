#include <errno.h>
#include <string.h>
#include <rte_ip.h>
#include <rte_udp.h>
#include "internal.h"
#include "udp.h"

void udp_input_node_run(struct app_runtime *rt, const struct node_frame *in,
                        struct node_output *out)
{
    (void)out;
    for (uint16_t i = 0; i < in->count; i++) {
        struct rte_mbuf *m = in->pkts[i];
        struct packet_ctx ctx = in->ctxs[i];
        uint16_t available = rte_pktmbuf_pkt_len(m) - ctx.l4_offset;
        if (available < sizeof(struct rte_udp_hdr)) {
            node_drop(rt, NODE_UDP_INPUT, m, &ctx, DROP_INVALID_UDP, 1);
            continue;
        }
        const struct rte_udp_hdr *udp = rte_pktmbuf_mtod_offset(m, const struct rte_udp_hdr *, ctx.l4_offset);
        uint16_t length = rte_be_to_cpu_16(udp->dgram_len);
        if (length < sizeof(*udp) || length > available) {
            node_drop(rt, NODE_UDP_INPUT, m, &ctx, DROP_UDP_BAD_LENGTH, 1);
            continue;
        }
        const struct rte_ipv4_hdr *ip = rte_pktmbuf_mtod_offset(m, const struct rte_ipv4_hdr *, ctx.l3_offset);
        /* The pseudo-header uses UDP length, which may be shorter than the IP payload. */
        struct rte_ipv4_hdr pseudo = *ip;
        pseudo.total_length = rte_cpu_to_be_16(sizeof(pseudo) + length);
        uint32_t checksum = rte_raw_cksum(udp, length) + (uint32_t)rte_ipv4_phdr_cksum(&pseudo, 0);
        checksum = (checksum & 0xffff) + (checksum >> 16);
        checksum = (checksum & 0xffff) + (checksum >> 16);
        if (udp->dgram_cksum && checksum != UINT16_MAX) {
            node_drop(rt, NODE_UDP_INPUT, m, &ctx, DROP_UDP_BAD_CHECKSUM, 1);
            continue;
        }
        struct ps_addr source = { .ip_be = ip->src_addr, .port = rte_be_to_cpu_16(udp->src_port) };
        int rc = udp_deliver(rt, rte_be_to_cpu_16(udp->dst_port), &source, udp + 1, length - sizeof(*udp));
        if (rc < 0) {
            enum drop_reason reason = rc == -ENOENT ? DROP_UDP_UNBOUND_PORT :
                rc == -ENOBUFS ? DROP_UDP_RX_QUEUE_FULL : DROP_MTU;
            node_drop(rt, NODE_UDP_INPUT, m, &ctx, reason, 0);
            continue;
        }
        rte_pktmbuf_free(m);
    }
}

void udp_output_node_run(struct app_runtime *rt, const struct node_frame *in,
                         struct node_output *out)
{
    for (uint16_t i = 0; i < in->count; i++) {
        struct rte_mbuf *m = in->pkts[i];
        struct packet_ctx ctx = in->ctxs[i];
        uint32_t length = rte_pktmbuf_pkt_len(m) + sizeof(struct rte_udp_hdr);
        if (length > UINT16_MAX - sizeof(struct rte_ipv4_hdr)) {
            node_drop(rt, NODE_UDP_OUTPUT, m, &ctx, DROP_MTU, 0);
            continue;
        }
        struct rte_udp_hdr *udp = (struct rte_udp_hdr *)rte_pktmbuf_prepend(m, sizeof(*udp));
        if (!udp) {
            node_drop(rt, NODE_UDP_OUTPUT, m, &ctx, DROP_NO_HEADROOM, 1);
            continue;
        }
        udp->src_port = rte_cpu_to_be_16(ctx.src_port);
        udp->dst_port = rte_cpu_to_be_16(ctx.dst_port);
        udp->dgram_len = rte_cpu_to_be_16((uint16_t)length);
        udp->dgram_cksum = 0;
        struct rte_ipv4_hdr pseudo = {
            .version_ihl = 0x45,
            .total_length = rte_cpu_to_be_16((uint16_t)(sizeof(pseudo) + length)),
            .next_proto_id = IPPROTO_UDP,
            .src_addr = rt->port.ip_be,
            .dst_addr = ctx.dst_ip_be
        };
        udp->dgram_cksum = rte_ipv4_udptcp_cksum(&pseudo, udp);
        ctx.ip_protocol = IPPROTO_UDP;
        node_enqueue(out, NODE_IPV4_OUTPUT, m, &ctx);
    }
}
