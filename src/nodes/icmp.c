#include <rte_icmp.h>
#include <rte_ip.h>
#include "internal.h"

void icmp_input_node_run(struct app_runtime *rt, const struct node_frame *in,
                         struct node_output *out)
{
    for (uint16_t i = 0; i < in->count; i++) {
        struct rte_mbuf *m = in->pkts[i];
        struct packet_ctx ctx = in->ctxs[i];
        uint16_t length = rte_pktmbuf_pkt_len(m) - ctx.l4_offset;
        struct rte_icmp_hdr *icmp = rte_pktmbuf_mtod_offset(m, struct rte_icmp_hdr *, ctx.l4_offset);
        if (length < sizeof(*icmp) || rte_raw_cksum(icmp, length) != UINT16_MAX || icmp->icmp_code != 0) {
            node_drop(rt, NODE_ICMP_INPUT, m, &ctx, DROP_INVALID_ICMP, 1);
            continue;
        }
        if (icmp->icmp_type != RTE_IP_ICMP_ECHO_REQUEST) {
            node_drop(rt, NODE_ICMP_INPUT, m, &ctx, DROP_UNSUPPORTED_ICMP, 0);
            continue;
        }
        struct rte_ether_hdr *eth = rte_pktmbuf_mtod(m, struct rte_ether_hdr *);
        struct rte_ipv4_hdr *ip = rte_pktmbuf_mtod_offset(m, struct rte_ipv4_hdr *, ctx.l3_offset);
        uint32_t requester = ip->src_addr;
        ip->src_addr = rt->port.ip_be;
        ip->dst_addr = requester;
        eth->dst_addr = eth->src_addr;
        eth->src_addr = rt->port.mac;
        icmp->icmp_type = RTE_IP_ICMP_ECHO_REPLY;
        icmp->icmp_cksum = 0;
        icmp->icmp_cksum = (uint16_t)~rte_raw_cksum(icmp, length);
        ip->time_to_live = 64;
        ip->hdr_checksum = 0;
        ip->hdr_checksum = rte_ipv4_cksum(ip);
        ctx.egress_port_id = rt->port.port_id;
        node_enqueue(out, NODE_TX, m, &ctx);
    }
}

static void unsupported(struct app_runtime *rt, const struct node_frame *in, enum node_id node)
{
    for (uint16_t i = 0; i < in->count; i++) {
        struct packet_ctx ctx = in->ctxs[i];
        node_drop(rt, node, in->pkts[i], &ctx, DROP_UNSUPPORTED_PROTOCOL, 0);
    }
}

void tcp_input_node_run(struct app_runtime *rt, const struct node_frame *in, struct node_output *out)
{
    (void)out;
    unsupported(rt, in, NODE_TCP_INPUT);
}
