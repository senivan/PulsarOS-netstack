#include <netinet/in.h>
#include <rte_ip.h>
#include "internal.h"

void ipv4_acl_node_run(struct app_runtime *rt, const struct node_frame *in, struct node_output *out)
{
    struct acl_key keys[GRAPH_FRAME_SIZE];
    int results[GRAPH_FRAME_SIZE];
    if (rt->network) {
        for (uint16_t i = 0; i < in->count; i++) {
            const struct packet_ctx *ctx = &in->ctxs[i];
            const struct rte_ipv4_hdr *ip = rte_pktmbuf_mtod_offset(in->pkts[i], const struct rte_ipv4_hdr *, ctx->l3_offset);
            struct acl_key *key = &keys[i];
            *key = (struct acl_key){ .src=ctx->src_ip_be, .dst=ctx->dst_ip_be,
                .iif=netif_by_dpdk_port(rt, ctx->ingress_port_id)->id, .proto=ctx->ip_protocol };
            unsigned length = rte_be_to_cpu_16(ip->total_length) - sizeof(*ip);
            const uint8_t *l4 = (const uint8_t *)(ip+1);
            if ((key->proto == IPPROTO_UDP && length >= 8) || (key->proto == IPPROTO_TCP && length >= 20)) {
                key->ports_valid = 1;
                key->sport = (uint16_t)((uint16_t)l4[0] << 8 | l4[1]);
                key->dport = (uint16_t)((uint16_t)l4[2] << 8 | l4[3]);
            }
        }
        net_acl_classify_batch(rt->network, keys, in->count, results);
    }
    for (uint16_t i = 0; i < in->count; i++) {
        struct rte_mbuf *m = in->pkts[i];
        struct packet_ctx ctx = in->ctxs[i];
        const struct rte_ipv4_hdr *ip = rte_pktmbuf_mtod_offset(m, const struct rte_ipv4_hdr *, ctx.l3_offset);
        if (rt->network && !net_acl_account(rt->network, &rt->acl_stats, results[i], rte_be_to_cpu_16(ip->total_length))) {
            node_drop(rt, NODE_IPV4_ACL, m, &ctx, DROP_ACL, 0);
            continue;
        }
        if (!netif_is_local_ip(rt, ip->dst_addr)) {
            if (!rt->ipv4_forwarding) {
                node_drop(rt, NODE_IPV4_ACL, m, &ctx, DROP_FORWARDING_DISABLED, 0);
                continue;
            }
            uint32_t src = rte_be_to_cpu_32(ip->src_addr), dst = rte_be_to_cpu_32(ip->dst_addr);
            if (!ipv4_destination_valid(rt, ip->src_addr) || (src >> 16) == 0xa9fe) {
                node_drop(rt, NODE_IPV4_ACL, m, &ctx, DROP_INVALID_SOURCE, 0);
                continue;
            }
            if (!ipv4_destination_valid(rt, ip->dst_addr) || (dst >> 16) == 0xa9fe) {
                node_drop(rt, NODE_IPV4_ACL, m, &ctx, DROP_INVALID_DESTINATION, 0);
                continue;
            }
            ctx.transit = 1;
            node_enqueue(out, NODE_IPV4_FORWARD, m, &ctx);
            continue;
        }
        switch (ip->next_proto_id) {
        case IPPROTO_ICMP: node_enqueue(out, NODE_ICMP_INPUT, m, &ctx); break;
        case IPPROTO_UDP: node_enqueue(out, NODE_UDP_INPUT, m, &ctx); break;
        case IPPROTO_TCP: node_enqueue(out, NODE_TCP_INPUT, m, &ctx); break;
        default: node_drop(rt, NODE_IPV4_ACL, m, &ctx, DROP_UNSUPPORTED_PROTOCOL, 0); break;
        }
    }
}
