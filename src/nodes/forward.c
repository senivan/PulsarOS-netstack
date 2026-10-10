#include <rte_cycles.h>
#include <rte_ip.h>
#include "internal.h"

void ipv4_forward_node_run(struct app_runtime *rt, const struct node_frame *in,
                           struct node_output *out)
{
    for (uint16_t i = 0; i < in->count; i++) {
        struct rte_mbuf *m = in->pkts[i];
        struct packet_ctx ctx = in->ctxs[i];
        struct rte_ipv4_hdr *ip = rte_pktmbuf_mtod_offset(m, struct rte_ipv4_hdr *, ctx.l3_offset);
        if (ip->time_to_live <= 1) {
            icmp_send_error(rt, m, &ctx, 11, 0, 0, rte_get_timer_cycles());
            node_drop(rt, NODE_IPV4_FORWARD, m, &ctx, DROP_TTL_EXPIRED, 0);
            continue;
        }
        struct route_result route;
        enum drop_reason reason = ipv4_route_lookup(rt, ip->dst_addr, &route);
        if (reason != DROP_NONE) {
            if (reason == DROP_NO_ROUTE || reason == DROP_INVALID_EGRESS)
                icmp_send_error(rt, m, &ctx, 3, 0, 0, rte_get_timer_cycles());
            node_drop(rt, NODE_IPV4_FORWARD, m, &ctx, reason, 0);
            continue;
        }
        if (rte_be_to_cpu_16(ip->total_length) > route.mtu) {
            if (rte_be_to_cpu_16(ip->fragment_offset) & RTE_IPV4_HDR_DF_FLAG)
                icmp_send_error(rt, m, &ctx, 3, 4, route.mtu, rte_get_timer_cycles());
            node_drop(rt, NODE_IPV4_FORWARD, m, &ctx, DROP_MTU, 0);
            continue;
        }
        ip->time_to_live--;
        ip->hdr_checksum = 0;
        ip->hdr_checksum = rte_ipv4_cksum(ip);
        ctx.egress_port_id = netif_by_id(rt, route.netif_id)->port_id;
        ctx.next_hop_ip_be = route.next_hop_be;
        rte_pktmbuf_adj(m, ctx.l3_offset);
        ctx.l4_offset -= ctx.l3_offset;
        ctx.l3_offset = 0;
        node_enqueue(out, NODE_ETH_OUTPUT, m, &ctx);
    }
}
