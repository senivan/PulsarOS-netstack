#include <string.h>
#include <rte_ip.h>
#include "internal.h"

void ipv4_route_node_run(struct app_runtime *rt, const struct node_frame *in,
                         struct node_output *out)
{
    for (uint16_t i = 0; i < in->count; i++) {
        struct packet_ctx ctx = in->ctxs[i];
        struct route_result route;
        enum drop_reason reason = ipv4_route_lookup(rt, ctx.dst_ip_be, &route);
        if (reason != DROP_NONE) {
            node_drop(rt, NODE_IPV4_ROUTE, in->pkts[i], &ctx, reason, 0);
            continue;
        }
        if (ctx.ip_protocol != IPPROTO_UDP) {
            node_drop(rt, NODE_IPV4_ROUTE, in->pkts[i], &ctx, DROP_UNSUPPORTED_PROTOCOL, 0);
            continue;
        }
        const struct port_state *port = netif_by_id(rt, route.netif_id);
        ctx.egress_port_id = port->port_id;
        ctx.src_ip_be = route.source_ip_be;
        ctx.next_hop_ip_be = route.next_hop_be;
        node_enqueue(out, NODE_UDP_OUTPUT, in->pkts[i], &ctx);
    }
}

void ipv4_output_node_run(struct app_runtime *rt, const struct node_frame *in,
                          struct node_output *out)
{
    for (uint16_t i = 0; i < in->count; i++) {
        struct rte_mbuf *m = in->pkts[i];
        struct packet_ctx ctx = in->ctxs[i];
        const struct port_state *port = netif_by_dpdk_port(rt, ctx.egress_port_id);
        if (!port || !port->started) {
            node_drop(rt, NODE_IPV4_OUTPUT, m, &ctx, DROP_INVALID_EGRESS, 1);
            continue;
        }
        uint32_t total = rte_pktmbuf_pkt_len(m) + sizeof(struct rte_ipv4_hdr);
        if (total > port->mtu || total > UINT16_MAX) {
            node_drop(rt, NODE_IPV4_OUTPUT, m, &ctx, DROP_MTU, 0);
            continue;
        }
        struct rte_ipv4_hdr *ip = (struct rte_ipv4_hdr *)rte_pktmbuf_prepend(m, sizeof(*ip));
        if (!ip) {
            node_drop(rt, NODE_IPV4_OUTPUT, m, &ctx, DROP_NO_HEADROOM, 1);
            continue;
        }
        memset(ip, 0, sizeof(*ip));
        ip->version_ihl = 0x45;
        ip->total_length = rte_cpu_to_be_16((uint16_t)total);
        ip->packet_id = rte_cpu_to_be_16(rt->next_ip_id++);
        ip->fragment_offset = rte_cpu_to_be_16(RTE_IPV4_HDR_DF_FLAG);
        ip->time_to_live = 64;
        ip->next_proto_id = ctx.ip_protocol;
        ip->src_addr = ctx.src_ip_be;
        ip->dst_addr = ctx.dst_ip_be;
        ip->hdr_checksum = rte_ipv4_cksum(ip);
        ctx.l3_offset = 0;
        ctx.l4_offset = sizeof(*ip);
        node_enqueue(out, NODE_ETH_OUTPUT, m, &ctx);
    }
}

void eth_output_node_run(struct app_runtime *rt, const struct node_frame *in,
                         struct node_output *out)
{
    for (uint16_t i = 0; i < in->count; i++) {
        struct rte_mbuf *m = in->pkts[i];
        struct packet_ctx ctx = in->ctxs[i];
        const struct port_state *port = netif_by_dpdk_port(rt, ctx.egress_port_id);
        if (!port || !port->started) {
            node_drop(rt, NODE_ETH_OUTPUT, m, &ctx, DROP_INVALID_EGRESS, 1);
            continue;
        }
        struct rte_ether_addr destination;
        if (neighbour_lookup(&rt->neighbours, port->id, ctx.next_hop_ip_be, &destination) < 0) {
            node_drop(rt, NODE_ETH_OUTPUT, m, &ctx, DROP_NEIGHBOUR_NOT_FOUND, 0);
            continue;
        }
        struct rte_ether_hdr *eth = (struct rte_ether_hdr *)rte_pktmbuf_prepend(m, sizeof(*eth));
        if (!eth) {
            node_drop(rt, NODE_ETH_OUTPUT, m, &ctx, DROP_NO_HEADROOM, 1);
            continue;
        }
        eth->src_addr = port->mac;
        eth->dst_addr = destination;
        eth->ether_type = rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV4);
        ctx.l3_offset += sizeof(*eth);
        ctx.l4_offset += sizeof(*eth);
        node_enqueue(out, NODE_TX, m, &ctx);
    }
}
