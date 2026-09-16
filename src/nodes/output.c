#include <string.h>
#include <rte_ip.h>
#include "internal.h"

static int on_link_destination(const struct port_state *port, uint32_t ip_be)
{
    uint32_t ip = rte_be_to_cpu_32(ip_be), local = rte_be_to_cpu_32(port->ip_be);
    uint32_t mask = port->prefix_len ? UINT32_MAX << (32 - port->prefix_len) : 0;
    if ((ip >> 24) == 0 || (ip >> 24) == 127 || ip >= 0xe0000000u || ip == local ||
        (ip & mask) != (local & mask)) return 0;
    return port->prefix_len > 30 || ((ip & ~mask) != 0 && (ip & ~mask) != ~mask);
}

void ipv4_output_node_run(struct app_runtime *rt, const struct node_frame *in,
                          struct node_output *out)
{
    for (uint16_t i = 0; i < in->count; i++) {
        struct rte_mbuf *m = in->pkts[i];
        struct packet_ctx ctx = in->ctxs[i];
        uint32_t total = rte_pktmbuf_pkt_len(m) + sizeof(struct rte_ipv4_hdr);
        if (total > rt->port.mtu || total > UINT16_MAX) {
            node_drop(rt, NODE_IPV4_OUTPUT, m, &ctx, DROP_MTU, 0);
            continue;
        }
        if (!on_link_destination(&rt->port, ctx.dst_ip_be)) {
            node_drop(rt, NODE_IPV4_OUTPUT, m, &ctx, DROP_INVALID_DESTINATION, 0);
            continue;
        }
        struct rte_ipv4_hdr *ip = (struct rte_ipv4_hdr *)rte_pktmbuf_prepend(m, sizeof(*ip));
        if (!ip) {
            node_drop(rt, NODE_IPV4_OUTPUT, m, &ctx, DROP_NO_HEADROOM, 1);
            continue;
        }
        /* Header construction follows the existing VXLAN outer-IPv4 pattern. */
        memset(ip, 0, sizeof(*ip));
        ip->version_ihl = 0x45;
        ip->total_length = rte_cpu_to_be_16((uint16_t)total);
        ip->packet_id = rte_cpu_to_be_16(rt->next_ip_id++);
        ip->fragment_offset = rte_cpu_to_be_16(RTE_IPV4_HDR_DF_FLAG);
        ip->time_to_live = 64;
        ip->next_proto_id = ctx.ip_protocol;
        ip->src_addr = rt->port.ip_be;
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
        struct rte_ether_addr destination;
        if (neighbour_lookup(&rt->neighbours, ctx.dst_ip_be, &destination) < 0) {
            node_drop(rt, NODE_ETH_OUTPUT, m, &ctx, DROP_NEIGHBOUR_NOT_FOUND, 0);
            continue;
        }
        struct rte_ether_hdr *eth = (struct rte_ether_hdr *)rte_pktmbuf_prepend(m, sizeof(*eth));
        if (!eth) {
            node_drop(rt, NODE_ETH_OUTPUT, m, &ctx, DROP_NO_HEADROOM, 1);
            continue;
        }
        eth->src_addr = rt->port.mac;
        eth->dst_addr = destination;
        eth->ether_type = rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV4);
        ctx.l3_offset += sizeof(*eth);
        ctx.l4_offset += sizeof(*eth);
        ctx.egress_port_id = rt->port.port_id;
        node_enqueue(out, NODE_TX, m, &ctx);
    }
}
