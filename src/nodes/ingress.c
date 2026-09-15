#include <netinet/in.h>
#include <string.h>
#include <rte_arp.h>
#include <rte_byteorder.h>
#include <rte_ip.h>
#include "internal.h"

static int valid_source_ip(const struct port_state *port, uint32_t ip_be)
{
    uint32_t ip = rte_be_to_cpu_32(ip_be);
    uint32_t local = rte_be_to_cpu_32(port->ip_be);
    uint32_t mask = port->prefix_len ? UINT32_MAX << (32 - port->prefix_len) : 0;
    if ((ip >> 24) == 0 || (ip >> 24) == 127 || ip >= 0xe0000000u || ip == local) return 0;
    if (port->prefix_len <= 30 && (ip & mask) == (local & mask) &&
        ((ip & ~mask) == 0 || (ip & ~mask) == ~mask)) return 0;
    return 1;
}

void eth_input_node_run(struct app_runtime *rt, const struct node_frame *in,
                        struct node_output *out)
{
    for (uint16_t i = 0; i < in->count; i++) {
        struct rte_mbuf *m = in->pkts[i];
        struct packet_ctx ctx = in->ctxs[i];
        if (ctx.ingress_port_id != rt->port.port_id) {
            node_drop(rt, NODE_ETH_INPUT, m, &ctx, DROP_PORT_BINDING, 1);
            continue;
        }
        /* RX scatter is disabled. Never parse or rewrite a shared/chained buffer. */
        if (!rte_pktmbuf_is_contiguous(m) || !RTE_MBUF_DIRECT(m) || rte_mbuf_refcnt_read(m) != 1) {
            node_drop(rt, NODE_ETH_INPUT, m, &ctx, DROP_NONCONTIGUOUS, 1);
            continue;
        }
        if (rte_pktmbuf_data_len(m) < sizeof(struct rte_ether_hdr)) {
            node_drop(rt, NODE_ETH_INPUT, m, &ctx, DROP_TRUNCATED_ETH, 1);
            continue;
        }
        const struct rte_ether_hdr *eth = rte_pktmbuf_mtod(m, const struct rte_ether_hdr *);
        if (!rte_is_valid_assigned_ether_addr(&eth->src_addr) ||
            rte_is_same_ether_addr(&eth->src_addr, &rt->port.mac)) {
            node_drop(rt, NODE_ETH_INPUT, m, &ctx, DROP_INVALID_SOURCE, 1);
            continue;
        }
        int arp = eth->ether_type == rte_cpu_to_be_16(RTE_ETHER_TYPE_ARP);
        if (!rte_is_same_ether_addr(&eth->dst_addr, &rt->port.mac) &&
            !(arp && rte_is_broadcast_ether_addr(&eth->dst_addr))) {
            node_drop(rt, NODE_ETH_INPUT, m, &ctx, DROP_NOT_LOCAL, 0);
            continue;
        }
        ctx.l3_offset = sizeof(*eth);
        if (arp) node_enqueue(out, NODE_ARP_INPUT, m, &ctx);
        else if (eth->ether_type == rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV4))
            node_enqueue(out, NODE_IPV4_INPUT, m, &ctx);
        else node_drop(rt, NODE_ETH_INPUT, m, &ctx, DROP_UNSUPPORTED_ETHERTYPE, 0);
    }
}

void arp_input_node_run(struct app_runtime *rt, const struct node_frame *in,
                        struct node_output *out)
{
    for (uint16_t i = 0; i < in->count; i++) {
        struct rte_mbuf *m = in->pkts[i];
        struct packet_ctx ctx = in->ctxs[i];
        uint16_t length = ctx.l3_offset + sizeof(struct rte_arp_hdr);
        if (rte_pktmbuf_data_len(m) < length) {
            node_drop(rt, NODE_ARP_INPUT, m, &ctx, DROP_INVALID_ARP, 1);
            continue;
        }
        struct rte_ether_hdr *eth = rte_pktmbuf_mtod(m, struct rte_ether_hdr *);
        struct rte_arp_hdr *arp = rte_pktmbuf_mtod_offset(m, struct rte_arp_hdr *, ctx.l3_offset);
        if (arp->arp_hardware != rte_cpu_to_be_16(RTE_ARP_HRD_ETHER) ||
            arp->arp_protocol != rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV4) ||
            arp->arp_hlen != RTE_ETHER_ADDR_LEN || arp->arp_plen != 4 ||
            !rte_is_same_ether_addr(&eth->src_addr, &arp->arp_data.arp_sha) ||
            (arp->arp_opcode != rte_cpu_to_be_16(RTE_ARP_OP_REQUEST) &&
             arp->arp_opcode != rte_cpu_to_be_16(RTE_ARP_OP_REPLY)) ||
            (arp->arp_data.arp_sip && !valid_source_ip(&rt->port, arp->arp_data.arp_sip))) {
            node_drop(rt, NODE_ARP_INPUT, m, &ctx, DROP_INVALID_ARP, 1);
            continue;
        }
        if (arp->arp_data.arp_tip != rt->port.ip_be) {
            node_drop(rt, NODE_ARP_INPUT, m, &ctx, DROP_NOT_LOCAL, 0);
            continue;
        }
        if (arp->arp_opcode == rte_cpu_to_be_16(RTE_ARP_OP_REPLY)) {
            /* No pending resolutions or neighbour cache in this receive-only phase. */
            rte_pktmbuf_free(m);
            continue;
        }
        struct rte_ether_addr requester = arp->arp_data.arp_sha;
        uint32_t requester_ip = arp->arp_data.arp_sip;
        eth->dst_addr = requester;
        eth->src_addr = rt->port.mac;
        arp->arp_opcode = rte_cpu_to_be_16(RTE_ARP_OP_REPLY);
        arp->arp_data.arp_tha = requester;
        arp->arp_data.arp_tip = requester_ip;
        arp->arp_data.arp_sha = rt->port.mac;
        arp->arp_data.arp_sip = rt->port.ip_be;
        /* Discard incoming padding; TX adds freshly zeroed Ethernet padding. */
        rte_pktmbuf_trim(m, rte_pktmbuf_pkt_len(m) - length);
        ctx.egress_port_id = rt->port.port_id;
        node_enqueue(out, NODE_TX, m, &ctx);
    }
}

void ipv4_input_node_run(struct app_runtime *rt, const struct node_frame *in,
                         struct node_output *out)
{
    for (uint16_t i = 0; i < in->count; i++) {
        struct rte_mbuf *m = in->pkts[i];
        struct packet_ctx ctx = in->ctxs[i];
        if (rte_pktmbuf_data_len(m) < ctx.l3_offset + sizeof(struct rte_ipv4_hdr)) {
            node_drop(rt, NODE_IPV4_INPUT, m, &ctx, DROP_INVALID_IPV4, 1);
            continue;
        }
        const struct rte_ipv4_hdr *ip = rte_pktmbuf_mtod_offset(m, const struct rte_ipv4_hdr *, ctx.l3_offset);
        uint16_t ihl = (ip->version_ihl & 0x0f) * 4;
        uint16_t total = rte_be_to_cpu_16(ip->total_length);
        if ((ip->version_ihl >> 4) != 4 || ihl < sizeof(*ip) || total < ihl ||
            rte_pktmbuf_data_len(m) < ctx.l3_offset + total ||
            ip->time_to_live == 0 || rte_ipv4_cksum(ip) != 0 ||
            (rte_be_to_cpu_16(ip->fragment_offset) & 0x8000)) {
            node_drop(rt, NODE_IPV4_INPUT, m, &ctx, DROP_INVALID_IPV4, 1);
            continue;
        }
        if (ip->dst_addr != rt->port.ip_be) {
            node_drop(rt, NODE_IPV4_INPUT, m, &ctx, DROP_NOT_LOCAL, 0);
            continue;
        }
        if (!valid_source_ip(&rt->port, ip->src_addr)) {
            node_drop(rt, NODE_IPV4_INPUT, m, &ctx, DROP_INVALID_SOURCE, 1);
            continue;
        }
        if (total > rt->port.mtu) {
            node_drop(rt, NODE_IPV4_INPUT, m, &ctx, DROP_MTU, 0);
            continue;
        }
        if (rte_be_to_cpu_16(ip->fragment_offset) & (RTE_IPV4_HDR_MF_FLAG | RTE_IPV4_HDR_OFFSET_MASK)) {
            node_drop(rt, NODE_IPV4_INPUT, m, &ctx, DROP_IPV4_FRAGMENT, 0);
            continue;
        }
        if (ihl != sizeof(*ip)) {
            node_drop(rt, NODE_IPV4_INPUT, m, &ctx, DROP_IPV4_OPTIONS, 0);
            continue;
        }
        ctx.l4_offset = ctx.l3_offset + ihl;
        rte_pktmbuf_trim(m, rte_pktmbuf_pkt_len(m) - (ctx.l3_offset + total));
        switch (ip->next_proto_id) {
        case IPPROTO_ICMP: node_enqueue(out, NODE_ICMP_INPUT, m, &ctx); break;
        case IPPROTO_UDP: node_enqueue(out, NODE_UDP_INPUT, m, &ctx); break;
        case IPPROTO_TCP: node_enqueue(out, NODE_TCP_INPUT, m, &ctx); break;
        default: node_drop(rt, NODE_IPV4_INPUT, m, &ctx, DROP_UNSUPPORTED_PROTOCOL, 0); break;
        }
    }
}
