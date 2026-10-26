#include <netinet/in.h>
#include <string.h>
#include <rte_arp.h>
#include <rte_byteorder.h>
#include <rte_ip.h>
#include "internal.h"

static int valid_source_ip(const struct app_runtime *rt, const struct port_state *port, uint32_t ip_be)
{
    uint32_t ip = rte_be_to_cpu_32(ip_be);
    if (netif_is_local_ip(rt, ip_be)) return 0;
    if (rt->network) return ipv4_destination_valid(rt, ip_be);
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
        const struct port_state *port = netif_by_dpdk_port(rt, ctx.ingress_port_id);
        if (!port || port->admin_down) {
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
            rte_is_same_ether_addr(&eth->src_addr, &port->mac)) {
            node_drop(rt, NODE_ETH_INPUT, m, &ctx, DROP_INVALID_SOURCE, 1);
            continue;
        }
        int arp = eth->ether_type == rte_cpu_to_be_16(RTE_ETHER_TYPE_ARP);
        if (!rte_is_same_ether_addr(&eth->dst_addr, &port->mac) &&
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
        const struct port_state *port = netif_by_dpdk_port(rt, ctx.ingress_port_id);
        if (!port || port->admin_down) {
            node_drop(rt, NODE_ARP_INPUT, m, &ctx, DROP_PORT_BINDING, 1);
            continue;
        }
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
            (arp->arp_data.arp_sip && !valid_source_ip(rt, port, arp->arp_data.arp_sip))) {
            node_drop(rt, NODE_ARP_INPUT, m, &ctx, DROP_INVALID_ARP, 1);
            continue;
        }
        if (!net_address_on(rt, port->id, arp->arp_data.arp_tip)) {
            node_drop(rt, NODE_ARP_INPUT, m, &ctx, DROP_NOT_LOCAL, 0);
            continue;
        }
        if (arp->arp_opcode == rte_cpu_to_be_16(RTE_ARP_OP_REPLY) &&
            !rte_is_same_ether_addr(&arp->arp_data.arp_tha, &port->mac)) {
            node_drop(rt, NODE_ARP_INPUT, m, &ctx, DROP_INVALID_ARP, 1);
            continue;
        }
        if (arp->arp_data.arp_sip && !netif_is_local_ip(rt, arp->arp_data.arp_sip) &&
            (rt->network ? net_source(rt, port->id, arp->arp_data.arp_sip) != 0 :
             route_is_direct(&rt->routes, port->id, arp->arp_data.arp_sip)) &&
            neighbour_update(rt, port->id, arp->arp_data.arp_sip, &arp->arp_data.arp_sha) < 0)
            rt->neighbour_learn_failures++;
        if (arp->arp_opcode == rte_cpu_to_be_16(RTE_ARP_OP_REPLY)) {
            rte_pktmbuf_free(m);
            continue;
        }
        struct rte_ether_addr requester = arp->arp_data.arp_sha;
        uint32_t requester_ip = arp->arp_data.arp_sip;
        uint32_t local_ip = arp->arp_data.arp_tip;
        eth->dst_addr = requester;
        eth->src_addr = port->mac;
        arp->arp_opcode = rte_cpu_to_be_16(RTE_ARP_OP_REPLY);
        arp->arp_data.arp_tha = requester;
        arp->arp_data.arp_tip = requester_ip;
        arp->arp_data.arp_sha = port->mac;
        arp->arp_data.arp_sip = local_ip;
        /* Discard incoming padding; TX adds freshly zeroed Ethernet padding. */
        rte_pktmbuf_trim(m, rte_pktmbuf_pkt_len(m) - length);
        ctx.egress_port_id = port->port_id;
        node_enqueue(out, NODE_TX, m, &ctx);
    }
}

void ipv4_input_node_run(struct app_runtime *rt, const struct node_frame *in,
                         struct node_output *out)
{
    for (uint16_t i = 0; i < in->count; i++) {
        struct rte_mbuf *m = in->pkts[i];
        struct packet_ctx ctx = in->ctxs[i];
        const struct port_state *port = netif_by_dpdk_port(rt, ctx.ingress_port_id);
        if (!port || port->admin_down) {
            node_drop(rt, NODE_IPV4_INPUT, m, &ctx, DROP_PORT_BINDING, 1);
            continue;
        }
        if (rte_pktmbuf_data_len(m) < ctx.l3_offset + sizeof(struct rte_ipv4_hdr)) {
            node_drop(rt, NODE_IPV4_INPUT, m, &ctx, DROP_INVALID_IPV4, 1);
            continue;
        }
        const struct rte_ipv4_hdr *ip = rte_pktmbuf_mtod_offset(m, const struct rte_ipv4_hdr *, ctx.l3_offset);
        uint16_t ihl = (ip->version_ihl & 0x0f) * 4;
        uint16_t total = rte_be_to_cpu_16(ip->total_length);
        if ((ip->version_ihl >> 4) != 4 || ihl < sizeof(*ip) || total < ihl ||
            rte_pktmbuf_data_len(m) < ctx.l3_offset + total ||
            rte_ipv4_cksum(ip) != 0 ||
            (rte_be_to_cpu_16(ip->fragment_offset) & 0x8000)) {
            node_drop(rt, NODE_IPV4_INPUT, m, &ctx, DROP_INVALID_IPV4, 1);
            continue;
        }
        if (!valid_source_ip(rt, port, ip->src_addr) || netif_is_local_ip(rt, ip->src_addr)) {
            node_drop(rt, NODE_IPV4_INPUT, m, &ctx, DROP_INVALID_SOURCE, 1);
            continue;
        }
        if (total > port->mtu) {
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
        ctx.src_ip_be = ip->src_addr;
        ctx.dst_ip_be = ip->dst_addr;
        ctx.ip_protocol = ip->next_proto_id;
        rte_pktmbuf_trim(m, rte_pktmbuf_pkt_len(m) - (ctx.l3_offset + total));
        if (rt->network) {
            struct acl_key key = { .src = ip->src_addr, .dst = ip->dst_addr,
                .iif = port->id, .proto = ip->next_proto_id };
            unsigned length = total - ihl;
            const uint8_t *l4 = (const uint8_t *)ip + ihl;
            if ((key.proto == IPPROTO_UDP && length >= 8) ||
                (key.proto == IPPROTO_TCP && length >= 20)) {
                key.ports_valid = 1;
                key.sport = (uint16_t)((uint16_t)l4[0] << 8 | l4[1]);
                key.dport = (uint16_t)((uint16_t)l4[2] << 8 | l4[3]);
            }
            if (!net_acl_accept(rt->network, &rt->acl_stats, &key, total)) {
                node_drop(rt, NODE_IPV4_INPUT, m, &ctx, DROP_ACL, 0);
                continue;
            }
        }
        if (!netif_is_local_ip(rt, ip->dst_addr)) {
            if (!rt->ipv4_forwarding) {
                node_drop(rt, NODE_IPV4_INPUT, m, &ctx, DROP_FORWARDING_DISABLED, 0);
                continue;
            }
            uint32_t src = rte_be_to_cpu_32(ip->src_addr), dst = rte_be_to_cpu_32(ip->dst_addr);
            if (!ipv4_destination_valid(rt, ip->src_addr) || (src >> 16) == 0xa9fe) {
                node_drop(rt, NODE_IPV4_INPUT, m, &ctx, DROP_INVALID_SOURCE, 0);
                continue;
            }
            if (!ipv4_destination_valid(rt, ip->dst_addr) || (dst >> 16) == 0xa9fe) {
                node_drop(rt, NODE_IPV4_INPUT, m, &ctx, DROP_INVALID_DESTINATION, 0);
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
        default: node_drop(rt, NODE_IPV4_INPUT, m, &ctx, DROP_UNSUPPORTED_PROTOCOL, 0); break;
        }
    }
}
