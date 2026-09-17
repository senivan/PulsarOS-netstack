#include <string.h>
#include <rte_arp.h>
#include "internal.h"
#include "arp.h"

void arp_request(struct app_runtime *rt, const struct port_state *port, uint32_t target_ip_be)
{
    struct rte_mbuf *m = rte_pktmbuf_alloc(rt->mbuf_pool);
    if (!m) {
        rt->graph.nodes[NODE_ARP_OUTPUT].stats.drops++;
        rt->graph.nodes[NODE_ARP_OUTPUT].stats.errors++;
        rt->graph.drop_reasons[DROP_MBUF_ALLOCATION_FAILED]++;
        return;
    }
    struct node_frame frame = { .count = 1 };
    frame.pkts[0] = m;
    frame.ctxs[0].egress_port_id = port->port_id;
    frame.ctxs[0].next_hop_ip_be = target_ip_be;
    if (rt->active_output) node_enqueue(rt->active_output, NODE_ARP_OUTPUT, m, &frame.ctxs[0]);
    else graph_submit(rt, NODE_ARP_OUTPUT, &frame);
}

void arp_output_node_run(struct app_runtime *rt, const struct node_frame *in, struct node_output *out)
{
    for (uint16_t i = 0; i < in->count; i++) {
        struct rte_mbuf *m = in->pkts[i];
        struct packet_ctx ctx = in->ctxs[i];
        const struct port_state *port = netif_by_dpdk_port(rt, ctx.egress_port_id);
        if (!port || !port->started) {
            node_drop(rt, NODE_ARP_OUTPUT, m, &ctx, DROP_INVALID_EGRESS, 1);
            continue;
        }
        uint16_t length = sizeof(struct rte_ether_hdr) + sizeof(struct rte_arp_hdr);
        struct rte_ether_hdr *eth = (struct rte_ether_hdr *)rte_pktmbuf_append(m, length);
        if (!eth) {
            node_drop(rt, NODE_ARP_OUTPUT, m, &ctx, DROP_NO_TAILROOM, 1);
            continue;
        }
        memset(eth, 0, length);
        eth->src_addr = port->mac;
        memset(&eth->dst_addr, 0xff, sizeof(eth->dst_addr));
        eth->ether_type = rte_cpu_to_be_16(RTE_ETHER_TYPE_ARP);
        struct rte_arp_hdr *arp = (struct rte_arp_hdr *)(eth + 1);
        arp->arp_hardware = rte_cpu_to_be_16(RTE_ARP_HRD_ETHER);
        arp->arp_protocol = rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV4);
        arp->arp_hlen = RTE_ETHER_ADDR_LEN;
        arp->arp_plen = 4;
        arp->arp_opcode = rte_cpu_to_be_16(RTE_ARP_OP_REQUEST);
        arp->arp_data.arp_sha = port->mac;
        arp->arp_data.arp_sip = port->ip_be;
        arp->arp_data.arp_tip = ctx.next_hop_ip_be;
        node_enqueue(out, NODE_TX, m, &ctx);
    }
}
