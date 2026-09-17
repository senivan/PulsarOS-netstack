#include "internal.h"

static void register_node(struct app_runtime *rt, enum node_id id,
                          const char *name, node_run_t run)
{
    rt->graph.nodes[id] = (struct dp_node){ .id = id, .name = name, .run = run };
}

void nodes_register(struct app_runtime *rt)
{
    register_node(rt, NODE_DROP, "drop", drop_node_run);
    register_node(rt, NODE_ETH_INPUT, "eth_input", eth_input_node_run);
    register_node(rt, NODE_ARP_OUTPUT, "arp_output", arp_output_node_run);
    register_node(rt, NODE_ARP_INPUT, "arp_input", arp_input_node_run);
    register_node(rt, NODE_IPV4_INPUT, "ipv4_input", ipv4_input_node_run);
    register_node(rt, NODE_ICMP_INPUT, "icmp_input", icmp_input_node_run);
    register_node(rt, NODE_UDP_INPUT, "udp_input", udp_input_node_run);
    register_node(rt, NODE_TCP_INPUT, "tcp_input", tcp_input_node_run);
    register_node(rt, NODE_IPV4_OUTPUT, "ipv4_output", ipv4_output_node_run);
    register_node(rt, NODE_IPV4_ROUTE, "ipv4_route", ipv4_route_node_run);
    register_node(rt, NODE_UDP_OUTPUT, "udp_output", udp_output_node_run);
    register_node(rt, NODE_ETH_OUTPUT, "eth_output", eth_output_node_run);
    register_node(rt, NODE_TX, "tx", tx_node_run);
}
