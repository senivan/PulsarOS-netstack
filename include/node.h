#pragma once

#include <stdint.h>

struct app_runtime;
struct node_frame;
struct node_output;

enum node_id {
    NODE_DROP, NODE_ETH_INPUT, NODE_ARP_INPUT, NODE_IPV4_INPUT,
    NODE_ICMP_INPUT, NODE_UDP_INPUT, NODE_TCP_INPUT, NODE_TX, NODE_MAX
};

struct node_stats { uint64_t packets, bytes, drops, errors; };
typedef void (*node_run_t)(struct app_runtime *, const struct node_frame *, struct node_output *);
struct dp_node { enum node_id id; const char *name; node_run_t run; struct node_stats stats; };
