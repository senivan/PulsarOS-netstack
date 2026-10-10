#include <string.h>
#include <rte_cycles.h>
#include "runtime.h"
#include "arp.h"

static void release_pending(struct app_runtime *rt, struct pending_neighbour *pending)
{
    struct node_frame frame = { .count = pending->count };
    for (uint16_t i = 0; i < frame.count; i++) {
        frame.pkts[i] = pending->packets[i];
        frame.ctxs[i] = pending->contexts[i];
    }
    /* Detach before handing ownership back to the graph, including its failure paths. */
    memset(pending, 0, sizeof(*pending));
    if (rt->active_output) {
        for (uint16_t i = 0; i < frame.count; i++)
            node_enqueue(rt->active_output, NODE_ETH_OUTPUT, frame.pkts[i], &frame.ctxs[i]);
    } else graph_submit(rt, NODE_ETH_OUTPUT, &frame);
}

static void discard_pending(struct app_runtime *rt, struct pending_neighbour *pending,
                            enum drop_reason reason, uint64_t now)
{
    struct pending_neighbour detached = *pending;
    memset(pending, 0, sizeof(*pending));
    /* Error output may reuse the detached entry for return-path resolution. */
    rt->graph.nodes[NODE_DROP].stats.packets += detached.count;
    rt->graph.nodes[NODE_DROP].stats.drops += detached.count;
    rt->graph.nodes[NODE_ETH_OUTPUT].stats.drops += detached.count;
    rt->graph.drop_reasons[reason] += detached.count;
    for (uint16_t i = 0; i < detached.count; i++) {
        struct rte_mbuf *m = detached.packets[i];
        if (reason == DROP_NEIGHBOUR_RESOLUTION_TIMEOUT && detached.contexts[i].transit)
            icmp_send_error(rt, m, &detached.contexts[i], 3, 1, 0, now);
        rt->graph.nodes[NODE_DROP].stats.bytes += rte_pktmbuf_pkt_len(m);
        rte_pktmbuf_free(m);
    }
}

enum drop_reason neighbour_queue(struct app_runtime *rt, uint16_t netif_id,
                                  struct rte_mbuf *m, const struct packet_ctx *ctx, uint64_t now)
{
    struct pending_neighbour *pending = NULL, *empty = NULL;
    for (unsigned i = 0; i < NEIGHBOUR_PENDING_MAX; i++) {
        struct pending_neighbour *entry = &rt->pending_neighbours.entries[i];
        if (!entry->count) { if (!empty) empty = entry; }
        else if (entry->netif_id == netif_id && entry->ip_be == ctx->next_hop_ip_be) {
            pending = entry;
            break;
        }
    }
    if (!pending) pending = empty;
    if (!pending) return DROP_NEIGHBOUR_PENDING_FULL;
    if (pending->count == NEIGHBOUR_PENDING_QUEUE_MAX) return DROP_NEIGHBOUR_QUEUE_FULL;
    const struct port_state *port = netif_by_id(rt, netif_id);
    if (!port || !port->started || port->port_id != ctx->egress_port_id) return DROP_INVALID_EGRESS;
    int first = !pending->count;
    if (first) {
        pending->netif_id = netif_id;
        pending->ip_be = ctx->next_hop_ip_be;
        pending->requests = 1;
        pending->last_request = now;
    }
    pending->packets[pending->count] = m;
    pending->contexts[pending->count] = *ctx;
    pending->contexts[pending->count++].report_acceptance = 0;
    if (ctx->report_acceptance) rt->accepted_sends++;
    if (first) arp_request(rt, port, pending->ip_be);
    return DROP_NONE;
}

int neighbour_update(struct app_runtime *rt, uint16_t netif_id, uint32_t ip_be,
                      const struct rte_ether_addr *mac)
{
    int rc = neighbour_learn(&rt->neighbours, netif_id, ip_be, mac);
    if (rc) return rc;
    for (unsigned i = 0; i < NEIGHBOUR_PENDING_MAX; i++) {
        struct pending_neighbour *pending = &rt->pending_neighbours.entries[i];
        if (pending->count && pending->netif_id == netif_id && pending->ip_be == ip_be)
            release_pending(rt, pending);
    }
    return 0;
}

void neighbour_tick(struct app_runtime *rt, uint64_t now)
{
    for (unsigned i = 0; i < NEIGHBOUR_PENDING_MAX; i++) {
        struct pending_neighbour *pending = &rt->pending_neighbours.entries[i];
        if (!pending->count) continue;
        const struct port_state *port = netif_by_id(rt, pending->netif_id);
        if (!port || !port->started) {
            discard_pending(rt, pending, DROP_INVALID_EGRESS, now);
            continue;
        }
        struct rte_ether_addr mac;
        if (!neighbour_lookup(&rt->neighbours, pending->netif_id, pending->ip_be, &mac)) {
            release_pending(rt, pending);
            continue;
        }
        if (now - pending->last_request < rte_get_timer_hz() * ARP_RETRY_SECONDS) continue;
        if (pending->requests == ARP_MAX_REQUESTS) {
            discard_pending(rt, pending, DROP_NEIGHBOUR_RESOLUTION_TIMEOUT, now);
            continue;
        }
        pending->requests++;
        pending->last_request = now;
        arp_request(rt, port, pending->ip_be);
    }
}

void neighbour_fini(struct app_runtime *rt)
{
    for (unsigned i = 0; i < NEIGHBOUR_PENDING_MAX; i++)
        discard_pending(rt, &rt->pending_neighbours.entries[i], DROP_NEIGHBOUR_CANCELLED, 0);
}

_Static_assert(NEIGHBOUR_PENDING_QUEUE_MAX <= GRAPH_FRAME_SIZE, "pending queue must fit a graph frame");
