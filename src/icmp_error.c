#include <string.h>
#include <rte_cycles.h>
#include <rte_ip.h>
#include "runtime.h"

struct icmp_error_hdr {
    uint8_t type, code;
    uint16_t checksum;
    uint16_t unused, mtu;
};

static int take_token(struct icmp_error_state *state, uint64_t now)
{
    uint64_t interval = rte_get_timer_hz() / ICMP_ERROR_RATE;
    if (!state->initialized) {
        state->initialized = 1;
        state->last_refill = now;
        state->tokens = ICMP_ERROR_BURST;
    }
    uint64_t elapsed = now - state->last_refill;
    uint64_t refill = elapsed / interval;
    if (refill) {
        state->tokens = refill >= ICMP_ERROR_BURST - state->tokens ?
                        ICMP_ERROR_BURST : state->tokens + (uint32_t)refill;
        state->last_refill = now - elapsed % interval;
    }
    if (!state->tokens) return 0;
    state->tokens--;
    return 1;
}

void icmp_send_error(struct app_runtime *rt, const struct rte_mbuf *original,
                     const struct packet_ctx *ctx, uint8_t type, uint8_t code,
                     uint16_t mtu, uint64_t now)
{
    struct icmp_error_state *stats = &rt->icmp_errors;
    if (!rte_pktmbuf_is_contiguous(original) ||
        rte_pktmbuf_data_len(original) < (uint32_t)ctx->l3_offset + sizeof(struct rte_ipv4_hdr)) {
        stats->suppressed++;
        return;
    }
    const struct rte_ipv4_hdr *ip = rte_pktmbuf_mtod_offset(original, const struct rte_ipv4_hdr *, ctx->l3_offset);
    uint16_t ihl = (ip->version_ihl & 15) * 4;
    uint16_t total = rte_be_to_cpu_16(ip->total_length);
    /* RFC 1812 4.3.2.7: errors never provoke errors or answer broadcasts. */
    if ((ip->version_ihl >> 4) != 4 || ihl < sizeof(*ip) || total < ihl ||
        rte_pktmbuf_data_len(original) < (uint32_t)ctx->l3_offset + total ||
        rte_ipv4_cksum(ip) != 0 ||
        !ipv4_destination_valid(rt, ip->src_addr) ||
        (!netif_is_local_ip(rt, ip->dst_addr) && !ipv4_destination_valid(rt, ip->dst_addr)) ||
        (rte_be_to_cpu_16(ip->fragment_offset) & RTE_IPV4_HDR_OFFSET_MASK)) {
        stats->suppressed++;
        return;
    }
    if (ctx->l3_offset >= sizeof(struct rte_ether_hdr)) {
        const struct rte_ether_hdr *eth = rte_pktmbuf_mtod(original, const struct rte_ether_hdr *);
        if (rte_is_multicast_ether_addr(&eth->dst_addr)) { stats->suppressed++; return; }
    }
    if (ip->next_proto_id == IPPROTO_ICMP) {
        const uint8_t *icmp = (const uint8_t *)ip + ihl;
        if (total - ihl < 8 || icmp[0] == 3 || icmp[0] == 4 || icmp[0] == 5 ||
            icmp[0] == 11 || icmp[0] == 12) { stats->suppressed++; return; }
    }
    if (!take_token(stats, now)) { stats->rate_limited++; return; }
    struct route_result route;
    if (ipv4_route_lookup(rt, ip->src_addr, &route) != DROP_NONE ||
        route.mtu < sizeof(*ip) + sizeof(struct icmp_error_hdr) + ihl + RTE_MIN(total - ihl, 8)) {
        stats->failed++;
        return;
    }
    uint16_t limit = RTE_MIN(route.mtu, 576);
    uint16_t quote = RTE_MIN(total, limit - sizeof(*ip) - sizeof(struct icmp_error_hdr));
    struct rte_mbuf *m = rte_pktmbuf_alloc(rt->mbuf_pool);
    if (!m) { stats->failed++; return; }
    struct icmp_error_hdr *error = (struct icmp_error_hdr *)rte_pktmbuf_append(m, sizeof(*error) + quote);
    if (!error) { rte_pktmbuf_free(m); stats->failed++; return; }
    memset(error, 0, sizeof(*error));
    error->type = type;
    error->code = code;
    if (type == 3 && code == 4) error->mtu = rte_cpu_to_be_16(mtu);
    memcpy(error + 1, ip, quote);
    error->checksum = (uint16_t)~rte_raw_cksum(error, sizeof(*error) + quote);
    struct packet_ctx response = { .egress_port_id = netif_by_id(rt, route.netif_id)->port_id,
        .src_ip_be = netif_is_local_ip(rt, ip->dst_addr) ? ip->dst_addr : route.source_ip_be,
        .dst_ip_be = ip->src_addr,
        .next_hop_ip_be = route.next_hop_be, .ip_protocol = IPPROTO_ICMP };
    int rc;
    if (rt->active_output) rc = node_enqueue(rt->active_output, NODE_IPV4_OUTPUT, m, &response);
    else {
        struct node_frame frame = { .count = 1 };
        frame.pkts[0] = m;
        frame.ctxs[0] = response;
        uint64_t before = rt->graph.nodes[NODE_IPV4_OUTPUT].stats.packets;
        graph_submit(rt, NODE_IPV4_OUTPUT, &frame);
        rc = rt->graph.nodes[NODE_IPV4_OUTPUT].stats.packets == before ? -1 : 0;
    }
    if (rc) stats->failed++;
    else stats->generated++;
}
