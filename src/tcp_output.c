#include <errno.h>
#include <string.h>
#include <rte_ip.h>
#include <rte_tcp.h>
#include "runtime.h"

int tcp_emit(struct app_runtime *rt, const struct ps_sockaddr *local, const struct ps_sockaddr *remote,
              uint32_t seq, uint32_t ack, uint8_t flags, uint16_t window,
              const void *data, uint16_t length)
{
    struct route_result route;
    if (ipv4_route_lookup(rt, remote->ip_be, &route) != DROP_NONE) {
        rt->tcp_stats.output_failed++;
        return -ENETUNREACH;
    }
    unsigned header_len = sizeof(struct rte_tcp_hdr) + ((flags & RTE_TCP_SYN_FLAG) ? 4 : 0);
    if (route.mtu < 20 + header_len + length) {
        rt->tcp_stats.output_failed++;
        return -EMSGSIZE;
    }
    struct rte_mbuf *m = rte_pktmbuf_alloc(rt->mbuf_pool);
    if (!m) { rt->tcp_stats.output_failed++; return -ENOMEM; }
    struct rte_tcp_hdr *tcp = (struct rte_tcp_hdr *)rte_pktmbuf_append(m, header_len + length);
    if (!tcp) { rte_pktmbuf_free(m); rt->tcp_stats.output_failed++; return -ENOBUFS; }
    memset(tcp, 0, header_len);
    tcp->src_port = rte_cpu_to_be_16(local->port);
    tcp->dst_port = rte_cpu_to_be_16(remote->port);
    tcp->sent_seq = rte_cpu_to_be_32(seq);
    tcp->recv_ack = rte_cpu_to_be_32(ack);
    tcp->data_off = (uint8_t)((header_len / 4) << 4);
    tcp->tcp_flags = flags;
    tcp->rx_win = rte_cpu_to_be_16(window);
    if (flags & RTE_TCP_SYN_FLAG) {
        uint16_t mss = route.mtu - 40;
        uint8_t *option = (uint8_t *)(tcp + 1);
        option[0] = 2; option[1] = 4;
        option[2] = (uint8_t)(mss >> 8); option[3] = (uint8_t)mss;
    }
    if (length) memcpy((uint8_t *)tcp + header_len, data, length);
    struct rte_ipv4_hdr pseudo = { .version_ihl = 0x45,
        .total_length = rte_cpu_to_be_16(20 + header_len + length), .next_proto_id = IPPROTO_TCP,
        .src_addr = local->ip_be, .dst_addr = remote->ip_be };
    tcp->cksum = rte_ipv4_udptcp_cksum(&pseudo, tcp);
    struct packet_ctx ctx = { .egress_port_id = netif_by_id(rt, route.netif_id)->port_id,
        .src_ip_be = local->ip_be, .dst_ip_be = remote->ip_be, .next_hop_ip_be = route.next_hop_be,
        .src_port = local->port, .dst_port = remote->port, .ip_protocol = IPPROTO_TCP };
    /* Only copied bytes survive graph submission; no socket or RX-mbuf pointers. */
    int rc;
    if (rt->active_output) rc = node_enqueue(rt->active_output, NODE_IPV4_OUTPUT, m, &ctx);
    else {
        struct node_frame frame = { .count = 1 };
        frame.pkts[0] = m;
        frame.ctxs[0] = ctx;
        uint64_t before = rt->graph.nodes[NODE_IPV4_OUTPUT].stats.packets;
        graph_submit(rt, NODE_IPV4_OUTPUT, &frame);
        rc = rt->graph.nodes[NODE_IPV4_OUTPUT].stats.packets == before ? -1 : 0;
    }
    if (rc) rt->tcp_stats.output_failed++;
    else rt->tcp_stats.sent++;
    return rc ? -ENOBUFS : 0;
}

int tcp_emit_flight(struct app_runtime *rt, struct ps_socket_entry *s)
{
    struct tcp_connection *c = &s->transport.tcp;
    return tcp_emit(rt, &s->local, &s->remote, c->snd_una, c->rcv_nxt,
                    c->flight_flags, TCP_BUFFER_SIZE - c->rx_len, c->tx, c->flight_len);
}

void tcp_ack(struct app_runtime *rt, struct ps_socket_entry *s)
{
    struct tcp_connection *c = &s->transport.tcp;
    tcp_emit(rt, &s->local, &s->remote, c->snd_nxt, c->rcv_nxt,
              RTE_TCP_ACK_FLAG, TCP_BUFFER_SIZE - c->rx_len, NULL, 0);
}
