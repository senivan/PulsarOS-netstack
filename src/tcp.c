#include <errno.h>
#include <string.h>
#include <rte_cycles.h>
#include <rte_random.h>
#include <rte_tcp.h>
#include "runtime.h"

static int before(uint32_t a, uint32_t b) { return (int32_t)(a - b) < 0; }

static struct ps_socket_entry *connection(struct app_runtime *rt, const struct ps_sockaddr *local,
                                          const struct ps_sockaddr *remote)
{
    for (unsigned i = 0; i < PS_SOCKET_MAX; i++) {
        struct ps_socket_entry *s = &rt->sockets.entries[i];
        if (s->allocated && s->type == PS_SOCK_STREAM && s->transport.tcp.state != TCP_CLOSED &&
            s->transport.tcp.state != TCP_LISTEN && s->local.ip_be == local->ip_be &&
            s->local.port == local->port && s->remote.ip_be == remote->ip_be &&
            s->remote.port == remote->port) return s;
    }
    return NULL;
}

static struct ps_socket_entry *listener(struct app_runtime *rt, const struct ps_sockaddr *local)
{
    for (unsigned i = 0; i < PS_SOCKET_MAX; i++) {
        struct ps_socket_entry *s = &rt->sockets.entries[i];
        if (s->allocated && s->open && s->type == PS_SOCK_STREAM && s->transport.tcp.state == TCP_LISTEN &&
            s->local.port == local->port && (!s->local.ip_be || s->local.ip_be == local->ip_be)) return s;
    }
    return NULL;
}

static void start_flight(struct ps_socket_entry *s, uint8_t flags, uint16_t length, uint64_t now)
{
    struct tcp_connection *c = &s->transport.tcp;
    c->flight_flags = flags;
    c->flight_len = length;
    c->snd_nxt = c->snd_una + length + !!(flags & (RTE_TCP_SYN_FLAG | RTE_TCP_FIN_FLAG));
    c->rto = rte_get_timer_hz();
    c->deadline = now + c->rto;
    c->retries = 0;
}

static void initialize(struct ps_socket_entry *s, uint64_t now)
{
    struct tcp_connection *c = &s->transport.tcp;
    c->snd_una = c->snd_nxt = (uint32_t)rte_rand() ^ (uint32_t)now;
    c->mss = 536;
    c->peer_window = UINT16_MAX;
}

static void cancel_queued(struct app_runtime *rt, const struct ps_socket_entry *s)
{
    for (unsigned i = 0; i < NEIGHBOUR_PENDING_MAX; i++) {
        struct pending_neighbour *pending = &rt->pending_neighbours.entries[i];
        unsigned keep = 0;
        for (unsigned j = 0; j < pending->count; j++) {
            const struct packet_ctx *ctx = &pending->contexts[j];
            if (ctx->ip_protocol == IPPROTO_TCP && ctx->src_ip_be == s->local.ip_be &&
                ctx->dst_ip_be == s->remote.ip_be && ctx->src_port == s->local.port && ctx->dst_port == s->remote.port) {
                rt->graph.nodes[NODE_DROP].stats.packets++;
                rt->graph.nodes[NODE_DROP].stats.drops++;
                rt->graph.nodes[NODE_DROP].stats.bytes += rte_pktmbuf_pkt_len(pending->packets[j]);
                rt->graph.nodes[NODE_ETH_OUTPUT].stats.drops++;
                rt->graph.drop_reasons[DROP_NEIGHBOUR_CANCELLED]++;
                rte_pktmbuf_free(pending->packets[j]);
            } else {
                pending->packets[keep] = pending->packets[j];
                pending->contexts[keep++] = *ctx;
            }
        }
        pending->count = keep;
        if (!keep) memset(pending, 0, sizeof(*pending));
    }
}

void tcp_fail(struct app_runtime *rt, struct ps_socket_entry *s, int error)
{
    if (s->transport.tcp.state != TCP_CLOSED) {
        cancel_queued(rt, s);
        rt->tcp_stats.closed++;
    }
    if (!s->open) { memset(s, 0, sizeof(*s)); return; }
    s->error = error;
    memset(&s->transport.tcp, 0, sizeof(s->transport.tcp));
}

void tcp_time_wait(struct ps_socket_entry *s, uint64_t now)
{
    struct tcp_connection *c = &s->transport.tcp;
    c->state = TCP_TIME_WAIT;
    c->flight_flags = 0;
    c->deadline = 0;
    c->expires = now + TCP_TIME_WAIT_SECONDS * rte_get_timer_hz();
}

void tcp_kick(struct app_runtime *rt, struct ps_socket_entry *s, uint64_t now)
{
    struct tcp_connection *c = &s->transport.tcp;
    if (c->flight_flags || (c->state != TCP_ESTABLISHED && c->state != TCP_CLOSE_WAIT)) return;
    if (!c->peer_window && (c->tx_len || c->closing)) {
        if (!c->deadline) { c->rto = rte_get_timer_hz(); c->deadline = now + c->rto; c->retries = 0; }
        return;
    }
    if (c->tx_len) {
        struct route_result route;
        if (ipv4_route_lookup(rt, s->remote.ip_be, &route) != DROP_NONE || route.mtu <= 40) {
            tcp_fail(rt, s, ENETUNREACH);
            return;
        }
        uint16_t length = RTE_MIN(c->tx_len, RTE_MIN(c->peer_window, RTE_MIN(c->mss, route.mtu - 40)));
        start_flight(s, RTE_TCP_ACK_FLAG | RTE_TCP_PSH_FLAG, length, now);
        tcp_emit_flight(rt, s);
    } else if (c->closing) {
        c->state = c->state == TCP_CLOSE_WAIT ? TCP_LAST_ACK : TCP_FIN_WAIT_1;
        start_flight(s, RTE_TCP_FIN_FLAG | RTE_TCP_ACK_FLAG, 0, now);
        tcp_emit_flight(rt, s);
    }
}

int tcp_connect(struct app_runtime *rt, struct ps_socket_entry *s, const struct ps_sockaddr *addr)
{
    struct tcp_connection *c = &s->transport.tcp;
    if (s->error) return -s->error;
    if (c->state == TCP_SYN_SENT || c->state == TCP_SYN_RECEIVED) return -EALREADY;
    if (c->state != TCP_CLOSED) return c->state == TCP_LISTEN ? -EINVAL : -EISCONN;
    struct route_result route;
    if (ipv4_route_lookup(rt, addr->ip_be, &route) != DROP_NONE || route.mtu < 44) return -ENETUNREACH;
    if (!s->local.port) {
        int rc = socket_bind(rt, s, &(struct ps_sockaddr){0});
        if (rc) return rc;
    }
    if (!s->local.ip_be) s->local.ip_be = route.source_ip_be;
    s->remote = *addr;
    uint64_t now = rte_get_timer_cycles();
    initialize(s, now);
    c->state = TCP_SYN_SENT;
    start_flight(s, RTE_TCP_SYN_FLAG, 0, now);
    tcp_emit_flight(rt, s);
    return -EINPROGRESS;
}

int tcp_listen(struct ps_socket_entry *s, int backlog)
{
    if (backlog <= 0 || !s->local.port) return -EINVAL;
    struct tcp_connection *c = &s->transport.tcp;
    if (c->state != TCP_CLOSED && c->state != TCP_LISTEN) return -EINVAL;
    c->backlog = RTE_MIN(backlog, PS_SOCKET_MAX - 1);
    c->state = TCP_LISTEN;
    return 0;
}

ps_fd_t tcp_accept(struct app_runtime *rt, struct ps_socket_entry *s, struct ps_sockaddr *peer)
{
    if (s->transport.tcp.state != TCP_LISTEN) return -EINVAL;
    for (unsigned i = 0; i < PS_SOCKET_MAX; i++) {
        struct ps_socket_entry *child = &rt->sockets.entries[i];
        struct tcp_connection *c = &child->transport.tcp;
        if (child->allocated && child->type == PS_SOCK_STREAM && c->parent == s->fd &&
            (c->state == TCP_ESTABLISHED || c->state == TCP_CLOSE_WAIT)) {
            child->open = 1;
            c->parent = 0;
            c->expires = 0;
            if (peer) *peer = child->remote;
            return child->fd;
        }
    }
    return -EAGAIN;
}

void tcp_close(struct app_runtime *rt, struct ps_socket_entry *s, uint64_t now)
{
    struct tcp_connection *c = &s->transport.tcp;
    s->open = 0;
    if (c->state == TCP_LISTEN) {
        for (unsigned i = 0; i < PS_SOCKET_MAX; i++) {
            struct ps_socket_entry *child = &rt->sockets.entries[i];
            if (!child->allocated || child->type != PS_SOCK_STREAM || child->transport.tcp.parent != s->fd) continue;
            struct ps_sockaddr local = child->local, remote = child->remote;
            uint32_t seq = child->transport.tcp.snd_nxt, ack = child->transport.tcp.rcv_nxt;
            tcp_fail(rt, child, ECONNRESET);
            tcp_emit(rt, &local, &remote, seq, ack, RTE_TCP_RST_FLAG | RTE_TCP_ACK_FLAG, 0, NULL, 0);
        }
        memset(s, 0, sizeof(*s));
    } else if (c->state == TCP_CLOSED || c->state == TCP_SYN_SENT || c->state == TCP_SYN_RECEIVED) {
        tcp_fail(rt, s, ECONNABORTED);
    } else {
        c->closing = 1;
        tcp_kick(rt, s, now);
    }
}

ssize_t tcp_send(struct app_runtime *rt, struct ps_socket_entry *s, const void *data, size_t length)
{
    struct tcp_connection *c = &s->transport.tcp;
    if (s->error) return -s->error;
    if (c->state != TCP_ESTABLISHED && c->state != TCP_CLOSE_WAIT) return -ENOTCONN;
    if (!length) return 0;
    size_t accepted = RTE_MIN(length, TCP_BUFFER_SIZE - c->tx_len);
    if (!accepted) return -EAGAIN;
    memcpy(c->tx + c->tx_len, data, accepted);
    c->tx_len += accepted;
    tcp_kick(rt, s, rte_get_timer_cycles());
    return s->error ? -s->error : (ssize_t)accepted;
}

ssize_t tcp_recv(struct app_runtime *rt, struct ps_socket_entry *s, void *data, size_t length)
{
    struct tcp_connection *c = &s->transport.tcp;
    if (!length) return 0;
    if (!c->rx_len) {
        if (s->error) return -s->error;
        if (c->peer_fin) return 0;
        return c->state == TCP_ESTABLISHED ? -EAGAIN : -ENOTCONN;
    }
    size_t received = RTE_MIN(length, c->rx_len);
    memcpy(data, c->rx, received);
    c->rx_len -= received;
    memmove(c->rx, c->rx + received, c->rx_len);
    tcp_ack(rt, s);
    return (ssize_t)received;
}

static void reset_reply(struct app_runtime *rt, const struct ps_sockaddr *local,
                         const struct ps_sockaddr *remote, uint32_t seq, uint32_t ack,
                         uint8_t flags, uint16_t length)
{
    if (flags & RTE_TCP_RST_FLAG) return;
    uint8_t response = RTE_TCP_RST_FLAG;
    uint32_t response_seq = ack, response_ack = 0;
    if (!(flags & RTE_TCP_ACK_FLAG)) {
        response |= RTE_TCP_ACK_FLAG;
        response_seq = 0;
        response_ack = seq + length + !!(flags & RTE_TCP_SYN_FLAG) + !!(flags & RTE_TCP_FIN_FLAG);
    }
    tcp_emit(rt, local, remote, response_seq, response_ack, response, 0, NULL, 0);
    rt->tcp_stats.resets++;
}

static enum drop_reason passive_open(struct app_runtime *rt, struct ps_socket_entry *listen,
                                      const struct ps_sockaddr *local, const struct ps_sockaddr *remote,
                                      uint32_t seq, uint16_t window, uint16_t mss, uint64_t now)
{
    unsigned pending = 0;
    for (unsigned i = 0; i < PS_SOCKET_MAX; i++) {
        struct ps_socket_entry *s = &rt->sockets.entries[i];
        if (s->allocated && s->type == PS_SOCK_STREAM && s->transport.tcp.parent == listen->fd) pending++;
    }
    if (pending >= listen->transport.tcp.backlog) return DROP_TCP_BACKLOG_FULL;
    struct ps_socket_entry *s = socket_allocate(rt, PS_SOCK_STREAM);
    if (!s) return DROP_TCP_BACKLOG_FULL;
    s->open = 0;
    s->local = *local;
    s->remote = *remote;
    initialize(s, now);
    struct tcp_connection *c = &s->transport.tcp;
    c->parent = listen->fd;
    c->state = TCP_SYN_RECEIVED;
    c->rcv_nxt = seq + 1;
    c->peer_window = window;
    c->mss = mss;
    c->snd_wl1 = seq;
    start_flight(s, RTE_TCP_SYN_FLAG | RTE_TCP_ACK_FLAG, 0, now);
    tcp_emit_flight(rt, s);
    rt->tcp_stats.syns++;
    return DROP_NONE;
}

static void acknowledge(struct app_runtime *rt, struct ps_socket_entry *s, uint32_t ack, uint64_t now)
{
    struct tcp_connection *c = &s->transport.tcp;
    if (!before(c->snd_una, ack)) { rt->tcp_stats.duplicate_acks++; return; }
    uint32_t bytes = ack - c->snd_una;
    if (c->flight_len) {
        c->tx_len -= bytes;
        c->flight_len -= bytes;
        memmove(c->tx, c->tx + bytes, c->tx_len);
    }
    c->snd_una = ack;
    c->deadline = now + c->rto;
    if (ack != c->snd_nxt) return;
    uint8_t flags = c->flight_flags;
    c->flight_flags = 0;
    c->deadline = 0;
    c->retries = 0;
    if (flags & RTE_TCP_FIN_FLAG) {
        if (c->state == TCP_LAST_ACK) { tcp_fail(rt, s, 0); return; }
        if (c->peer_fin) tcp_time_wait(s, now);
        else {
            c->state = TCP_FIN_WAIT_2;
            c->expires = now + TCP_FIN_WAIT_SECONDS * rte_get_timer_hz();
        }
    }
}

enum drop_reason tcp_input(struct app_runtime *rt, const struct packet_ctx *ctx, const struct rte_tcp_hdr *tcp,
                           uint16_t header_len, uint16_t length, uint16_t mss, uint64_t now)
{
    struct ps_sockaddr local = { .ip_be = ctx->dst_ip_be, .port = rte_be_to_cpu_16(tcp->dst_port) };
    struct ps_sockaddr remote = { .ip_be = ctx->src_ip_be, .port = rte_be_to_cpu_16(tcp->src_port) };
    if (!ipv4_destination_valid(rt, remote.ip_be)) return DROP_INVALID_SOURCE;
    uint32_t seq = rte_be_to_cpu_32(tcp->sent_seq), ack = rte_be_to_cpu_32(tcp->recv_ack);
    uint16_t window = rte_be_to_cpu_16(tcp->rx_win);
    uint8_t flags = tcp->tcp_flags;
    struct ps_socket_entry *s = connection(rt, &local, &remote);
    if (!s) {
        struct ps_socket_entry *listen = listener(rt, &local);
        if (listen && !(flags & RTE_TCP_RST_FLAG) && !(flags & RTE_TCP_ACK_FLAG) && (flags & RTE_TCP_SYN_FLAG))
            return passive_open(rt, listen, &local, &remote, seq, window, mss, now);
        reset_reply(rt, &local, &remote, seq, ack, flags, length);
        return DROP_TCP_NO_SOCKET;
    }
    struct tcp_connection *c = &s->transport.tcp;
    if (c->state == TCP_SYN_SENT) {
        if ((flags & RTE_TCP_ACK_FLAG) && ack != c->snd_nxt) {
            reset_reply(rt, &local, &remote, seq, ack, flags, length);
            return DROP_TCP_INVALID_STATE;
        }
        if (flags & RTE_TCP_RST_FLAG) {
            if (flags & RTE_TCP_ACK_FLAG) tcp_fail(rt, s, ECONNREFUSED);
            return DROP_NONE;
        }
        if ((flags & (RTE_TCP_SYN_FLAG | RTE_TCP_ACK_FLAG)) != (RTE_TCP_SYN_FLAG | RTE_TCP_ACK_FLAG))
            return DROP_TCP_INVALID_STATE;
        c->rcv_nxt = seq + 1;
        c->snd_una = ack;
        c->flight_flags = 0;
        c->deadline = 0;
        c->mss = mss;
        c->peer_window = window;
        c->snd_wl1 = seq;
        c->snd_wl2 = ack;
        c->state = TCP_ESTABLISHED;
        rt->tcp_stats.established++;
        tcp_ack(rt, s);
        return DROP_NONE;
    }
    if (c->state == TCP_SYN_RECEIVED && (flags & RTE_TCP_SYN_FLAG) && seq + 1 == c->rcv_nxt) {
        tcp_emit_flight(rt, s);
        return DROP_NONE;
    }
    if (c->state == TCP_TIME_WAIT) {
        if (!(flags & RTE_TCP_RST_FLAG)) {
            tcp_ack(rt, s);
            if ((flags & RTE_TCP_FIN_FLAG) && seq + length + 1 == c->rcv_nxt) tcp_time_wait(s, now);
        }
        return DROP_NONE;
    }
    if (seq != c->rcv_nxt) {
        if (!(flags & RTE_TCP_RST_FLAG)) tcp_ack(rt, s);
        else if (!before(seq, c->rcv_nxt) && before(seq, c->rcv_nxt + TCP_BUFFER_SIZE - c->rx_len)) tcp_ack(rt, s);
        rt->tcp_stats.out_of_order++;
        return DROP_TCP_OUT_OF_ORDER;
    }
    if (flags & RTE_TCP_RST_FLAG) { rt->tcp_stats.resets++; tcp_fail(rt, s, ECONNRESET); return DROP_NONE; }
    if (flags & RTE_TCP_SYN_FLAG) { tcp_ack(rt, s); return DROP_TCP_INVALID_STATE; }
    if ((length || (flags & RTE_TCP_FIN_FLAG)) && c->rx_len == TCP_BUFFER_SIZE) {
        tcp_ack(rt, s);
        return DROP_TCP_OUT_OF_ORDER;
    }
    if (!(flags & RTE_TCP_ACK_FLAG)) return DROP_TCP_INVALID_STATE;
    if (before(c->snd_nxt, ack)) { tcp_ack(rt, s); return DROP_TCP_INVALID_STATE; }
    if (c->state == TCP_SYN_RECEIVED) {
        if (ack != c->snd_nxt) {
            reset_reply(rt, &local, &remote, seq, ack, flags, length);
            return DROP_TCP_INVALID_STATE;
        }
        c->state = TCP_ESTABLISHED;
        c->expires = now + 60 * rte_get_timer_hz();
        rt->tcp_stats.established++;
    }
    acknowledge(rt, s, ack, now);
    if (!s->allocated || c->state == TCP_CLOSED) return DROP_NONE;
    if (!before(seq, c->snd_wl1) && (seq != c->snd_wl1 || !before(ack, c->snd_wl2))) {
        c->peer_window = window;
        c->snd_wl1 = seq;
        c->snd_wl2 = ack;
    }
    if (!c->peer_fin && length) {
        uint16_t received = RTE_MIN(length, TCP_BUFFER_SIZE - c->rx_len);
        memcpy(c->rx + c->rx_len, (const uint8_t *)tcp + header_len, received);
        c->rx_len += received;
        c->rcv_nxt += received;
        if (received != length) { tcp_ack(rt, s); tcp_kick(rt, s, now); return DROP_NONE; }
    }
    if (!c->peer_fin && (flags & RTE_TCP_FIN_FLAG) && c->rx_len < TCP_BUFFER_SIZE) {
        c->peer_fin = 1;
        c->rcv_nxt++;
        if (c->state == TCP_ESTABLISHED) c->state = TCP_CLOSE_WAIT;
        else if (c->state == TCP_FIN_WAIT_2) tcp_time_wait(s, now);
    }
    if (length || (flags & RTE_TCP_FIN_FLAG)) tcp_ack(rt, s);
    tcp_kick(rt, s, now);
    return DROP_NONE;
}
