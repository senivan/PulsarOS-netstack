#define _GNU_SOURCE
#include <assert.h>
#include <errno.h>
#include <sched.h>
#include <stdio.h>
#include <string.h>
#include <rte_arp.h>
#include <rte_cycles.h>
#include <rte_eal.h>
#include <rte_ip.h>
#include <rte_malloc.h>
#include <rte_tcp.h>
#include "runtime.h"

#define POOL_SIZE 511
#define PEER rte_cpu_to_be_32(RTE_IPV4(192u, 0, 2, 1))
#define OTHER rte_cpu_to_be_32(RTE_IPV4(203u, 0, 113, 1))
#define SYN RTE_TCP_SYN_FLAG
#define ACK RTE_TCP_ACK_FLAG
#define FIN RTE_TCP_FIN_FLAG
#define RST RTE_TCP_RST_FLAG
static struct app_runtime rt;
static const struct rte_ether_addr peer_mac = {{2, 0, 0, 0, 0, 1}};
static struct { _Alignas(8) uint8_t data[1600]; unsigned length; } wire[256];
static unsigned count;
static uint16_t tx_limit = UINT16_MAX;

static uint16_t capture(uint16_t port, uint16_t queue, struct rte_mbuf **packets, uint16_t n, void *arg)
{
    (void)queue; (void)arg;
    assert(port == rt.ports[0].port_id);
    n = RTE_MIN(n, tx_limit);
    for (unsigned i = 0; i < n; i++) {
        assert(count < RTE_DIM(wire));
        wire[count].length = rte_pktmbuf_pkt_len(packets[i]);
        memcpy(wire[count++].data, rte_pktmbuf_mtod(packets[i], const void *), rte_pktmbuf_pkt_len(packets[i]));
    }
    return n;
}

static const struct rte_tcp_hdr *segment(unsigned index)
{
    assert(index < count);
    const struct rte_ipv4_hdr *ip = (const struct rte_ipv4_hdr *)(wire[index].data + 14);
    assert(ip->next_proto_id == IPPROTO_TCP && ip->src_addr == rt.ports[0].ip_be);
    assert(rte_ipv4_cksum(ip) == 0 && rte_ipv4_udptcp_cksum(ip, ip + 1) == 0);
    assert(rte_be_to_cpu_16(ip->total_length) <= rt.ports[0].mtu);
    return (const struct rte_tcp_hdr *)(ip + 1);
}

static unsigned allocated(void)
{
    unsigned n = 0;
    for (unsigned i = 0; i < PS_SOCKET_MAX; i++) n += rt.sockets.entries[i].allocated;
    return n;
}

static void reset(void)
{
    neighbour_fini(&rt);
    assert(rte_mempool_avail_count(rt.mbuf_pool) == POOL_SIZE);
    socket_subsystem_fini(&rt);
    assert(socket_subsystem_init(&rt) == 0);
    assert(graph_init(&rt) == 0 && route_init_connected(&rt) == 0);
    memset(&rt.tcp_stats, 0, sizeof(rt.tcp_stats));
    memset(&rt.neighbours, 0, sizeof(rt.neighbours));
    assert(neighbour_learn(&rt.neighbours, rt.ports[0].id, PEER, &peer_mac) == 0);
    rt.ports[0].mtu = 1500;
    count = 0;
    tx_limit = UINT16_MAX;
}

static ps_fd_t listen_on(uint16_t port, int backlog)
{
    ps_fd_t fd = ps_socket(PS_AF_INET, PS_SOCK_STREAM, 0);
    assert(fd > 0);
    assert(ps_bind(fd, &(struct ps_sockaddr){.port = port}) == 0);
    assert(ps_listen(fd, backlog) == 0);
    return fd;
}

static struct rte_mbuf *packet(uint32_t source, uint16_t sport, uint16_t dport,
                                uint32_t seq, uint32_t ack, uint8_t flags,
                                const void *data, unsigned length, uint16_t window, int options)
{
    struct rte_mbuf *m = rte_pktmbuf_alloc(rt.mbuf_pool);
    assert(m);
    unsigned hdr = options ? 24 : 20;
    struct rte_ether_hdr *eth = (struct rte_ether_hdr *)rte_pktmbuf_append(m, 34 + hdr + length);
    assert(eth);
    memset(eth, 0, 34 + hdr + length);
    eth->src_addr = peer_mac;
    eth->dst_addr = rt.ports[0].mac;
    eth->ether_type = rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV4);
    struct rte_ipv4_hdr *ip = (struct rte_ipv4_hdr *)(eth + 1);
    ip->version_ihl = 0x45;
    ip->total_length = rte_cpu_to_be_16(20 + hdr + length);
    ip->time_to_live = 64;
    ip->next_proto_id = IPPROTO_TCP;
    ip->src_addr = source;
    ip->dst_addr = rt.ports[0].ip_be;
    ip->hdr_checksum = rte_ipv4_cksum(ip);
    struct rte_tcp_hdr *tcp = (struct rte_tcp_hdr *)(ip + 1);
    tcp->src_port = rte_cpu_to_be_16(sport);
    tcp->dst_port = rte_cpu_to_be_16(dport);
    tcp->sent_seq = rte_cpu_to_be_32(seq);
    tcp->recv_ack = rte_cpu_to_be_32(ack);
    tcp->data_off = (hdr / 4) << 4;
    tcp->tcp_flags = flags;
    tcp->rx_win = rte_cpu_to_be_16(window);
    if (options) {
        uint8_t *p = (uint8_t *)(tcp + 1);
        p[0] = 2; p[1] = 4; p[2] = 1; p[3] = 44; /* MSS 300. */
    }
    if (length) memcpy((uint8_t *)tcp + hdr, data, length);
    tcp->cksum = rte_ipv4_udptcp_cksum(ip, tcp);
    return m;
}

static void inject(struct rte_mbuf *m, enum drop_reason reason)
{
    unsigned available = rte_mempool_avail_count(rt.mbuf_pool) + 1;
    uint64_t before = rt.graph.drop_reasons[reason];
    struct node_frame frame = { .count = 1 };
    frame.pkts[0] = m;
    frame.ctxs[0].ingress_port_id = rt.ports[0].port_id;
    assert(graph_submit(&rt, NODE_ETH_INPUT, &frame) == 0);
    if (reason) {
        if (rt.graph.drop_reasons[reason] != before + 1) graph_dump_stats(&rt);
        assert(rt.graph.drop_reasons[reason] == before + 1);
    }
    assert(!rt.graph.q_count && !rt.active_output);
    assert(rte_mempool_avail_count(rt.mbuf_pool) == available);
}

static void input(uint16_t sport, uint32_t seq, uint32_t ack, uint8_t flags, const void *data, unsigned length)
{
    inject(packet(PEER, sport, 9000, seq, ack, flags, data, length, 8192, flags & SYN), DROP_NONE);
}

static struct ps_socket_entry *child(ps_fd_t listener)
{
    for (unsigned i = 0; i < PS_SOCKET_MAX; i++) {
        struct ps_socket_entry *s = &rt.sockets.entries[i];
        if (s->allocated && s->type == PS_SOCK_STREAM && s->transport.tcp.parent == listener) return s;
    }
    return NULL;
}

static ps_fd_t establish(ps_fd_t listener, uint16_t sport, uint32_t seq)
{
    unsigned index = count;
    input(sport, seq, 0, SYN, NULL, 0);
    struct ps_socket_entry *s = child(listener);
    assert(s && s->transport.tcp.state == TCP_SYN_RECEIVED && !s->open);
    assert(count == index + 1 && segment(index)->tcp_flags == (SYN | ACK));
    uint32_t ack = s->transport.tcp.snd_nxt;
    assert(s->transport.tcp.mss == 300 && ps_accept(listener, NULL) == -EAGAIN);
    input(sport, seq + 1, ack, ACK, NULL, 0);
    assert(s->transport.tcp.state == TCP_ESTABLISHED);
    struct ps_sockaddr peer;
    ps_fd_t fd = ps_accept(listener, &peer);
    assert(fd == s->fd && fd != listener && peer.ip_be == PEER && peer.port == sport);
    assert(ps_accept(listener, NULL) == -EAGAIN);
    return fd;
}

static void parsing_and_resets(void)
{
    reset();
    inject(packet(PEER, 1234, 9999, 10, 0, SYN, NULL, 0, 100, 0), DROP_TCP_NO_SOCKET);
    const struct rte_tcp_hdr *tcp = segment(0);
    assert(tcp->tcp_flags == (RST | ACK) && rte_be_to_cpu_32(tcp->recv_ack) == 11);
    inject(packet(PEER, 1234, 9999, 10, 555, ACK, NULL, 0, 100, 0), DROP_TCP_NO_SOCKET);
    assert(segment(1)->tcp_flags == RST && rte_be_to_cpu_32(segment(1)->sent_seq) == 555);
    inject(packet(PEER, 1234, 9999, 10, 0, RST, NULL, 0, 100, 0), DROP_TCP_NO_SOCKET);
    assert(count == 2);
    for (unsigned i = 0; i < 7; i++) {
        struct rte_mbuf *m = packet(PEER, 1234, 9000, 10, 0, SYN, NULL, 0, 100, i >= 5);
        struct rte_tcp_hdr *hdr = rte_pktmbuf_mtod_offset(m, struct rte_tcp_hdr *, 34);
        if (i == 0) hdr->data_off = 0x40;
        if (i == 1) hdr->data_off = 0xf0;
        if (i == 2) hdr->tcp_flags |= FIN;
        if (i == 3) hdr->tcp_flags |= RTE_TCP_URG_FLAG;
        if (i == 4) hdr->cksum ^= 1;
        if (i >= 5) {
            ((uint8_t *)(hdr + 1))[1] = i == 5 ? 0 : 3;
            hdr->cksum = 0;
            hdr->cksum = rte_ipv4_udptcp_cksum(rte_pktmbuf_mtod_offset(m, const struct rte_ipv4_hdr *, 14), hdr);
        }
        inject(m, i == 4 ? DROP_TCP_BAD_CHECKSUM : DROP_INVALID_TCP);
    }
    assert(count == 2 && !allocated());
}

static void handshake_and_data(void)
{
    reset();
    ps_fd_t listener = listen_on(9000, 2);
    input(1234, UINT32_MAX - 1, 0, SYN, NULL, 0);
    struct ps_socket_entry *s = child(listener);
    assert(s && s->transport.tcp.rcv_nxt == UINT32_MAX);
    uint32_t synack = s->transport.tcp.snd_nxt;
    uint64_t deadline = s->transport.tcp.deadline;
    tcp_tick(&rt, deadline - 1);
    assert(count == 1);
    tcp_tick(&rt, deadline);
    assert(count == 2 && rt.tcp_stats.retransmissions == 1);
    assert(segment(0)->sent_seq == segment(1)->sent_seq);
    input(1234, UINT32_MAX - 1, 0, SYN, NULL, 0);
    assert(allocated() == 2 && count == 3);
    input(1234, UINT32_MAX, synack, ACK, NULL, 0);
    ps_fd_t fd = ps_accept(listener, NULL);
    assert(fd == s->fd && fd != listener);
    ps_fd_t fd2 = establish(listener, 1235, 1000);
    assert(fd2 != fd && allocated() == 3);
    unsigned old = count;
    input(1234, UINT32_MAX, synack, ACK, "hello", 5);
    assert(s->transport.tcp.rcv_nxt == 4 && count == old + 1);
    assert(rte_be_to_cpu_32(segment(count - 1)->recv_ack) == 4);
    char data[16];
    assert(ps_recv(fd2, data, sizeof(data)) == -EAGAIN);
    assert(ps_recv(fd, data, 3) == 3 && !memcmp(data, "hel", 3));
    assert(ps_recv(fd, data, sizeof(data)) == 2 && !memcmp(data, "lo", 2));
    assert(ps_recv(fd, data, sizeof(data)) == -EAGAIN);
    inject(packet(PEER, 1234, 9000, UINT32_MAX, synack, ACK, "hello", 5, 8192, 0), DROP_TCP_OUT_OF_ORDER);
    inject(packet(PEER, 1234, 9000, 8, synack, ACK, "bad", 3, 8192, 0), DROP_TCP_OUT_OF_ORDER);
    assert(s->transport.tcp.rx_len == 0 && s->transport.tcp.rcv_nxt == 4);
    uint8_t payload[1000];
    memset(payload, 0xa5, sizeof(payload));
    assert(ps_send(fd, payload, sizeof(payload)) == sizeof(payload));
    assert(s->transport.tcp.flight_len == 300 && s->transport.tcp.tx_len == 1000);
    old = count;
    deadline = s->transport.tcp.deadline;
    tcp_tick(&rt, deadline);
    assert(count == old + 1 && rt.tcp_stats.retransmissions == 2);
    const struct rte_tcp_hdr *tcp = segment(count - 1);
    assert(rte_be_to_cpu_32(tcp->sent_seq) == synack && !memcmp((const uint8_t *)tcp + 20, payload, 300));
    input(1234, 4, synack, ACK, NULL, 0);
    assert(s->transport.tcp.tx_len == 1000 && rt.tcp_stats.duplicate_acks > 0);
    input(1234, 4, synack + 100, ACK, NULL, 0);
    assert(s->transport.tcp.flight_len == 200 && s->transport.tcp.tx_len == 900);
    input(1234, 4, synack + 300, ACK, NULL, 0);
    assert(s->transport.tcp.flight_len == 300 && s->transport.tcp.tx_len == 700);
    while (s->transport.tcp.tx_len) input(1234, 4, s->transport.tcp.snd_nxt, ACK, NULL, 0);
    assert(s->transport.tcp.snd_una == synack + 1000 && !s->transport.tcp.flight_flags);
    assert(ps_close(listener) == 0 && allocated() == 2);
    assert(ps_close(fd2) == 0 && ps_close(fd) == 0);
    assert(ps_send(fd, "x", 1) == -EBADF);
    tcp_tick(&rt, UINT64_MAX / 2);
    for (unsigned i = 0; i <= TCP_MAX_RETRIES; i++) tcp_tick(&rt, s->transport.tcp.deadline);
    reset();
}

static void close_and_timeouts(void)
{
    reset();
    ps_fd_t listener = listen_on(9000, 2);
    ps_fd_t fd = establish(listener, 1234, 10);
    struct ps_socket_entry *s = socket_lookup(&rt, fd);
    uint32_t ack = s->transport.tcp.snd_nxt;
    input(1234, 11, ack, FIN | ACK, NULL, 0);
    assert(s->transport.tcp.state == TCP_CLOSE_WAIT && s->transport.tcp.rcv_nxt == 12);
    char data[4];
    assert(ps_recv(fd, data, sizeof(data)) == 0);
    assert(ps_send(fd, "end", 3) == 3);
    assert(ps_close(fd) == 0 && !s->open && s->transport.tcp.state == TCP_CLOSE_WAIT);
    input(1234, 12, ack + 3, ACK, NULL, 0);
    assert(s->transport.tcp.state == TCP_LAST_ACK && segment(count - 1)->tcp_flags == (FIN | ACK));
    tcp_tick(&rt, s->transport.tcp.deadline);
    assert(segment(count - 1)->tcp_flags == (FIN | ACK));
    input(1234, 12, ack + 4, ACK, NULL, 0);
    assert(allocated() == 1 && !socket_lookup(&rt, fd));

    fd = establish(listener, 1235, 20);
    s = socket_lookup(&rt, fd);
    ack = s->transport.tcp.snd_nxt;
    assert(ps_close(fd) == 0 && s->transport.tcp.state == TCP_FIN_WAIT_1);
    input(1235, 21, ack + 1, ACK, NULL, 0);
    assert(s->transport.tcp.state == TCP_FIN_WAIT_2);
    input(1235, 21, ack + 1, FIN | ACK, NULL, 0);
    assert(s->transport.tcp.state == TCP_TIME_WAIT);
    uint64_t expires = s->transport.tcp.expires;
    input(1235, 21, ack + 1, FIN | ACK, NULL, 0);
    assert(s->transport.tcp.state == TCP_TIME_WAIT && s->transport.tcp.expires >= expires);
    tcp_tick(&rt, s->transport.tcp.expires - 1);
    assert(socket_lookup(&rt, fd));
    tcp_tick(&rt, s->transport.tcp.expires);
    assert(!socket_lookup(&rt, fd));

    fd = establish(listener, 1236, 30);
    s = socket_lookup(&rt, fd);
    ack = s->transport.tcp.snd_nxt;
    assert(ps_close(fd) == 0);
    input(1236, 31, ack, FIN | ACK, NULL, 0);
    assert(s->transport.tcp.state == TCP_FIN_WAIT_1 && s->transport.tcp.peer_fin);
    input(1236, 32, ack + 1, ACK, NULL, 0);
    assert(s->transport.tcp.state == TCP_TIME_WAIT);
    tcp_tick(&rt, s->transport.tcp.expires);

    input(1237, 40, 0, SYN, NULL, 0);
    s = child(listener);
    for (unsigned i = 0; i <= TCP_MAX_RETRIES; i++) tcp_tick(&rt, s->transport.tcp.deadline);
    assert(!child(listener) && rt.tcp_stats.timeouts == 1);
    assert(ps_close(listener) == 0 && !allocated());
    assert(rte_mempool_avail_count(rt.mbuf_pool) == POOL_SIZE);
}

static void active_and_windows(void)
{
    reset();
    ps_fd_t fd = ps_socket(PS_AF_INET, PS_SOCK_STREAM, 0);
    struct ps_sockaddr dst = { .ip_be = PEER, .port = 1234 };
    assert(ps_connect(fd, &dst) == -EINPROGRESS && ps_connect(fd, &dst) == -EALREADY);
    struct ps_socket_entry *s = socket_lookup(&rt, fd);
    uint32_t ack = s->transport.tcp.snd_nxt;
    uint16_t port = s->local.port;
    assert(segment(0)->tcp_flags == SYN && s->transport.tcp.state == TCP_SYN_SENT);
    inject(packet(PEER, 1234, port, 100, ack, SYN | ACK, NULL, 0, 0, 1), DROP_NONE);
    assert(ps_connect(fd, &dst) == -EISCONN && s->transport.tcp.state == TCP_ESTABLISHED);
    assert(ps_send(fd, "hello", 5) == 5 && !s->transport.tcp.flight_flags);
    unsigned old = count;
    tcp_tick(&rt, s->transport.tcp.deadline);
    assert(count == old + 1 && rte_be_to_cpu_32(segment(count - 1)->sent_seq) == ack - 1);
    inject(packet(PEER, 1234, port, 101, ack, ACK, NULL, 0, 2, 0), DROP_NONE);
    assert(s->transport.tcp.flight_len == 2);
    inject(packet(PEER, 1234, port, 101, ack + 2, ACK, NULL, 0, 100, 0), DROP_NONE);
    assert(s->transport.tcp.flight_len == 3);
    inject(packet(PEER, 1234, port, 101, ack + 5, ACK, NULL, 0, 100, 0), DROP_NONE);
    assert(!s->transport.tcp.tx_len);
    inject(packet(PEER, 1234, port, 101, ack + 5, RST | ACK, NULL, 0, 100, 0), DROP_NONE);
    assert(ps_recv(fd, &old, 1) == -ECONNRESET && ps_send(fd, "x", 1) == -ECONNRESET);
    assert(ps_close(fd) == 0 && !allocated());
    fd = ps_socket(PS_AF_INET, PS_SOCK_STREAM, 0);
    assert(ps_connect(fd, &dst) == -EINPROGRESS);
    s = socket_lookup(&rt, fd);
    inject(packet(PEER, 1234, s->local.port, 0, s->transport.tcp.snd_nxt, RST | ACK, NULL, 0, 100, 0), DROP_NONE);
    assert(ps_send(fd, "x", 1) == -ECONNREFUSED);
    assert(ps_close(fd) == 0);
    reset();
}

static void capacity_and_failure_tests(void)
{
    reset();
    ps_fd_t listener = listen_on(9000, 1);
    input(1234, 10, 0, SYN, NULL, 0);
    inject(packet(PEER, 1235, 9000, 20, 0, SYN, NULL, 0, 100, 0), DROP_TCP_BACKLOG_FULL);
    assert(allocated() == 2 && ps_close(listener) == 0 && !allocated());

    reset();
    listener = listen_on(9000, 2);
    ps_fd_t fd = establish(listener, 1234, 10);
    struct ps_socket_entry *s = socket_lookup(&rt, fd);
    uint32_t ack = s->transport.tcp.snd_nxt;
    uint8_t bytes[TCP_BUFFER_SIZE];
    memset(bytes, 0x5a, sizeof(bytes));
    unsigned received = 0;
    while (received < sizeof(bytes)) {
        unsigned n = RTE_MIN(1460, sizeof(bytes) - received);
        input(1234, 11 + received, ack, ACK, bytes, n);
        received += n;
    }
    assert(s->transport.tcp.rx_len == TCP_BUFFER_SIZE && segment(count - 1)->rx_win == 0);
    uint32_t seq = s->transport.tcp.rcv_nxt;
    input(1234, seq, ack, FIN | ACK, NULL, 0);
    assert(!s->transport.tcp.peer_fin && s->transport.tcp.rcv_nxt == seq);
    assert(ps_recv(fd, bytes, 1) == 1 && rte_be_to_cpu_16(segment(count - 1)->rx_win) == 1);
    input(1234, seq, ack, FIN | ACK, NULL, 0);
    assert(s->transport.tcp.peer_fin && s->transport.tcp.rcv_nxt == seq + 1);
    assert(ps_recv(fd, bytes, sizeof(bytes)) == TCP_BUFFER_SIZE - 1);
    assert(ps_recv(fd, bytes, 1) == 0);
    assert(ps_close(fd) == 0);
    input(1234, seq + 1, ack + 1, ACK, NULL, 0);
    assert(allocated() == 1);

    fd = establish(listener, 1235, 100);
    s = socket_lookup(&rt, fd);
    ack = s->transport.tcp.snd_nxt;
    assert(ps_send(fd, bytes, sizeof(bytes)) == sizeof(bytes));
    assert(ps_send(fd, bytes, 1) == -EAGAIN);
    inject(packet(PEER, 1235, 9000, 101, s->transport.tcp.snd_nxt + 1, ACK, NULL, 0, 100, 0), DROP_TCP_INVALID_STATE);
    assert(s->transport.tcp.tx_len == TCP_BUFFER_SIZE && s->transport.tcp.snd_una == ack);
    inject(packet(PEER, 1235, 9000, 102, 0, RST, NULL, 0, 100, 0), DROP_TCP_OUT_OF_ORDER);
    assert(!s->error && s->transport.tcp.state == TCP_ESTABLISHED);
    assert(ps_close(fd) == 0);
    for (unsigned i = 0; i <= TCP_MAX_RETRIES; i++) tcp_tick(&rt, s->transport.tcp.deadline);
    assert(!socket_lookup(&rt, fd) && rt.tcp_stats.timeouts == 1);
    assert(ps_close(listener) == 0 && !allocated());

    reset();
    listener = listen_on(9000, 1);
    fd = establish(listener, 1234, 10);
    s = socket_lookup(&rt, fd);
    ack = s->transport.tcp.snd_nxt;
    rt.ports[0].mtu = 100;
    assert(ps_send(fd, bytes, 200) == 200 && s->transport.tcp.flight_len == 60);
    assert(rte_be_to_cpu_16(((const struct rte_ipv4_hdr *)(wire[count - 1].data + 14))->total_length) == 100);
    while (s->transport.tcp.tx_len) input(1234, 11, s->transport.tcp.snd_nxt, ACK, NULL, 0);
    struct rte_mbuf *held[POOL_SIZE];
    for (unsigned i = 0; i < POOL_SIZE; i++) { held[i] = rte_pktmbuf_alloc(rt.mbuf_pool); assert(held[i]); }
    unsigned old = count;
    assert(ps_send(fd, bytes, 10) == 10 && count == old && rt.tcp_stats.output_failed == 1);
    for (unsigned i = 0; i < POOL_SIZE; i++) rte_pktmbuf_free(held[i]);
    tcp_tick(&rt, s->transport.tcp.deadline);
    assert(count == old + 1 && rte_be_to_cpu_32(segment(count - 1)->sent_seq) == ack + 200);
    input(1234, 11, s->transport.tcp.snd_nxt, ACK, NULL, 0);
    for (unsigned i = 0; i < GRAPH_FRAME_POOL_SIZE; i++) rt.graph.slots[i].used = 1;
    old = count;
    assert(ps_send(fd, bytes, 10) == 10 && count == old && rt.tcp_stats.output_failed == 2);
    assert(rt.graph.drop_reasons[DROP_GRAPH_FULL] == 1);
    for (unsigned i = 0; i < GRAPH_FRAME_POOL_SIZE; i++) rt.graph.slots[i].used = 0;
    tcp_tick(&rt, s->transport.tcp.deadline);
    assert(count == old + 1);
    input(1234, 11, s->transport.tcp.snd_nxt, ACK, NULL, 0);
    tx_limit = 0;
    assert(ps_send(fd, bytes, 10) == 10 && rt.graph.drop_reasons[DROP_TX_FAILED] == 1);
    tx_limit = UINT16_MAX;
    tcp_tick(&rt, s->transport.tcp.deadline);
    input(1234, 11, s->transport.tcp.snd_nxt, ACK, NULL, 0);
    rt.routes.count = 0;
    assert(ps_send(fd, bytes, 1) == -ENETUNREACH);
    assert(ps_close(fd) == 0);

    reset();
    memset(&rt.neighbours, 0, sizeof(rt.neighbours));
    fd = ps_socket(PS_AF_INET, PS_SOCK_STREAM, 0);
    assert(ps_connect(fd, &(struct ps_sockaddr){ .ip_be = PEER, .port = 1234 }) == -EINPROGRESS);
    assert(rte_mempool_avail_count(rt.mbuf_pool) == POOL_SIZE - 1);
    assert(ps_close(fd) == 0 && !allocated());
    assert(rte_mempool_avail_count(rt.mbuf_pool) == POOL_SIZE && rt.graph.drop_reasons[DROP_NEIGHBOUR_CANCELLED] == 1);
    reset();
    listener = listen_on(9000, 1);
    assert(route_add_gateway(&rt.routes, OTHER, 24, rt.ports[0].id, PEER) == 0);
    inject(packet(OTHER, 1234, 9000, 123, 0, SYN, NULL, 0, 100, 0), DROP_NONE);
    const struct rte_ipv4_hdr *ip = (const struct rte_ipv4_hdr *)(wire[0].data + 14);
    assert(ip->dst_addr == OTHER && segment(0)->tcp_flags == (SYN | ACK));
    assert(rte_is_same_ether_addr(&((const struct rte_ether_hdr *)wire[0].data)->dst_addr, &peer_mac));
    assert(ps_close(listener) == 0 && !allocated());
    reset();
}

static void lifetime_tests(void)
{
    reset();
    ps_fd_t listener = listen_on(9000, 1);
    ps_fd_t fd = establish(listener, 1234, 10);
    struct ps_socket_entry *s = socket_lookup(&rt, fd);
    uint32_t ack = s->transport.tcp.snd_nxt;
    assert(ps_close(listener) == 0 && allocated() == 1);
    assert(ps_close(fd) == 0);
    input(1234, 11, ack + 1, FIN | ACK, NULL, 0);
    assert(s->transport.tcp.state == TCP_TIME_WAIT);
    ps_fd_t next = ps_socket(PS_AF_INET, PS_SOCK_STREAM, 0);
    assert(ps_bind(next, &(struct ps_sockaddr){ .port = 9000 }) == -EADDRINUSE);
    tcp_tick(&rt, s->transport.tcp.expires);
    assert(!socket_lookup(&rt, fd));
    assert(ps_bind(next, &(struct ps_sockaddr){ .port = 9000 }) == 0);
    assert(ps_listen(next, 1) == 0);
    fd = establish(next, 1235, 20);
    s = socket_lookup(&rt, fd);
    ack = s->transport.tcp.snd_nxt;
    assert(ps_close(fd) == 0);
    input(1235, 21, ack + 1, ACK, NULL, 0);
    assert(s->transport.tcp.state == TCP_FIN_WAIT_2);
    tcp_tick(&rt, s->transport.tcp.expires);
    assert(!socket_lookup(&rt, fd) && ps_close(next) == 0 && !allocated());
    fd = ps_socket(PS_AF_INET, PS_SOCK_STREAM, 0);
    assert(ps_connect(fd, &(struct ps_sockaddr){ .ip_be = PEER, .port = 1234 }) == -EINPROGRESS);
    s = socket_lookup(&rt, fd);
    for (unsigned i = 0; i <= TCP_MAX_RETRIES; i++) tcp_tick(&rt, s->transport.tcp.deadline);
    char byte;
    assert(ps_recv(fd, &byte, 1) == -ETIMEDOUT);
    assert(ps_close(fd) == 0 && !allocated());
    reset();
    listener = listen_on(9000, 1);
    fd = establish(listener, 1234, 10);
    input(1234, 11, 0, RST, NULL, 0);
    assert(ps_recv(fd, &byte, 1) == -ECONNRESET);
    memset(&rt.neighbours, 0, sizeof(rt.neighbours));
    struct node_frame frame = { .count = 1 };
    frame.pkts[0] = packet(PEER, 1234, 9000, 20, 0, SYN, NULL, 0, 100, 0);
    frame.ctxs[0].ingress_port_id = rt.ports[0].port_id;
    assert(graph_submit(&rt, NODE_ETH_INPUT, &frame) == 0);
    assert(child(listener) && rte_mempool_avail_count(rt.mbuf_pool) == POOL_SIZE - 1);
    assert(ps_close(fd) == 0 && rte_mempool_avail_count(rt.mbuf_pool) == POOL_SIZE - 1);
    reset();
}

int main(void)
{
    cpu_set_t cpus;
    assert(sched_getaffinity(0, sizeof(cpus), &cpus) == 0);
    unsigned cpu;
    for (cpu = 0; cpu < CPU_SETSIZE; cpu++) if (CPU_ISSET(cpu, &cpus)) break;
    char core[32];
    snprintf(core, sizeof(core), "0@%u", cpu);
    char *args[] = {"test-tcp", "--lcores", core, "--no-huge", "--no-pci", "--no-shconf", "--no-telemetry", "--vdev=net_null0", NULL};
    assert(rte_eal_init(8, args) >= 0);
    rt.mbuf_pool = rte_pktmbuf_pool_create("tcp_pool", POOL_SIZE, 0, 0, RTE_MBUF_DEFAULT_BUF_SIZE, rte_socket_id());
    assert(rt.mbuf_pool);
    rt.port_count = 1;
    struct port_state *p = &rt.ports[0];
    assert(rte_eth_dev_get_port_by_name("net_null0", &p->port_id) == 0);
    p->id = 11;
    p->ip_be = rte_cpu_to_be_32(RTE_IPV4(192u, 0, 2, 2));
    p->prefix_len = 24;
    p->mac = (struct rte_ether_addr){{2, 0, 0, 0, 0, 2}};
    struct rte_eth_conf conf = {0};
    assert(rte_eth_dev_configure(p->port_id, 1, 1, &conf) == 0);
    assert(rte_eth_rx_queue_setup(p->port_id, 0, 128, rte_socket_id(), NULL, rt.mbuf_pool) == 0);
    assert(rte_eth_tx_queue_setup(p->port_id, 0, 128, rte_socket_id(), NULL) == 0);
    assert(rte_eth_dev_start(p->port_id) == 0);
    p->configured = p->started = 1;
    const struct rte_eth_rxtx_callback *cb = rte_eth_add_tx_callback(p->port_id, 0, capture, NULL);
    assert(cb);
    parsing_and_resets();
    handshake_and_data();
    close_and_timeouts();
    active_and_windows();
    capacity_and_failure_tests();
    lifetime_tests();
    reset();
    socket_subsystem_fini(&rt);
    assert(rte_eth_remove_tx_callback(p->port_id, 0, cb) == 0);
    rte_free((void *)cb);
    rte_eth_dev_stop(p->port_id);
    rte_eth_dev_close(p->port_id);
    assert(rte_mempool_avail_count(rt.mbuf_pool) == POOL_SIZE);
    rte_mempool_free(rt.mbuf_pool);
    assert(rte_eal_cleanup() == 0);
    puts("TCP parsing, tuples, handshake, stream, ACKs, retransmission, resets, windows, close and ownership passed");
    return 0;
}
