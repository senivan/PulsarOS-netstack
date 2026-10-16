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
#include <rte_udp.h>
#include "runtime.h"

#define POOL_SIZE 511
#define A rte_cpu_to_be_32(RTE_IPV4(192u, 0, 2, 1))
#define B rte_cpu_to_be_32(RTE_IPV4(198u, 51, 100, 1))
#define REMOTE rte_cpu_to_be_32(RTE_IPV4(203u, 0, 113, 1))

static struct app_runtime rt;
static const struct rte_ether_addr peers[2] = {{{2, 0, 0, 0, 0, 1}}, {{2, 0, 0, 0, 1, 1}}};
static struct { uint16_t port, length; _Alignas(8) uint8_t data[1600]; } captures[128];
static unsigned capture_count;
static uint16_t tx_limit = UINT16_MAX;

static uint16_t capture(uint16_t port, uint16_t queue, struct rte_mbuf **packets,
                        uint16_t count, void *arg)
{
    (void)queue; (void)arg;
    uint16_t sent = RTE_MIN(count, tx_limit);
    for (unsigned i = 0; i < sent; i++) {
        assert(capture_count < RTE_DIM(captures));
        assert(rte_pktmbuf_pkt_len(packets[i]) <= sizeof(captures[0].data));
        captures[capture_count].port = port;
        captures[capture_count].length = rte_pktmbuf_pkt_len(packets[i]);
        memcpy(captures[capture_count++].data, rte_pktmbuf_mtod(packets[i], const void *), rte_pktmbuf_pkt_len(packets[i]));
        assert(!packets[i]->ol_flags && !packets[i]->tx_offload);
    }
    return sent;
}

static void reset(void)
{
    neighbour_fini(&rt);
    assert(rte_mempool_avail_count(rt.mbuf_pool) == POOL_SIZE);
    memset(&rt.neighbours, 0, sizeof(rt.neighbours));
    memset(&rt.icmp_errors, 0, sizeof(rt.icmp_errors));
    socket_subsystem_fini(&rt);
    assert(socket_subsystem_init(&rt) == 0);
    assert(route_init_connected(&rt) == 0 && graph_init(&rt) == 0);
    assert(neighbour_learn(&rt.neighbours, rt.ports[0].id, A, &peers[0]) == 0);
    assert(neighbour_learn(&rt.neighbours, rt.ports[1].id, B, &peers[1]) == 0);
    capture_count = 0;
    tx_limit = UINT16_MAX;
}

static struct rte_ipv4_hdr *header(struct rte_mbuf *m)
{
    return rte_pktmbuf_mtod_offset(m, struct rte_ipv4_hdr *, 14);
}

static void checksum(struct rte_mbuf *m)
{
    struct rte_ipv4_hdr *ip = header(m);
    ip->hdr_checksum = 0;
    ip->hdr_checksum = rte_ipv4_cksum(ip);
}

static struct rte_mbuf *packet(uint32_t source, uint32_t destination, uint8_t ttl,
                               uint8_t protocol, uint16_t length)
{
    struct rte_mbuf *m = rte_pktmbuf_alloc(rt.mbuf_pool);
    assert(m && length >= 20);
    struct rte_ether_hdr *eth = (struct rte_ether_hdr *)rte_pktmbuf_append(m, 14 + length);
    assert(eth);
    memset(eth, 0, 14 + length);
    eth->src_addr = peers[0];
    eth->dst_addr = rt.ports[0].mac;
    eth->ether_type = rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV4);
    struct rte_ipv4_hdr *ip = header(m);
    ip->version_ihl = 0x45;
    ip->type_of_service = 0xab;
    ip->packet_id = rte_cpu_to_be_16(1234);
    ip->total_length = rte_cpu_to_be_16(length);
    ip->fragment_offset = rte_cpu_to_be_16(RTE_IPV4_HDR_DF_FLAG);
    ip->src_addr = source;
    ip->dst_addr = destination;
    ip->time_to_live = ttl;
    ip->next_proto_id = protocol;
    for (unsigned i = 20; i < length; i++) ((uint8_t *)ip)[i] = (uint8_t)i;
    checksum(m);
    return m;
}

static uint16_t sum(const void *data, unsigned length)
{
    const uint8_t *bytes = data;
    uint32_t result = 0;
    for (unsigned i = 0; i < length; i += 2)
        result += (uint16_t)bytes[i] << 8 | (i + 1 < length ? bytes[i + 1] : 0);
    while (result >> 16) result = (result & 0xffff) + (result >> 16);
    return (uint16_t)result;
}

static void error(struct rte_mbuf *m, uint8_t type, uint8_t code, uint16_t mtu, uint64_t now)
{
    struct packet_ctx ctx = { .ingress_port_id = rt.ports[0].port_id, .l3_offset = 14, .l4_offset = 34 };
    icmp_send_error(&rt, m, &ctx, type, code, mtu, now);
}

static void check_error(unsigned index, uint16_t port, uint32_t destination,
                        uint8_t type, uint8_t code, uint16_t mtu,
                        const void *quote, unsigned quote_length)
{
    assert(index < capture_count && captures[index].port == port);
    const struct rte_ipv4_hdr *ip = (const struct rte_ipv4_hdr *)(captures[index].data + 14);
    const uint8_t *icmp = (const uint8_t *)(ip + 1);
    struct rte_ipv4_hdr original;
    memcpy(&original, quote, sizeof(original));
    uint32_t source = netif_is_local_ip(&rt, original.dst_addr) ?
                      original.dst_addr : netif_by_dpdk_port(&rt, port)->ip_be;
    assert(ip->src_addr == source && ip->dst_addr == destination);
    assert(ip->time_to_live == 64 && ip->next_proto_id == IPPROTO_ICMP);
    assert(sum(ip, 20) == UINT16_MAX && sum(icmp, 8 + quote_length) == UINT16_MAX);
    assert(rte_be_to_cpu_16(ip->total_length) == 28 + quote_length);
    assert(icmp[0] == type && icmp[1] == code && !icmp[4] && !icmp[5]);
    assert(((uint16_t)icmp[6] << 8 | icmp[7]) == mtu);
    assert(!memcmp(icmp + 8, quote, quote_length));
}

static void error_tests(void)
{
    const uint8_t types[] = {11, 3, 3, 3}, codes[] = {0, 0, 1, 4};
    uint64_t now = rte_get_timer_cycles();
    for (unsigned i = 0; i < RTE_DIM(types); i++) {
        reset();
        struct rte_mbuf *m = packet(A, B, 1, IPPROTO_UDP, 101);
        error(m, types[i], codes[i], codes[i] == 4 ? 1200 : 0, now);
        check_error(0, rt.ports[0].port_id, A, types[i], codes[i], codes[i] == 4 ? 1200 : 0, header(m), 101);
        assert(rt.icmp_errors.generated == 1);
        rte_pktmbuf_free(m);
        assert(rte_mempool_avail_count(rt.mbuf_pool) == POOL_SIZE);
    }
    /* RFC 1812 4.3.2.3: quote up to a 576-byte datagram or return MTU. */
    reset();
    struct rte_mbuf *m = packet(A, B, 1, IPPROTO_UDP, 1400);
    error(m, 11, 0, 0, now);
    check_error(0, rt.ports[0].port_id, A, 11, 0, 0, header(m), 548);
    rt.ports[0].mtu = 100;
    error(m, 11, 0, 0, now);
    check_error(1, rt.ports[0].port_id, A, 11, 0, 0, header(m), 72);
    rt.ports[0].mtu = 47;
    error(m, 11, 0, 0, now);
    assert(rt.icmp_errors.failed == 1 && capture_count == 2);
    rt.ports[0].mtu = 1500;
    rte_pktmbuf_free(m);

    reset();
    assert(route_add_gateway(&rt.routes, REMOTE, 24, rt.ports[1].id, B) == 0);
    m = packet(REMOTE, A, 1, IPPROTO_UDP, 28);
    error(m, 11, 0, 0, now);
    check_error(0, rt.ports[1].port_id, REMOTE, 11, 0, 0, header(m), 28);
    assert(rte_is_same_ether_addr(&((const struct rte_ether_hdr *)captures[0].data)->dst_addr, &peers[1]));
    rte_pktmbuf_free(m);

    reset();
    memset(&rt.neighbours, 0, sizeof(rt.neighbours));
    m = packet(A, B, 1, IPPROTO_UDP, 28);
    error(m, 11, 0, 0, now);
    assert(capture_count == 1 && rt.icmp_errors.generated == 1);
    const struct rte_arp_hdr *arp = (const struct rte_arp_hdr *)(captures[0].data + 14);
    assert(arp->arp_data.arp_tip == A && arp->arp_data.arp_sip == rt.ports[0].ip_be);
    assert(neighbour_update(&rt, rt.ports[0].id, A, &peers[0]) == 0);
    check_error(1, rt.ports[0].port_id, A, 11, 0, 0, header(m), 28);
    rte_pktmbuf_free(m);

    /* RFC 1812 4.3.2.7: suppress responses to error and nonunicast traffic. */
    reset();
    const uint8_t error_types[] = {3, 4, 5, 11, 12};
    for (unsigned i = 0; i < RTE_DIM(error_types); i++) {
        m = packet(A, B, 1, IPPROTO_ICMP, 28);
        ((uint8_t *)(header(m) + 1))[0] = error_types[i];
        error(m, 11, 0, 0, now);
        rte_pktmbuf_free(m);
    }
    const uint32_t invalid[] = {0, rte_cpu_to_be_32(0x7f000001), rte_cpu_to_be_32(0xe0000001),
        rte_cpu_to_be_32(0xffffffff), rte_cpu_to_be_32(0xc00002ff), rt.ports[0].ip_be};
    for (unsigned i = 0; i < RTE_DIM(invalid); i++) {
        m = packet(invalid[i], B, 1, IPPROTO_UDP, 28);
        error(m, 11, 0, 0, now);
        rte_pktmbuf_free(m);
    }
    m = packet(A, B, 1, IPPROTO_UDP, 28);
    header(m)->fragment_offset = rte_cpu_to_be_16(1);
    checksum(m);
    error(m, 11, 0, 0, now);
    rte_pktmbuf_free(m);
    m = packet(A, rte_cpu_to_be_32(0xc00002ff), 1, IPPROTO_UDP, 28);
    error(m, 11, 0, 0, now);
    rte_pktmbuf_free(m);
    m = packet(A, B, 1, IPPROTO_UDP, 28);
    memset(&rte_pktmbuf_mtod(m, struct rte_ether_hdr *)->dst_addr, 255, 6);
    error(m, 11, 0, 0, now);
    rte_pktmbuf_free(m);
    assert(!capture_count && rt.icmp_errors.suppressed == 14);

    reset();
    m = packet(A, B, 1, IPPROTO_UDP, 28);
    for (unsigned i = 0; i <= ICMP_ERROR_BURST; i++) error(m, 11, 0, 0, now);
    assert(capture_count == ICMP_ERROR_BURST && rt.icmp_errors.rate_limited == 1);
    error(m, 11, 0, 0, now + rte_get_timer_hz() / ICMP_ERROR_RATE);
    assert(capture_count == ICMP_ERROR_BURST + 1);
    rte_pktmbuf_free(m);

    reset();
    m = packet(A, B, 1, IPPROTO_UDP, 28);
    rt.routes.count = 0;
    error(m, 11, 0, 0, now);
    assert(rt.icmp_errors.failed == 1 && !capture_count && !rt.graph.drop_reasons[DROP_NO_ROUTE]);
    assert(route_init_connected(&rt) == 0);
    struct rte_mbuf *held[POOL_SIZE];
    unsigned count = 0;
    while ((held[count] = rte_pktmbuf_alloc(rt.mbuf_pool))) count++;
    error(m, 11, 0, 0, now);
    assert(rt.icmp_errors.failed == 2);
    for (unsigned i = 0; i < count; i++) rte_pktmbuf_free(held[i]);
    for (unsigned i = 0; i < GRAPH_FRAME_POOL_SIZE; i++) rt.graph.slots[i].used = 1;
    error(m, 11, 0, 0, now);
    assert(rt.icmp_errors.failed == 3 && rt.graph.drop_reasons[DROP_GRAPH_FULL] == 1);
    for (unsigned i = 0; i < GRAPH_FRAME_POOL_SIZE; i++) rt.graph.slots[i].used = 0;
    tx_limit = 0;
    error(m, 11, 0, 0, now);
    assert(rt.icmp_errors.generated == 1 && rt.graph.drop_reasons[DROP_TX_FAILED] == 1);
    rte_pktmbuf_free(m);
    reset();
}

static void submit(struct rte_mbuf *m, unsigned ingress, enum drop_reason reason)
{
    struct rte_ether_hdr *eth = rte_pktmbuf_mtod(m, struct rte_ether_hdr *);
    eth->src_addr = peers[ingress];
    eth->dst_addr = rt.ports[ingress].mac;
    struct node_frame frame = { .count = 1 };
    frame.pkts[0] = m;
    frame.ctxs[0].ingress_port_id = rt.ports[ingress].port_id;
    uint64_t before = rt.graph.drop_reasons[reason];
    assert(graph_submit(&rt, NODE_ETH_INPUT, &frame) == 0);
    assert(rt.graph.drop_reasons[reason] == before + (reason != DROP_NONE));
}

static struct pending_neighbour *pending(unsigned netif, uint32_t ip_be)
{
    for (unsigned i = 0; i < NEIGHBOUR_PENDING_MAX; i++) {
        struct pending_neighbour *entry = &rt.pending_neighbours.entries[i];
        if (entry->count && entry->netif_id == rt.ports[netif].id && entry->ip_be == ip_be) return entry;
    }
    return NULL;
}

static void arp_reply(unsigned ingress, uint32_t ip_be)
{
    struct rte_mbuf *m = rte_pktmbuf_alloc(rt.mbuf_pool);
    assert(m);
    struct rte_ether_hdr *eth = (struct rte_ether_hdr *)rte_pktmbuf_append(m, 42);
    assert(eth);
    memset(eth, 0, 42);
    eth->ether_type = rte_cpu_to_be_16(RTE_ETHER_TYPE_ARP);
    struct rte_arp_hdr *arp = (struct rte_arp_hdr *)(eth + 1);
    arp->arp_hardware = rte_cpu_to_be_16(RTE_ARP_HRD_ETHER);
    arp->arp_protocol = rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV4);
    arp->arp_hlen = 6;
    arp->arp_plen = 4;
    arp->arp_opcode = rte_cpu_to_be_16(RTE_ARP_OP_REPLY);
    arp->arp_data.arp_sha = peers[ingress];
    arp->arp_data.arp_sip = ip_be;
    arp->arp_data.arp_tha = rt.ports[ingress].mac;
    arp->arp_data.arp_tip = rt.ports[ingress].ip_be;
    submit(m, ingress, DROP_NONE);
}

static struct rte_mbuf *udp_packet(uint32_t source, uint32_t destination,
                                   uint16_t port, uint16_t length, int with_checksum)
{
    struct rte_mbuf *m = packet(source, destination, 1, IPPROTO_UDP, length);
    struct rte_udp_hdr *udp = (struct rte_udp_hdr *)(header(m) + 1);
    udp->src_port = rte_cpu_to_be_16(50001);
    udp->dst_port = rte_cpu_to_be_16(port);
    udp->dgram_len = rte_cpu_to_be_16(length - 20);
    udp->dgram_cksum = 0;
    if (with_checksum) udp->dgram_cksum = rte_ipv4_udptcp_cksum(header(m), udp);
    return m;
}

static void udp_error_tests(void)
{
    const uint16_t lengths[] = {28, 41, 1500};
    for (unsigned local = 0; local < 2; local++) {
        for (unsigned i = 0; i < RTE_DIM(lengths); i++) for (int ck = 0; ck <= 1; ck++) {
            reset();
            struct rte_mbuf *m = udp_packet(A, rt.ports[local].ip_be, 9999, lengths[i], ck);
            uint8_t quote[548];
            unsigned length = RTE_MIN(lengths[i], sizeof(quote));
            memcpy(quote, header(m), length);
            memset(rte_pktmbuf_append(m, 16), 0xa5, 16);
            submit(m, 0, DROP_UDP_UNBOUND_PORT);
            assert(capture_count == 1 && rt.icmp_errors.generated == 1);
            check_error(0, rt.ports[0].port_id, A, 3, 3, 0, quote, length);
            assert(!rt.graph.nodes[NODE_UDP_INPUT].stats.errors);
            assert(rte_mempool_avail_count(rt.mbuf_pool) == POOL_SIZE);
        }
    }
    reset();
    ps_fd_t udp_fd = ps_socket(PS_AF_INET, PS_SOCK_DGRAM, 0);
    assert(udp_fd >= 0 && ps_bind(udp_fd, &(struct ps_sockaddr){ .port = 9000 }) == 0);
    for (unsigned i = 0; i <= PS_DGRAM_QUEUE_SIZE; i++)
        submit(udp_packet(A, rt.ports[0].ip_be, 9000, 41, 1), 0,
               i == PS_DGRAM_QUEUE_SIZE ? DROP_UDP_RX_QUEUE_FULL : DROP_NONE);
    uint8_t received[13];
    struct ps_sockaddr source;
    for (unsigned i = 0; i < PS_DGRAM_QUEUE_SIZE; i++) {
        assert(ps_recvfrom(udp_fd, received, sizeof(received), &source) == (ssize_t)sizeof(received));
        assert(source.ip_be == A && source.port == 50001);
        for (unsigned j = 0; j < sizeof(received); j++) assert(received[j] == 28 + j);
    }
    assert(ps_recvfrom(udp_fd, received, sizeof(received), &source) == -EAGAIN);
    assert(!capture_count && !rt.icmp_errors.generated);

    reset();
    const enum drop_reason malformed[] = {DROP_INVALID_UDP, DROP_UDP_BAD_LENGTH,
        DROP_UDP_BAD_LENGTH, DROP_UDP_BAD_CHECKSUM};
    for (unsigned i = 0; i < RTE_DIM(malformed); i++) {
        struct rte_mbuf *m = udp_packet(A, rt.ports[0].ip_be, 9999, 41, 1);
        struct rte_udp_hdr *udp = (struct rte_udp_hdr *)(header(m) + 1);
        if (i == 0) {
            rte_pktmbuf_trim(m, 14);
            header(m)->total_length = rte_cpu_to_be_16(27);
            checksum(m);
        } else if (i < 3) udp->dgram_len = rte_cpu_to_be_16(i == 1 ? 7 : 22);
        else ((uint8_t *)(udp + 1))[0] ^= 1;
        submit(m, 0, malformed[i]);
    }
    assert(!capture_count && !rt.icmp_errors.generated && !rt.graph.drop_reasons[DROP_UDP_UNBOUND_PORT]);

    reset();
    submit(udp_packet(rte_cpu_to_be_32(RTE_IPV4(198u, 51, 100, 255)), rt.ports[0].ip_be, 9999, 28, 1),
           0, DROP_UDP_UNBOUND_PORT);
    assert(rt.icmp_errors.suppressed == 1 && !capture_count);
    struct rte_mbuf *m = udp_packet(A, rt.ports[0].ip_be, 9999, 28, 1);
    memset(&rte_pktmbuf_mtod(m, struct rte_ether_hdr *)->dst_addr, 255, 6);
    struct node_frame frame = { .count = 1 };
    frame.pkts[0] = m;
    frame.ctxs[0] = (struct packet_ctx){ .ingress_port_id = rt.ports[0].port_id, .l3_offset = 14, .l4_offset = 34 };
    assert(graph_submit(&rt, NODE_UDP_INPUT, &frame) == 0);
    assert(rt.icmp_errors.suppressed == 2 && !capture_count);
    submit(udp_packet(A, rte_cpu_to_be_32(0xe0000001), 9999, 28, 1), 0, DROP_FORWARDING_DISABLED);
    submit(udp_packet(0, rt.ports[0].ip_be, 9999, 28, 1), 0, DROP_INVALID_SOURCE);
    m = udp_packet(A, rt.ports[0].ip_be, 9999, 28, 1);
    header(m)->fragment_offset = rte_cpu_to_be_16(1);
    checksum(m);
    submit(m, 0, DROP_IPV4_FRAGMENT);
    assert(!capture_count && !rt.icmp_errors.generated);

    reset();
    rt.icmp_errors.initialized = 1;
    rt.icmp_errors.last_refill = rte_get_timer_cycles();
    submit(udp_packet(A, rt.ports[0].ip_be, 9999, 28, 1), 0, DROP_UDP_UNBOUND_PORT);
    assert(rt.icmp_errors.rate_limited == 1 && !capture_count);

    reset();
    assert(route_add_gateway(&rt.routes, REMOTE, 24, rt.ports[1].id, B) == 0);
    m = udp_packet(REMOTE, rt.ports[0].ip_be, 9999, 41, 1);
    uint8_t quote[41];
    memcpy(quote, header(m), sizeof(quote));
    submit(m, 0, DROP_UDP_UNBOUND_PORT);
    check_error(0, rt.ports[1].port_id, REMOTE, 3, 3, 0, quote, sizeof(quote));
    const struct rte_ether_hdr *eth = (const struct rte_ether_hdr *)captures[0].data;
    assert(rte_is_same_ether_addr(&eth->src_addr, &rt.ports[1].mac));
    assert(rte_is_same_ether_addr(&eth->dst_addr, &peers[1]));

    reset();
    memset(&rt.neighbours, 0, sizeof(rt.neighbours));
    m = udp_packet(A, rt.ports[0].ip_be, 9999, 41, 1);
    memcpy(quote, header(m), sizeof(quote));
    submit(m, 0, DROP_UDP_UNBOUND_PORT);
    assert(capture_count == 1 && pending(0, A) && !pending(0, A)->contexts[0].transit);
    assert(rte_mempool_avail_count(rt.mbuf_pool) == POOL_SIZE - 1);
    arp_reply(0, A);
    check_error(1, rt.ports[0].port_id, A, 3, 3, 0, quote, sizeof(quote));
    assert(!pending(0, A) && rte_mempool_avail_count(rt.mbuf_pool) == POOL_SIZE);

    reset();
    memset(&rt.neighbours, 0, sizeof(rt.neighbours));
    submit(udp_packet(A, rt.ports[0].ip_be, 9999, 28, 1), 0, DROP_UDP_UNBOUND_PORT);
    uint64_t start = pending(0, A)->last_request;
    for (unsigned i = 1; i <= ARP_MAX_REQUESTS; i++)
        neighbour_tick(&rt, start + i * rte_get_timer_hz() * ARP_RETRY_SECONDS);
    assert(!pending(0, A) && rt.icmp_errors.generated == 1);
    assert(rt.graph.drop_reasons[DROP_NEIGHBOUR_RESOLUTION_TIMEOUT] == 1);
    assert(rte_mempool_avail_count(rt.mbuf_pool) == POOL_SIZE);

    reset();
    rt.routes.count = 0;
    submit(udp_packet(A, rt.ports[0].ip_be, 9999, 28, 1), 0, DROP_UDP_UNBOUND_PORT);
    assert(rt.icmp_errors.failed == 1 && !capture_count);
    reset();
    m = udp_packet(A, rt.ports[0].ip_be, 9999, 28, 1);
    struct rte_mbuf *held[POOL_SIZE];
    unsigned count = 0;
    while ((held[count] = rte_pktmbuf_alloc(rt.mbuf_pool))) count++;
    submit(m, 0, DROP_UDP_UNBOUND_PORT);
    assert(rt.icmp_errors.failed == 1 && !capture_count);
    for (unsigned i = 0; i < count; i++) rte_pktmbuf_free(held[i]);
    reset();
    tx_limit = 0;
    submit(udp_packet(A, rt.ports[0].ip_be, 9999, 28, 1), 0, DROP_UDP_UNBOUND_PORT);
    assert(rt.icmp_errors.generated == 1 && rt.graph.drop_reasons[DROP_TX_FAILED] == 1);
    reset();
}

static void check_forward(unsigned index, unsigned egress, const void *original, unsigned length)
{
    assert(index < capture_count && captures[index].port == rt.ports[egress].port_id);
    const struct rte_ether_hdr *eth = (const struct rte_ether_hdr *)captures[index].data;
    const uint8_t *ip = captures[index].data + 14, *before = original;
    assert(rte_is_same_ether_addr(&eth->src_addr, &rt.ports[egress].mac));
    assert(rte_is_same_ether_addr(&eth->dst_addr, &peers[egress]));
    assert(sum(ip, 20) == UINT16_MAX && ip[8] == before[8] - 1);
    for (unsigned i = 0; i < length; i++)
        if (i != 8 && i != 10 && i != 11) assert(ip[i] == before[i]);
    assert(captures[index].length == RTE_MAX(60, 14 + length));
    for (unsigned i = 14 + length; i < captures[index].length; i++) assert(!captures[index].data[i]);
}

static void forwarding_tests(void)
{
    /* RFC 1812 5.3.1: transit TTL decrements once; local TTL is not a filter. */
    reset();
    rt.ipv4_forwarding = 0;
    submit(packet(A, B, 64, IPPROTO_UDP, 28), 0, DROP_FORWARDING_DISABLED);
    assert(!capture_count && !rt.icmp_errors.generated);
    rt.ipv4_forwarding = 1;
    const uint8_t protocols[] = {IPPROTO_ICMP, IPPROTO_UDP, IPPROTO_TCP, 99};
    const uint8_t ttls[] = {2, 64, 255};
    for (unsigned p = 0; p < 2; p++) for (unsigned j = 0; j < RTE_DIM(protocols); j++) {
        for (unsigned t = 0; t < RTE_DIM(ttls); t++) {
            struct rte_mbuf *m = packet(p ? B : A, p ? A : B, ttls[t], protocols[j], 101);
            uint8_t original[101];
            memcpy(original, header(m), sizeof(original));
            unsigned index = capture_count;
            submit(m, p, DROP_NONE);
            check_forward(index, 1 - p, original, sizeof(original));
        }
    }
    assert(!rt.graph.nodes[NODE_ICMP_INPUT].stats.packets && !rt.graph.nodes[NODE_UDP_INPUT].stats.packets &&
           !rt.graph.nodes[NODE_TCP_INPUT].stats.packets);
    struct rte_mbuf *m = packet(A, B, 2, 99, 28);
    memset(rte_pktmbuf_append(m, 16), 0xa5, 16);
    uint8_t original[28];
    memcpy(original, header(m), sizeof(original));
    submit(m, 0, DROP_NONE);
    check_forward(capture_count - 1, 1, original, sizeof(original));
    m = packet(A, B, 2, 99, 28);
    struct rte_ipv4_hdr expected = *header(m);
    expected.time_to_live--;
    expected.hdr_checksum = 0;
    unsigned id;
    for (id = 0; id <= UINT16_MAX; id++) {
        expected.packet_id = rte_cpu_to_be_16((uint16_t)id);
        if (rte_ipv4_cksum(&expected) == 0) break;
    }
    assert(id <= UINT16_MAX);
    header(m)->packet_id = expected.packet_id;
    checksum(m);
    memcpy(original, header(m), sizeof(original));
    submit(m, 0, DROP_NONE);
    check_forward(capture_count - 1, 1, original, sizeof(original));
    assert(((const struct rte_ipv4_hdr *)(captures[capture_count - 1].data + 14))->hdr_checksum == 0);
    for (unsigned ttl = 0; ttl <= 1; ttl++) {
        m = packet(A, B, ttl, IPPROTO_UDP, 28);
        memcpy(original, header(m), sizeof(original));
        submit(m, 0, DROP_TTL_EXPIRED);
        check_error(capture_count - 1, rt.ports[0].port_id, A, 11, 0, 0, original, sizeof(original));
        m = packet(A, rt.ports[0].ip_be, ttl, IPPROTO_ICMP, 28);
        uint8_t *icmp = (uint8_t *)(header(m) + 1);
        memset(icmp, 0, 8);
        icmp[0] = 8;
        uint16_t ck = (uint16_t)~rte_raw_cksum(icmp, 8);
        memcpy(icmp + 2, &ck, sizeof(ck));
        submit(m, 0, DROP_NONE);
        assert(captures[capture_count - 1].data[34] == 0);
    }

    reset();
    for (unsigned gateway = 0; gateway <= 1; gateway++) {
        assert(route_init_connected(&rt) == 0);
        assert(route_add_gateway(&rt.routes, REMOTE, 24, rt.ports[1].id, gateway ? B : 0) == 0);
        if (!gateway) assert(neighbour_learn(&rt.neighbours, rt.ports[1].id, REMOTE, &peers[1]) == 0);
        m = packet(A, REMOTE, 64, 99, 28);
        memcpy(original, header(m), sizeof(original));
        submit(m, 0, DROP_NONE);
        check_forward(capture_count - 1, 1, original, sizeof(original));
    }
    assert(route_init_connected(&rt) == 0);
    assert(route_add_gateway(&rt.routes, 0, 0, rt.ports[1].id, B) == 0);
    m = packet(A, REMOTE, 64, 99, 28);
    memcpy(original, header(m), sizeof(original));
    submit(m, 0, DROP_NONE);
    check_forward(capture_count - 1, 1, original, sizeof(original));
    assert(route_add_gateway(&rt.routes, REMOTE, 32, rt.ports[0].id, A) == 0);
    m = packet(A, REMOTE, 64, 99, 28);
    memcpy(original, header(m), sizeof(original));
    submit(m, 0, DROP_NONE);
    check_forward(capture_count - 1, 0, original, sizeof(original));

    reset();
    m = packet(A, REMOTE, 64, 99, 28);
    memcpy(original, header(m), sizeof(original));
    submit(m, 0, DROP_NO_ROUTE);
    check_error(0, rt.ports[0].port_id, A, 3, 0, 0, original, sizeof(original));
    assert(route_add(&rt.routes, REMOTE, 32, UINT16_MAX) == 0);
    submit(packet(A, REMOTE, 64, 99, 28), 0, DROP_INVALID_EGRESS);
    assert(rt.icmp_errors.generated == 2);
    submit(packet(A, REMOTE, 1, 99, 28), 0, DROP_TTL_EXPIRED);
    assert(rt.graph.drop_reasons[DROP_INVALID_EGRESS] == 1);
    reset();
    rt.ports[1].mtu = 100;
    submit(packet(A, B, 64, 99, 100), 0, DROP_NONE);
    m = packet(A, B, 64, IPPROTO_UDP, 101);
    uint8_t quote[101];
    memcpy(quote, header(m), sizeof(quote));
    submit(m, 0, DROP_MTU);
    check_error(1, rt.ports[0].port_id, A, 3, 4, 100, quote, sizeof(quote));
    m = packet(A, B, 64, 99, 101);
    header(m)->fragment_offset = 0;
    checksum(m);
    submit(m, 0, DROP_MTU);
    assert(capture_count == 2 && rt.graph.drop_reasons[DROP_MTU] == 2);
    rt.ports[1].mtu = 1500;

    reset();
    /* RFC 2644 and RFC 3927: a default route cannot bypass address restrictions. */
    assert(route_add_gateway(&rt.routes, 0, 0, rt.ports[1].id, B) == 0);
    const uint32_t invalid[] = {0, rte_cpu_to_be_32(0x7f000001), rte_cpu_to_be_32(0xe0000001),
        rte_cpu_to_be_32(0xffffffff), rte_cpu_to_be_32(0xc00002ff), rte_cpu_to_be_32(0xc63364ff),
        rte_cpu_to_be_32(0xa9fe0101)};
    for (unsigned i = 0; i < RTE_DIM(invalid); i++)
        submit(packet(A, invalid[i], 64, 99, 28), 0, DROP_INVALID_DESTINATION);
    submit(packet(rte_cpu_to_be_32(0xa9fe0101), B, 64, 99, 28), 0, DROP_INVALID_SOURCE);
    submit(packet(rt.ports[1].ip_be, B, 64, 99, 28), 0, DROP_INVALID_SOURCE);
    m = packet(A, B, 64, 99, 60);
    header(m)->version_ihl = 0x4f;
    checksum(m);
    submit(m, 0, DROP_IPV4_OPTIONS);
    m = packet(A, B, 64, 99, 28);
    header(m)->version_ihl = 0x4f;
    submit(m, 0, DROP_INVALID_IPV4);
    m = packet(A, B, 64, 99, 28);
    header(m)->fragment_offset = rte_cpu_to_be_16(RTE_IPV4_HDR_MF_FLAG);
    checksum(m);
    submit(m, 0, DROP_IPV4_FRAGMENT);
    assert(!capture_count && !rt.icmp_errors.generated);
    m = packet(A, B, 1, IPPROTO_ICMP, 28);
    ((uint8_t *)(header(m) + 1))[0] = 3;
    submit(m, 0, DROP_TTL_EXPIRED);
    assert(rt.icmp_errors.suppressed == 1 && !capture_count);
    reset();
    tx_limit = 0;
    submit(packet(A, B, 64, 99, 28), 0, DROP_TX_FAILED);
    reset();
}

static void forwarding_resolution_tests(void)
{
    reset();
    assert(route_add(&rt.routes, REMOTE, 24, rt.ports[1].id) == 0);
    struct rte_mbuf *m = packet(A, REMOTE, 64, 99, 28);
    uint8_t original[28];
    memcpy(original, header(m), sizeof(original));
    submit(m, 0, DROP_NONE);
    assert(capture_count == 1 && pending(1, REMOTE));
    const struct rte_arp_hdr *arp = (const struct rte_arp_hdr *)(captures[0].data + 14);
    assert(arp->arp_data.arp_tip == REMOTE && arp->arp_data.arp_sip == rt.ports[1].ip_be);
    arp_reply(0, REMOTE);
    assert(pending(1, REMOTE) && capture_count == 1);
    arp_reply(1, REMOTE);
    assert(!pending(1, REMOTE) && capture_count == 2);
    check_forward(1, 1, original, sizeof(original));
    assert(rt.graph.nodes[NODE_IPV4_FORWARD].stats.packets == 1);

    reset();
    memset(&rt.neighbours, 0, sizeof(rt.neighbours));
    assert(neighbour_learn(&rt.neighbours, rt.ports[0].id, A, &peers[0]) == 0);
    assert(route_add_gateway(&rt.routes, REMOTE, 24, rt.ports[1].id, B) == 0);
    m = packet(A, REMOTE, 64, 99, 28);
    memcpy(original, header(m), sizeof(original));
    submit(m, 0, DROP_NONE);
    assert(pending(1, B) && !pending(1, REMOTE));
    uint64_t start = pending(1, B)->last_request;
    for (unsigned i = 1; i <= ARP_MAX_REQUESTS; i++)
        neighbour_tick(&rt, start + i * rte_get_timer_hz() * ARP_RETRY_SECONDS);
    assert(!pending(1, B) && capture_count == ARP_MAX_REQUESTS + 1);
    original[8]--;
    ((struct rte_ipv4_hdr *)original)->hdr_checksum = 0;
    ((struct rte_ipv4_hdr *)original)->hdr_checksum = rte_ipv4_cksum((struct rte_ipv4_hdr *)original);
    check_error(ARP_MAX_REQUESTS, rt.ports[0].port_id, A, 3, 1, 0, original, sizeof(original));
    assert(rt.graph.drop_reasons[DROP_NEIGHBOUR_RESOLUTION_TIMEOUT] == 1);
    assert(rt.icmp_errors.generated == 1);

    reset();
    memset(&rt.neighbours, 0, sizeof(rt.neighbours));
    assert(route_add(&rt.routes, REMOTE, 24, rt.ports[1].id) == 0);
    submit(packet(A, REMOTE, 64, 99, 28), 0, DROP_NONE);
    start = pending(1, REMOTE)->last_request;
    for (unsigned i = 1; i <= ARP_MAX_REQUESTS; i++)
        neighbour_tick(&rt, start + i * rte_get_timer_hz() * ARP_RETRY_SECONDS);
    assert(!pending(1, REMOTE) && pending(0, A));
    assert(!pending(0, A)->contexts[0].transit && rt.icmp_errors.generated == 1);
    start = pending(0, A)->last_request;
    for (unsigned i = 1; i <= ARP_MAX_REQUESTS; i++)
        neighbour_tick(&rt, start + i * rte_get_timer_hz() * ARP_RETRY_SECONDS);
    assert(!pending(0, A) && rt.icmp_errors.generated == 1);
    assert(rt.graph.drop_reasons[DROP_NEIGHBOUR_RESOLUTION_TIMEOUT] == 2);
    assert(capture_count == ARP_MAX_REQUESTS * 2);
    assert(rte_mempool_avail_count(rt.mbuf_pool) == POOL_SIZE);

    reset();
    assert(route_add(&rt.routes, REMOTE, 24, rt.ports[1].id) == 0);
    for (unsigned i = 0; i < NEIGHBOUR_PENDING_QUEUE_MAX; i++)
        submit(packet(A, REMOTE, 64, 99, 28), 0, DROP_NONE);
    submit(packet(A, REMOTE, 64, 99, 28), 0, DROP_NEIGHBOUR_QUEUE_FULL);
    assert(pending(1, REMOTE)->count == NEIGHBOUR_PENDING_QUEUE_MAX && capture_count == 1);
    neighbour_fini(&rt);
    assert(rt.graph.drop_reasons[DROP_NEIGHBOUR_CANCELLED] == NEIGHBOUR_PENDING_QUEUE_MAX);
    assert(!rt.icmp_errors.generated);
    reset();
    assert(route_add(&rt.routes, REMOTE, 24, rt.ports[1].id) == 0);
    for (unsigned i = 0; i < NEIGHBOUR_PENDING_MAX; i++)
        submit(packet(A, rte_cpu_to_be_32(rte_be_to_cpu_32(REMOTE) + i), 64, 99, 28), 0, DROP_NONE);
    submit(packet(A, rte_cpu_to_be_32(rte_be_to_cpu_32(REMOTE) + NEIGHBOUR_PENDING_MAX), 64, 99, 28),
           0, DROP_NEIGHBOUR_PENDING_FULL);
    assert(capture_count == NEIGHBOUR_PENDING_MAX);
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
    char *args[] = {"test-forward", "--lcores", core, "--no-huge", "--no-pci", "--no-shconf",
        "--no-telemetry", "--vdev=net_null0", "--vdev=net_null1", NULL};
    assert(rte_eal_init(9, args) >= 0);
    rt.mbuf_pool = rte_pktmbuf_pool_create("forward_pool", POOL_SIZE, 0, 0, RTE_MBUF_DEFAULT_BUF_SIZE, rte_socket_id());
    assert(rt.mbuf_pool);
    rt.port_count = 2;
    const struct rte_eth_rxtx_callback *callbacks[2];
    for (unsigned i = 0; i < 2; i++) {
        struct port_state *port = &rt.ports[i];
        char name[32];
        snprintf(name, sizeof(name), "net_null%u", i);
        assert(rte_eth_dev_get_port_by_name(name, &port->port_id) == 0);
        port->id = i ? 42 : 11;
        port->ip_be = i ? rte_cpu_to_be_32(RTE_IPV4(198u, 51, 100, 2)) : rte_cpu_to_be_32(RTE_IPV4(192u, 0, 2, 2));
        port->prefix_len = 24;
        port->mtu = 1500;
        port->mac = (struct rte_ether_addr){{2, 0, 0, 0, (uint8_t)i, 2}};
        struct rte_eth_conf conf = {0};
        assert(rte_eth_dev_configure(port->port_id, 1, 1, &conf) == 0);
        assert(rte_eth_rx_queue_setup(port->port_id, 0, 128, rte_socket_id(), NULL, rt.mbuf_pool) == 0);
        assert(rte_eth_tx_queue_setup(port->port_id, 0, 128, rte_socket_id(), NULL) == 0);
        assert(rte_eth_dev_start(port->port_id) == 0);
        port->started = port->configured = 1;
        callbacks[i] = rte_eth_add_tx_callback(port->port_id, 0, capture, NULL);
        assert(callbacks[i]);
    }
    error_tests();
    udp_error_tests();
    forwarding_tests();
    forwarding_resolution_tests();
    for (unsigned i = 0; i < 2; i++) {
        assert(rte_eth_remove_tx_callback(rt.ports[i].port_id, 0, callbacks[i]) == 0);
        rte_free((void *)callbacks[i]);
        rte_eth_dev_stop(rt.ports[i].port_id);
        rte_eth_dev_close(rt.ports[i].port_id);
    }
    assert(rte_mempool_avail_count(rt.mbuf_pool) == POOL_SIZE);
    rte_mempool_free(rt.mbuf_pool);
    assert(rte_eal_cleanup() == 0);
    puts("ICMP errors, suppression, return routes, counters and ownership passed");
    return 0;
}
