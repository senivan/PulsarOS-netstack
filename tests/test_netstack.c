#define _GNU_SOURCE
#include <assert.h>
#include <errno.h>
#include <sched.h>
#include <stdio.h>
#include <string.h>
#include <rte_arp.h>
#include <rte_eal.h>
#include <rte_icmp.h>
#include <rte_ip.h>
#include <rte_malloc.h>
#include <rte_udp.h>
#include "runtime.h"
#include "dpdk_port.h"
#include "config.h"

static struct app_runtime rt;
static const struct rte_ether_addr peer = {{2, 0, 0, 0, 0, 1}};
static _Alignas(8) uint8_t captured[2048];
static uint16_t captured_len, tx_limit = UINT16_MAX;
static unsigned captured_count;
static struct rte_mbuf *captured_mbuf;
static uint16_t captured_port;
static unsigned port_captures[RTE_MAX_ETHPORTS];

static uint16_t capture(uint16_t port, uint16_t queue, struct rte_mbuf **pkts,
                        uint16_t count, void *arg)
{
    (void)queue; (void)arg;
    uint16_t sent = count < tx_limit ? count : tx_limit;
    for (uint16_t i = 0; i < sent; i++) {
        captured_len = rte_pktmbuf_pkt_len(pkts[i]);
        assert(captured_len <= sizeof(captured));
        memcpy(captured, rte_pktmbuf_mtod(pkts[i], const void *), captured_len);
        assert(pkts[i]->ol_flags == 0 && pkts[i]->tx_offload == 0);
        captured_count++;
        captured_mbuf = pkts[i];
        captured_port = port;
        port_captures[port]++;
    }
    return sent;
}

static struct rte_mbuf *packet(unsigned length, uint16_t type)
{
    struct rte_mbuf *m = rte_pktmbuf_alloc(rt.mbuf_pool);
    assert(m);
    void *data = rte_pktmbuf_append(m, length);
    assert(data);
    memset(data, 0, length);
    if (length >= sizeof(struct rte_ether_hdr)) {
        struct rte_ether_hdr *eth = data;
        eth->src_addr = peer;
        eth->dst_addr = rt.ports[0].mac;
        eth->ether_type = rte_cpu_to_be_16(type);
    }
    return m;
}

static struct rte_mbuf *arp_request(void)
{
    struct rte_mbuf *m = packet(60, RTE_ETHER_TYPE_ARP);
    struct rte_ether_hdr *eth = rte_pktmbuf_mtod(m, struct rte_ether_hdr *);
    memset(&eth->dst_addr, 255, sizeof(eth->dst_addr));
    struct rte_arp_hdr *arp = (struct rte_arp_hdr *)(eth + 1);
    arp->arp_hardware = rte_cpu_to_be_16(RTE_ARP_HRD_ETHER);
    arp->arp_protocol = rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV4);
    arp->arp_hlen = 6;
    arp->arp_plen = 4;
    arp->arp_opcode = rte_cpu_to_be_16(RTE_ARP_OP_REQUEST);
    arp->arp_data.arp_sha = peer;
    arp->arp_data.arp_sip = rte_cpu_to_be_32(RTE_IPV4(192u, 0, 2, 1));
    arp->arp_data.arp_tip = rt.ports[0].ip_be;
    memset((char *)(arp + 1), 0xa5, 18);
    return m;
}

static struct rte_ipv4_hdr *ip_header(struct rte_mbuf *m)
{
    return rte_pktmbuf_mtod_offset(m, struct rte_ipv4_hdr *, 14);
}

static void ip_checksum(struct rte_mbuf *m)
{
    struct rte_ipv4_hdr *ip = ip_header(m);
    ip->hdr_checksum = 0;
    ip->hdr_checksum = rte_ipv4_cksum(ip);
}

static struct rte_mbuf *echo(unsigned payload)
{
    struct rte_mbuf *m = packet(14 + 20 + 8 + payload, RTE_ETHER_TYPE_IPV4);
    struct rte_ipv4_hdr *ip = ip_header(m);
    ip->version_ihl = 0x45;
    ip->total_length = rte_cpu_to_be_16(20 + 8 + payload);
    ip->time_to_live = 1; /* A host must accept TTL=1, unlike a router. */
    ip->next_proto_id = IPPROTO_ICMP;
    ip->src_addr = rte_cpu_to_be_32(RTE_IPV4(192u, 0, 2, 1));
    ip->dst_addr = rt.ports[0].ip_be;
    struct rte_icmp_hdr *icmp = (struct rte_icmp_hdr *)(ip + 1);
    icmp->icmp_type = RTE_IP_ICMP_ECHO_REQUEST;
    icmp->icmp_ident = rte_cpu_to_be_16(123);
    icmp->icmp_seq_nb = rte_cpu_to_be_16(456);
    for (unsigned i = 0; i < payload; i++) ((uint8_t *)(icmp + 1))[i] = (uint8_t)(i + 1);
    icmp->icmp_cksum = (uint16_t)~rte_raw_cksum(icmp, 8 + payload);
    ip_checksum(m);
    return m;
}

static void submit_on(struct rte_mbuf *m, unsigned interface, enum drop_reason reason)
{
    unsigned expected_available = rte_mempool_avail_count(rt.mbuf_pool) + m->nb_segs;
    uint64_t before = rt.graph.drop_reasons[reason];
    unsigned tx_before = captured_count;
    struct node_frame frame = { .count = 1 };
    frame.pkts[0] = m;
    frame.ctxs[0].ingress_port_id = rt.ports[interface].port_id;
    assert(graph_submit(&rt, NODE_ETH_INPUT, &frame) == 0);
    assert(rt.graph.q_count == 0 && rt.active_output == NULL);
    for (unsigned i = 0; i < GRAPH_FRAME_POOL_SIZE; i++) assert(!rt.graph.slots[i].used);
    assert(rte_mempool_avail_count(rt.mbuf_pool) == expected_available);
    if (reason != DROP_NONE) {
        assert(rt.graph.drop_reasons[reason] == before + 1);
        assert(captured_count == tx_before);
    }
}

static void submit(struct rte_mbuf *m, enum drop_reason reason)
{
    submit_on(m, 0, reason);
}

static struct rte_mbuf *udp_packet(const void *payload, unsigned len, uint16_t port, int checksum)
{
    struct rte_mbuf *m = packet(42 + len, RTE_ETHER_TYPE_IPV4);
    struct rte_ipv4_hdr *ip = ip_header(m);
    ip->version_ihl = 0x45;
    ip->total_length = rte_cpu_to_be_16(28 + len);
    ip->time_to_live = 64;
    ip->next_proto_id = IPPROTO_UDP;
    ip->src_addr = rte_cpu_to_be_32(RTE_IPV4(192u, 0, 2, 1));
    ip->dst_addr = rt.ports[0].ip_be;
    struct rte_udp_hdr *udp = (struct rte_udp_hdr *)(ip + 1);
    udp->src_port = rte_cpu_to_be_16(50001);
    udp->dst_port = rte_cpu_to_be_16(port);
    udp->dgram_len = rte_cpu_to_be_16(8 + len);
    if (len) memcpy(udp + 1, payload, len);
    if (checksum) udp->dgram_cksum = rte_ipv4_udptcp_cksum(ip, udp);
    ip_checksum(m);
    return m;
}

static uint32_t sum_bytes(const uint8_t *data, unsigned length)
{
    uint32_t sum = 0;
    for (unsigned i = 0; i < length; i += 2)
        sum += (uint16_t)data[i] << 8 | (i + 1 < length ? data[i + 1] : 0);
    return sum;
}

static uint16_t folded(uint32_t sum)
{
    while (sum >> 16) sum = (sum & 0xffff) + (sum >> 16);
    return (uint16_t)sum;
}

static void check_udp_output(const uint8_t *payload, unsigned len, uint16_t id)
{
    const struct rte_ether_hdr *eth = (const struct rte_ether_hdr *)captured;
    const struct rte_ipv4_hdr *ip = (const struct rte_ipv4_hdr *)(eth + 1);
    const struct rte_udp_hdr *udp = (const struct rte_udp_hdr *)(ip + 1);
    assert(rte_is_same_ether_addr(&eth->src_addr, &rt.ports[0].mac));
    assert(rte_is_same_ether_addr(&eth->dst_addr, &peer));
    assert(eth->ether_type == rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV4));
    assert(ip->version_ihl == 0x45 && ip->time_to_live == 64);
    assert(ip->src_addr == rt.ports[0].ip_be);
    assert(ip->dst_addr == rte_cpu_to_be_32(RTE_IPV4(192u, 0, 2, 1)));
    assert(ip->total_length == rte_cpu_to_be_16(28 + len));
    assert(ip->packet_id == rte_cpu_to_be_16(id));
    assert(ip->fragment_offset == rte_cpu_to_be_16(RTE_IPV4_HDR_DF_FLAG));
    assert(ip->next_proto_id == IPPROTO_UDP);
    assert(folded(sum_bytes((const uint8_t *)ip, 20)) == UINT16_MAX);
    assert(udp->src_port == rte_cpu_to_be_16(9000) && udp->dst_port == rte_cpu_to_be_16(50001));
    assert(udp->dgram_len == rte_cpu_to_be_16(8 + len) && udp->dgram_cksum != 0);
    uint32_t checksum = sum_bytes((const uint8_t *)&ip->src_addr, 8) + IPPROTO_UDP + 8 + len;
    assert(folded(checksum + sum_bytes((const uint8_t *)udp, 8 + len)) == UINT16_MAX);
    assert(!memcmp(udp + 1, payload, len));
    unsigned frame_len = 42 + len < 60 ? 60 : 42 + len;
    assert(captured_len == frame_len);
    for (unsigned i = 42 + len; i < frame_len; i++) assert(captured[i] == 0);
}

static void udp_tests(void)
{
    uint8_t payload[PS_UDP_MAX_PAYLOAD], received[PS_UDP_MAX_PAYLOAD];
    for (unsigned i = 0; i < sizeof(payload); i++) payload[i] = (uint8_t)i;
    struct ps_addr address = { .ip_be = rte_cpu_to_be_32(RTE_IPV4(192u, 0, 2, 1)), .port = 50001 };
    struct ps_addr source;
    assert(ps_udp_bind(&rt, 0) == -EINVAL);
    assert(ps_udp_bind(&rt, 9000) == 0);
    assert(ps_udp_bind(&rt, 9000) == -EADDRINUSE);
    assert(ps_udp_bind(&rt, 9001) == 0);
    assert(ps_udp_recvfrom(&rt, 9000, received, sizeof(received), &source) == -EAGAIN);
    assert(ps_udp_recvfrom(&rt, 9999, received, sizeof(received), &source) == -ENOENT);

    const unsigned lengths[] = {0, 1, 2, 13, 64, PS_UDP_MAX_PAYLOAD};
    for (unsigned j = 0; j < sizeof(lengths) / sizeof(lengths[0]); j++) {
        unsigned len = lengths[j];
        for (int checksum = 0; checksum <= 1; checksum++) {
            submit(udp_packet(payload, len, 9000, checksum), DROP_NONE);
            assert(ps_udp_recvfrom(&rt, 9000, received, sizeof(received), &source) == (ssize_t)len);
            assert(!memcmp(received, payload, len));
            assert(source.ip_be == address.ip_be && source.port == address.port);
        }
        uint16_t id = rt.next_ip_id;
        assert(ps_udp_sendto(&rt, 9000, payload, len, &address) == (ssize_t)len);
        check_udp_output(payload, len, id);
        assert(rte_mempool_avail_count(rt.mbuf_pool) == 1023);
    }
    uint32_t pseudo_sum = sum_bytes((const uint8_t *)&rt.ports[0].ip_be, 4) +
        sum_bytes((const uint8_t *)&address.ip_be, 4) + IPPROTO_UDP + 10 + 9000 + 50001 + 10;
    uint16_t word = (uint16_t)~folded(pseudo_sum);
    uint8_t zero_checksum_payload[] = { (uint8_t)(word >> 8), (uint8_t)word };
    assert(ps_udp_sendto(&rt, 9000, zero_checksum_payload, 2, &address) == 2);
    assert(((const struct rte_udp_hdr *)(captured + 34))->dgram_cksum == UINT16_MAX);
    submit(udp_packet(zero_checksum_payload, 2, 9000, 1), DROP_NONE);
    assert(ps_udp_recvfrom(&rt, 9000, received, sizeof(received), &source) == 2);
    assert(!memcmp(received, zero_checksum_payload, 2));
    submit(udp_packet(payload, 13, 9001, 1), DROP_NONE);
    assert(ps_udp_recvfrom(&rt, 9000, received, sizeof(received), &source) == -EAGAIN);
    assert(ps_udp_recvfrom(&rt, 9001, received, 12, &source) == -EMSGSIZE);
    assert(ps_udp_recvfrom(&rt, 9001, received, sizeof(received), &source) == 13);
    assert(!memcmp(received, payload, 13));
    submit(udp_packet(payload, 13, 9999, 1), DROP_UDP_UNBOUND_PORT);
    struct rte_mbuf *m = udp_packet(payload, 0, 9000, 0);
    rte_pktmbuf_trim(m, 1);
    ip_header(m)->total_length = rte_cpu_to_be_16(27);
    ip_checksum(m);
    submit(m, DROP_INVALID_UDP);
    m = udp_packet(payload, 1, 9000, 0);
    rte_pktmbuf_mtod_offset(m, struct rte_udp_hdr *, 34)->dgram_len = rte_cpu_to_be_16(7);
    submit(m, DROP_UDP_BAD_LENGTH);
    m = udp_packet(payload, 1, 9000, 0);
    rte_pktmbuf_mtod_offset(m, struct rte_udp_hdr *, 34)->dgram_len = rte_cpu_to_be_16(10);
    submit(m, DROP_UDP_BAD_LENGTH);
    m = udp_packet(payload, 13, 9000, 1);
    rte_pktmbuf_mtod_offset(m, uint8_t *, 42)[0] ^= 1;
    submit(m, DROP_UDP_BAD_CHECKSUM);
    m = udp_packet(payload, 13, 9000, 1);
    memset(rte_pktmbuf_append(m, 7), 0xa5, 7);
    ip_header(m)->total_length = rte_cpu_to_be_16(48);
    ip_checksum(m);
    submit(m, DROP_NONE);
    assert(ps_udp_recvfrom(&rt, 9000, received, sizeof(received), &source) == 13);
    assert(!memcmp(received, payload, 13));

    for (unsigned cycle = 0; cycle < 3; cycle++) {
        for (unsigned i = 0; i < PS_UDP_RX_QUEUE_SIZE; i++) {
            uint8_t value = (uint8_t)i;
            submit(udp_packet(&value, 1, 9000, 1), DROP_NONE);
        }
        submit(udp_packet(payload, 1, 9000, 1), DROP_UDP_RX_QUEUE_FULL);
        for (unsigned i = 0; i < PS_UDP_RX_QUEUE_SIZE; i++) {
            assert(ps_udp_recvfrom(&rt, 9000, received, sizeof(received), &source) == 1);
            assert(received[0] == i);
        }
    }

    /* Hold and overwrite the RX mbuf to detect reuse or retained payload pointers. */
    m = udp_packet(payload, 13, 9000, 1);
    struct rte_mbuf *original = m, *held[1023];
    submit(m, DROP_NONE);
    for (unsigned i = 0; i < 1023; i++) { held[i] = rte_pktmbuf_alloc(rt.mbuf_pool); assert(held[i]); }
    for (unsigned i = 0; i < 1023; i++) if (held[i] != original) rte_pktmbuf_free(held[i]);
    memset(rte_pktmbuf_append(original, 60), 0xcc, 60);
    assert(ps_udp_recvfrom(&rt, 9000, received, sizeof(received), &source) == 13);
    uint16_t id = rt.next_ip_id;
    assert(ps_udp_sendto(&rt, 9000, received, 13, &source) == 13);
    assert(captured_mbuf != original);
    check_udp_output(payload, 13, id);
    rte_pktmbuf_free(original);

    struct ps_addr unknown = { .ip_be = rte_cpu_to_be_32(RTE_IPV4(192u, 0, 2, 3)), .port = 1 };
    uint64_t before = rt.graph.drop_reasons[DROP_NEIGHBOUR_NOT_FOUND];
    assert(ps_udp_sendto(&rt, 9000, payload, 1, &unknown) == -EIO);
    assert(rt.graph.drop_reasons[DROP_NEIGHBOUR_NOT_FOUND] == before + 1);
    unknown.ip_be = rte_cpu_to_be_32(RTE_IPV4(192u, 0, 2, 255));
    before = rt.graph.drop_reasons[DROP_INVALID_DESTINATION];
    assert(ps_udp_sendto(&rt, 9000, payload, 1, &unknown) == -EIO);
    assert(rt.graph.drop_reasons[DROP_INVALID_DESTINATION] == before + 1);
    assert(ps_udp_sendto(&rt, 9999, payload, 1, &address) == -ENOENT);
    assert(ps_udp_sendto(&rt, 9000, payload, SIZE_MAX, &address) == -EMSGSIZE);
    rt.ports[0].mtu = 64;
    assert(ps_udp_sendto(&rt, 9000, payload, 37, &address) == -EMSGSIZE);
    rt.ports[0].mtu = 1500;
    for (unsigned i = 0; i < 1023; i++) { held[i] = rte_pktmbuf_alloc(rt.mbuf_pool); assert(held[i]); }
    before = rt.graph.drop_reasons[DROP_MBUF_ALLOCATION_FAILED];
    assert(ps_udp_sendto(&rt, 9000, payload, 1, &address) == -ENOMEM);
    assert(rt.graph.drop_reasons[DROP_MBUF_ALLOCATION_FAILED] == before + 1);
    for (unsigned i = 0; i < 1023; i++) rte_pktmbuf_free(held[i]);
    for (unsigned i = 0; i < GRAPH_FRAME_POOL_SIZE; i++) rt.graph.slots[i].used = 1;
    before = rt.graph.drop_reasons[DROP_GRAPH_FULL];
    assert(ps_udp_sendto(&rt, 9000, payload, 1, &address) == -EIO);
    assert(rt.graph.drop_reasons[DROP_GRAPH_FULL] == before + 1);
    for (unsigned i = 0; i < GRAPH_FRAME_POOL_SIZE; i++) rt.graph.slots[i].used = 0;
    tx_limit = 0;
    before = rt.graph.drop_reasons[DROP_TX_FAILED];
    assert(ps_udp_sendto(&rt, 9000, payload, 1, &address) == -EIO);
    assert(rt.graph.drop_reasons[DROP_TX_FAILED] == before + 1);
    tx_limit = 2;
    struct node_frame burst = { .count = 4 };
    for (unsigned i = 0; i < burst.count; i++) {
        burst.pkts[i] = packet(1, 0);
        burst.ctxs[i].src_port = 9000;
        burst.ctxs[i].dst_port = address.port;
        burst.ctxs[i].dst_ip_be = address.ip_be;
        burst.ctxs[i].ip_protocol = IPPROTO_UDP;
    }
    before = rt.graph.drop_reasons[DROP_TX_FAILED];
    assert(graph_submit(&rt, NODE_IPV4_ROUTE, &burst) == 0);
    assert(rt.graph.drop_reasons[DROP_TX_FAILED] == before + 2);
    tx_limit = UINT16_MAX;
    for (unsigned i = 0; i < 100; i++) {
        assert(ps_udp_sendto(&rt, 9000, payload, 13, &address) == 13);
        assert(rte_mempool_avail_count(rt.mbuf_pool) == 1023);
    }
    for (unsigned i = 2; i < PS_UDP_MAX_ENDPOINTS; i++) assert(ps_udp_bind(&rt, 9000 + i) == 0);
    assert(ps_udp_bind(&rt, 10000) == -ENOSPC);
    assert(rte_mempool_avail_count(rt.mbuf_pool) == 1023);
    puts("UDP endpoints, checksums, output and ownership checks passed");
}

static const struct rte_ether_addr peer_b = {{2, 0, 0, 0, 1, 1}};

static uint32_t peer_ip_on(unsigned p)
{
    return rte_cpu_to_be_32(p ? RTE_IPV4(198u, 51, 100, 1) : RTE_IPV4(192u, 0, 2, 1));
}

static struct rte_mbuf *on_interface(struct rte_mbuf *m, unsigned p)
{
    struct rte_ether_hdr *eth = rte_pktmbuf_mtod(m, struct rte_ether_hdr *);
    eth->src_addr = p ? peer_b : peer;
    if (!rte_is_broadcast_ether_addr(&eth->dst_addr)) eth->dst_addr = rt.ports[p].mac;
    if (eth->ether_type == rte_cpu_to_be_16(RTE_ETHER_TYPE_ARP)) {
        struct rte_arp_hdr *arp = (struct rte_arp_hdr *)(eth + 1);
        arp->arp_data.arp_sip = peer_ip_on(p);
        arp->arp_data.arp_tip = rt.ports[p].ip_be;
        arp->arp_data.arp_sha = eth->src_addr;
    } else {
        struct rte_ipv4_hdr *ip = ip_header(m);
        ip->src_addr = peer_ip_on(p);
        ip->dst_addr = rt.ports[p].ip_be;
        if (ip->next_proto_id == IPPROTO_UDP) {
            struct rte_udp_hdr *udp = (struct rte_udp_hdr *)(ip + 1);
            udp->dgram_cksum = 0;
            udp->dgram_cksum = rte_ipv4_udptcp_cksum(ip, udp);
        }
        ip_checksum(m);
    }
    return m;
}

static void check_reply_on(unsigned p, uint32_t source_ip)
{
    const struct rte_ether_hdr *eth = (const struct rte_ether_hdr *)captured;
    const struct rte_ipv4_hdr *ip = (const struct rte_ipv4_hdr *)(eth + 1);
    assert(captured_port == rt.ports[p].port_id);
    assert(rte_is_same_ether_addr(&eth->src_addr, &rt.ports[p].mac));
    assert(rte_is_same_ether_addr(&eth->dst_addr, p ? &peer_b : &peer));
    assert(ip->src_addr == source_ip && ip->dst_addr == peer_ip_on(p));
    assert(folded(sum_bytes((const uint8_t *)ip, 20)) == UINT16_MAX);
}

static void route_tests(void)
{
    struct route_result result;
    for (unsigned p = 0; p < 2; p++) {
        assert(ipv4_route_lookup(&rt, peer_ip_on(p), &result) == DROP_NONE);
        assert(result.netif_id == rt.ports[p].id && result.source_ip_be == rt.ports[p].ip_be);
        assert(result.next_hop_be == peer_ip_on(p));
    }
    assert(route_add(&rt.routes, peer_ip_on(0), 32, rt.ports[1].id) == 0);
    assert(ipv4_route_lookup(&rt, peer_ip_on(0), &result) == DROP_NONE);
    assert(result.netif_id == rt.ports[1].id);
    assert(route_add(&rt.routes, peer_ip_on(0), 32, rt.ports[0].id) == 0);
    assert(ipv4_route_lookup(&rt, peer_ip_on(0), &result) == DROP_NONE);
    assert(result.netif_id == rt.ports[1].id); /* First route wins equal prefixes. */
    rt.ports[1].started = 0;
    assert(ipv4_route_lookup(&rt, peer_ip_on(0), &result) == DROP_INVALID_EGRESS);
    rt.ports[1].started = 1;
    assert(route_init_connected(&rt) == 0);
    uint32_t outside = rte_cpu_to_be_32(RTE_IPV4(203u, 0, 113, 1));
    assert(ipv4_route_lookup(&rt, outside, &result) == DROP_NO_ROUTE);
    assert(route_add(&rt.routes, outside, 32, UINT16_MAX) == 0);
    assert(ipv4_route_lookup(&rt, outside, &result) == DROP_INVALID_EGRESS);
    assert(route_init_connected(&rt) == 0);
    assert(route_add(&rt.routes, 0, 0, rt.ports[0].id) == 0);
    assert(ipv4_route_lookup(&rt, outside, &result) == DROP_NONE);
    assert(result.netif_id == rt.ports[0].id);
    assert(ipv4_route_lookup(&rt, peer_ip_on(1), &result) == DROP_NONE);
    assert(result.netif_id == rt.ports[1].id);
    assert(route_add(&rt.routes, 0, 33, 0) == -EINVAL);
    while (rt.routes.count < ROUTE_CAPACITY) assert(route_add(&rt.routes, 0, 0, 0) == 0);
    assert(route_add(&rt.routes, 0, 0, 0) == -ENOSPC);
    assert(route_init_connected(&rt) == 0);
}

static void multi_tests(void)
{
    struct port_state *b = &rt.ports[1];
    assert(rte_eth_dev_get_port_by_name("net_null1", &b->port_id) == 0);
    b->id = 42;
    assert(b->port_id != b->id && b->port_id != 1);
    b->mac = (struct rte_ether_addr){{2, 0, 0, 0, 1, 2}};
    b->ip_be = rte_cpu_to_be_32(RTE_IPV4(198u, 51, 100, 2));
    b->prefix_len = 24;
    b->mtu = 1500;
    struct rte_eth_conf ec = {0};
    assert(rte_eth_dev_configure(b->port_id, 1, 1, &ec) == 0);
    assert(rte_eth_rx_queue_setup(b->port_id, 0, 128, rte_socket_id(), NULL, rt.mbuf_pool) == 0);
    assert(rte_eth_tx_queue_setup(b->port_id, 0, 128, rte_socket_id(), NULL) == 0);
    assert(rte_eth_dev_start(b->port_id) == 0);
    b->configured = b->started = 1;
    rt.port_count = 2;
    const struct rte_eth_rxtx_callback *cb = rte_eth_add_tx_callback(b->port_id, 0, capture, NULL);
    assert(cb && route_init_connected(&rt) == 0);
    assert(netif_by_id(&rt, b->id) == b && netif_by_dpdk_port(&rt, b->port_id) == b);
    assert(!netif_by_id(&rt, 1) && !netif_by_dpdk_port(&rt, 1));
    route_tests();
    tx_limit = UINT16_MAX;
    const uint8_t payload[] = {0, 1, 0xff, 3, 4};
    for (unsigned p = 0; p < 2; p++) {
        submit_on(on_interface(arp_request(), p), p, DROP_NONE);
        assert(captured_port == rt.ports[p].port_id);
        const struct rte_ether_hdr *eth = (const struct rte_ether_hdr *)captured;
        const struct rte_arp_hdr *arp = (const struct rte_arp_hdr *)(eth + 1);
        assert(rte_is_same_ether_addr(&eth->src_addr, &rt.ports[p].mac));
        assert(rte_is_same_ether_addr(&arp->arp_data.arp_sha, &rt.ports[p].mac));
        assert(arp->arp_data.arp_sip == rt.ports[p].ip_be);
        struct rte_mbuf *m = on_interface(arp_request(), p);
        struct rte_arp_hdr *arp_reply = rte_pktmbuf_mtod_offset(m, struct rte_arp_hdr *, 14);
        arp_reply->arp_opcode = rte_cpu_to_be_16(RTE_ARP_OP_REPLY);
        arp_reply->arp_data.arp_tha = rt.ports[p].mac;
        unsigned prior = captured_count;
        submit_on(m, p, DROP_NONE);
        assert(captured_count == prior);
        struct rte_ether_addr learned;
        assert(neighbour_lookup(&rt.neighbours, rt.ports[p].id, peer_ip_on(p), &learned) == 0);
        assert(rte_is_same_ether_addr(&learned, p ? &peer_b : &peer));
        m = on_interface(arp_request(), p);
        rte_pktmbuf_mtod_offset(m, struct rte_arp_hdr *, 14)->arp_hlen = 5;
        submit_on(m, p, DROP_INVALID_ARP);
        assert(neighbour_lookup(&rt.neighbours, rt.ports[p].id, peer_ip_on(p), &learned) == 0);
        assert(rte_is_same_ether_addr(&learned, p ? &peer_b : &peer));
        m = on_interface(arp_request(), p);
        rte_pktmbuf_mtod_offset(m, struct rte_arp_hdr *, 14)->arp_data.arp_tip = rt.ports[1-p].ip_be;
        submit_on(m, p, DROP_NOT_LOCAL);
        m = on_interface(echo(3), p);
        rte_pktmbuf_mtod(m, struct rte_ether_hdr *)->dst_addr = rt.ports[1-p].mac;
        submit_on(m, p, DROP_NOT_LOCAL);
        submit_on(on_interface(echo(3), p), p, DROP_NONE);
        check_reply_on(p, rt.ports[p].ip_be);
        assert(((struct rte_icmp_hdr *)(captured + 34))->icmp_type == RTE_IP_ICMP_ECHO_REPLY);
        assert(folded(sum_bytes(captured + 34, 11)) == UINT16_MAX);
        m = on_interface(echo(3), p);
        ip_header(m)->dst_addr = rt.ports[1-p].ip_be;
        ip_checksum(m);
        submit_on(m, p, DROP_NONE);
        check_reply_on(p, rt.ports[1-p].ip_be);
        m = on_interface(echo(3), p);
        ip_header(m)->dst_addr = peer_ip_on(1-p);
        ip_checksum(m);
        submit_on(m, p, DROP_FORWARDING_DISABLED);

        submit_on(on_interface(udp_packet(payload, sizeof(payload), 9000, 1), p), p, DROP_NONE);
        struct ps_addr source;
        uint8_t data[32];
        assert(ps_udp_recvfrom(&rt, 9000, data, sizeof(data), &source) == sizeof(payload));
        assert(source.ip_be == peer_ip_on(p) && source.port == 50001);
        assert(!memcmp(data, payload, sizeof(payload)));
        assert(ps_udp_sendto(&rt, 9000, data, sizeof(payload), &source) == sizeof(payload));
        check_reply_on(p, rt.ports[p].ip_be);
        const struct rte_ipv4_hdr *ip = (const struct rte_ipv4_hdr *)(captured + 14);
        const struct rte_udp_hdr *udp = (const struct rte_udp_hdr *)(captured + 34);
        uint32_t sum = sum_bytes((const uint8_t *)&ip->src_addr, 8) + IPPROTO_UDP + 8 + sizeof(payload);
        assert(folded(sum + sum_bytes((const uint8_t *)udp, 8 + sizeof(payload))) == UINT16_MAX);
        assert(!memcmp(udp + 1, payload, sizeof(payload)));
        source.ip_be = rte_cpu_to_be_32(rte_be_to_cpu_32(peer_ip_on(p)) + 20);
        uint64_t before = rt.graph.drop_reasons[DROP_NEIGHBOUR_NOT_FOUND];
        assert(ps_udp_sendto(&rt, 9000, payload, sizeof(payload), &source) == -EIO);
        assert(rt.graph.drop_reasons[DROP_NEIGHBOUR_NOT_FOUND] == before + 1);
    }
    struct rte_mbuf *asymmetric = echo(3);
    ip_header(asymmetric)->src_addr = peer_ip_on(1);
    ip_checksum(asymmetric);
    submit_on(asymmetric, 0, DROP_NONE);
    check_reply_on(1, rt.ports[0].ip_be);
    assert(folded(sum_bytes(captured + 34, 11)) == UINT16_MAX);
    b->mtu = 28;
    asymmetric = echo(3);
    ip_header(asymmetric)->src_addr = peer_ip_on(1);
    ip_checksum(asymmetric);
    submit_on(asymmetric, 0, DROP_MTU);
    struct ps_addr limited = { .ip_be = peer_ip_on(1), .port = 1 };
    assert(ps_udp_sendto(&rt, 9000, payload, sizeof(payload), &limited) == -EMSGSIZE);
    limited.ip_be = peer_ip_on(0);
    assert(ps_udp_sendto(&rt, 9000, payload, sizeof(payload), &limited) == sizeof(payload));
    b->mtu = 1500;
    struct ps_addr missing = { .ip_be = rte_cpu_to_be_32(RTE_IPV4(203u, 0, 113, 1)), .port = 1 };
    uint64_t before = rt.graph.drop_reasons[DROP_NO_ROUTE];
    assert(ps_udp_sendto(&rt, 9000, payload, sizeof(payload), &missing) == -EIO);
    assert(rt.graph.drop_reasons[DROP_NO_ROUTE] == before + 1);
    assert(route_add(&rt.routes, missing.ip_be, 32, UINT16_MAX) == 0);
    before = rt.graph.drop_reasons[DROP_INVALID_EGRESS];
    assert(ps_udp_sendto(&rt, 9000, payload, sizeof(payload), &missing) == -EIO);
    assert(rt.graph.drop_reasons[DROP_INVALID_EGRESS] == before + 1);
    assert(route_init_connected(&rt) == 0);

    uint32_t shared = rte_cpu_to_be_32(RTE_IPV4(10u, 0, 0, 1));
    struct rte_ether_addr mac;
    assert(neighbour_learn(&rt.neighbours, rt.ports[0].id, shared, &peer) == 0);
    assert(neighbour_learn(&rt.neighbours, b->id, shared, &peer_b) == 0);
    assert(neighbour_learn(&rt.neighbours, b->id, shared, &peer) == 0);
    assert(neighbour_lookup(&rt.neighbours, rt.ports[0].id, shared, &mac) == 0);
    assert(rte_is_same_ether_addr(&mac, &peer));
    assert(neighbour_learn(&rt.neighbours, b->id, shared, &peer_b) == 0);
    assert(neighbour_lookup(&rt.neighbours, b->id, shared, &mac) == 0);
    assert(rte_is_same_ether_addr(&mac, &peer_b));
    struct node_frame frame = { .count = 1 };
    for (unsigned p = 0; p < 2; p++) {
        frame.pkts[0] = packet(20, 0);
        frame.ctxs[0] = (struct packet_ctx){ .egress_port_id = rt.ports[p].port_id,
            .next_hop_ip_be = shared, .dst_ip_be = peer_ip_on(p) };
        assert(graph_submit(&rt, NODE_ETH_OUTPUT, &frame) == 0);
        assert(captured_port == rt.ports[p].port_id);
        assert(rte_is_same_ether_addr(&((const struct rte_ether_hdr *)captured)->dst_addr, p ? &peer_b : &peer));
    }
    frame.pkts[0] = packet(60, 0);
    frame.ctxs[0].ingress_port_id = 1;
    before = rt.graph.drop_reasons[DROP_PORT_BINDING];
    assert(graph_submit(&rt, NODE_ETH_INPUT, &frame) == 0);
    assert(rt.graph.drop_reasons[DROP_PORT_BINDING] == before + 1);
    frame.pkts[0] = packet(60, 0);
    frame.ctxs[0].egress_port_id = 1;
    before = rt.graph.drop_reasons[DROP_INVALID_EGRESS];
    assert(graph_submit(&rt, NODE_TX, &frame) == 0);
    assert(rt.graph.drop_reasons[DROP_INVALID_EGRESS] == before + 1);
    for (unsigned limit = 0; limit < 3; limit++) {
        tx_limit = limit;
        frame.count = 4;
        unsigned counts[2] = {port_captures[rt.ports[0].port_id], port_captures[b->port_id]};
        uint64_t sent[2] = {rt.ports[0].tx_packets, b->tx_packets};
        uint64_t dropped[2] = {rt.ports[0].tx_drops, b->tx_drops};
        for (unsigned i = 0; i < frame.count; i++) {
            frame.pkts[i] = packet(60, 0);
            frame.ctxs[i].egress_port_id = rt.ports[i % 2].port_id;
        }
        before = rt.graph.drop_reasons[DROP_TX_FAILED];
        assert(graph_submit(&rt, NODE_TX, &frame) == 0);
        for (unsigned p = 0; p < 2; p++) {
            assert(port_captures[rt.ports[p].port_id] == counts[p] + limit);
            assert(rt.ports[p].tx_packets == sent[p] + limit);
            assert(rt.ports[p].tx_drops == dropped[p] + 2 - limit);
        }
        assert(rt.graph.drop_reasons[DROP_TX_FAILED] == before + 4 - 2 * limit);
        assert(rte_mempool_avail_count(rt.mbuf_pool) == 1023);
    }
    assert(rte_eth_remove_tx_callback(b->port_id, 0, cb) == 0);
    rte_free((void *)cb);
    rte_eth_dev_stop(b->port_id);
    rte_eth_dev_close(b->port_id);
    b->started = b->configured = 0;
    puts("multi-interface ARP, ICMP, UDP, routes, neighbours, no forwarding and mixed TX passed");
}

int main(void)
{
    cpu_set_t cpus;
    assert(sched_getaffinity(0, sizeof(cpus), &cpus) == 0);
    unsigned core;
    for (core = 0; core < CPU_SETSIZE; core++) if (CPU_ISSET(core, &cpus)) break;
    char core_arg[32];
    /* Map logical core zero onto an allowed CPU, including CPU IDs above RTE_MAX_LCORE. */
    snprintf(core_arg, sizeof(core_arg), "0@%u", core);
    char *argv[] = { "test-netstack", "--lcores", core_arg, "--no-pci", "--no-huge",
                     "--no-shconf", "--no-telemetry", "--vdev=net_null0",
                     "--vdev=net_null_unused", "--vdev=net_null1", NULL };
    assert(rte_eal_init(10, argv) >= 0);
    rt.mbuf_pool = rte_pktmbuf_pool_create("test_pool", 1023, 0, 0, RTE_MBUF_DEFAULT_BUF_SIZE, rte_socket_id());
    assert(rt.mbuf_pool);
    assert(rte_eth_dev_get_port_by_name("net_null0", &rt.ports[0].port_id) == 0);
    struct rte_eth_conf ec = {0};
    assert(rte_eth_dev_configure(rt.ports[0].port_id, 1, 1, &ec) == 0);
    assert(rte_eth_rx_queue_setup(rt.ports[0].port_id, 0, 128, rte_socket_id(), NULL, rt.mbuf_pool) == 0);
    assert(rte_eth_tx_queue_setup(rt.ports[0].port_id, 0, 128, rte_socket_id(), NULL) == 0);
    assert(rte_eth_dev_start(rt.ports[0].port_id) == 0);
    rt.ports[0].mac = (struct rte_ether_addr){{2, 0, 0, 0, 0, 2}};
    rt.ports[0].ip_be = rte_cpu_to_be_32(RTE_IPV4(192u, 0, 2, 2));
    rt.ports[0].prefix_len = 24;
    rt.ports[0].mtu = 1500;
    rt.port_count = 1;
    rt.ports[0].configured = rt.ports[0].started = 1;
    assert(route_init_connected(&rt) == 0);
    const struct rte_eth_rxtx_callback *cb = rte_eth_add_tx_callback(rt.ports[0].port_id, 0, capture, NULL);
    assert(cb && graph_init(&rt) == 0);

    struct neighbour_table table = {0};
    struct rte_ether_addr learned;
    assert(neighbour_lookup(&table, 0, 1, &learned) == -ENOENT);
    for (unsigned i = 1; i <= NEIGHBOUR_CAPACITY; i++)
        assert(neighbour_learn(&table, 0, rte_cpu_to_be_32(i), &peer) == 0);
    for (unsigned i = 1; i <= NEIGHBOUR_CAPACITY; i++) {
        assert(neighbour_lookup(&table, 0, rte_cpu_to_be_32(i), &learned) == 0);
        assert(rte_is_same_ether_addr(&learned, &peer));
    }
    assert(neighbour_learn(&table, 0, rte_cpu_to_be_32(NEIGHBOUR_CAPACITY + 1), &peer) == -ENOSPC);
    assert(neighbour_learn(&table, 0, rte_cpu_to_be_32(1), &rt.ports[0].mac) == 0);
    assert(neighbour_lookup(&table, 0, rte_cpu_to_be_32(1), &learned) == 0);
    assert(rte_is_same_ether_addr(&learned, &rt.ports[0].mac));

    submit(arp_request(), DROP_NONE);
    uint32_t peer_ip = rte_cpu_to_be_32(RTE_IPV4(192u, 0, 2, 1));
    assert(neighbour_lookup(&rt.neighbours, rt.ports[0].id, peer_ip, &learned) == 0);
    assert(rte_is_same_ether_addr(&learned, &peer));
    assert(captured_count == 1 && captured_len == 60);
    const struct rte_ether_hdr *eth = (const struct rte_ether_hdr *)captured;
    const struct rte_arp_hdr *arp = (const struct rte_arp_hdr *)(eth + 1);
    assert(rte_is_same_ether_addr(&eth->src_addr, &rt.ports[0].mac));
    assert(rte_is_same_ether_addr(&eth->dst_addr, &peer));
    assert(arp->arp_opcode == rte_cpu_to_be_16(RTE_ARP_OP_REPLY));
    assert(arp->arp_data.arp_sip == rt.ports[0].ip_be);
    assert(arp->arp_data.arp_tip == rte_cpu_to_be_32(RTE_IPV4(192u, 0, 2, 1)));
    for (unsigned i = 42; i < 60; i++) assert(captured[i] == 0);
    struct rte_mbuf *m = arp_request();
    rte_pktmbuf_mtod_offset(m, struct rte_arp_hdr *, 14)->arp_data.arp_sip = 0;
    submit(m, DROP_NONE);
    assert(arp->arp_data.arp_tip == 0); /* RFC 5227 probe. */
    assert(neighbour_lookup(&rt.neighbours, rt.ports[0].id, 0, &learned) == -ENOENT);
    m = arp_request();
    struct rte_arp_hdr *update = rte_pktmbuf_mtod_offset(m, struct rte_arp_hdr *, 14);
    update->arp_data.arp_sha.addr_bytes[5] = 3;
    rte_pktmbuf_mtod(m, struct rte_ether_hdr *)->src_addr = update->arp_data.arp_sha;
    submit(m, DROP_NONE);
    assert(neighbour_lookup(&rt.neighbours, rt.ports[0].id, peer_ip, &learned) == 0 && learned.addr_bytes[5] == 3);
    m = arp_request();
    update = rte_pktmbuf_mtod_offset(m, struct rte_arp_hdr *, 14);
    update->arp_hlen = 5;
    submit(m, DROP_INVALID_ARP);
    assert(neighbour_lookup(&rt.neighbours, rt.ports[0].id, peer_ip, &learned) == 0 && learned.addr_bytes[5] == 3);
    m = arp_request();
    update = rte_pktmbuf_mtod_offset(m, struct rte_arp_hdr *, 14);
    update->arp_opcode = rte_cpu_to_be_16(RTE_ARP_OP_REPLY);
    update->arp_data.arp_tha = rt.ports[0].mac;
    submit(m, DROP_NONE);
    assert(neighbour_lookup(&rt.neighbours, rt.ports[0].id, peer_ip, &learned) == 0);
    assert(rte_is_same_ether_addr(&learned, &peer));

    for (unsigned payload = 0; payload <= 65; payload++) {
        unsigned before = captured_count;
        submit(echo(payload), DROP_NONE);
        assert(captured_count == before + 1);
        const struct rte_ipv4_hdr *ip = (const struct rte_ipv4_hdr *)(captured + 14);
        const struct rte_icmp_hdr *icmp = (const struct rte_icmp_hdr *)(ip + 1);
        assert(ip->src_addr == rt.ports[0].ip_be && ip->dst_addr == rte_cpu_to_be_32(RTE_IPV4(192u, 0, 2, 1)));
        assert(ip->time_to_live == 64 && rte_ipv4_cksum(ip) == 0);
        assert(icmp->icmp_type == RTE_IP_ICMP_ECHO_REPLY && rte_raw_cksum(icmp, 8 + payload) == UINT16_MAX);
        assert(icmp->icmp_ident == rte_cpu_to_be_16(123) && icmp->icmp_seq_nb == rte_cpu_to_be_16(456));
        for (unsigned i = 0; i < payload; i++) assert(((const uint8_t *)(icmp + 1))[i] == (uint8_t)(i + 1));
    }
    submit(packet(13, RTE_ETHER_TYPE_IPV4), DROP_TRUNCATED_ETH);
    submit(packet(14, RTE_ETHER_TYPE_ARP), DROP_INVALID_ARP);
    submit(packet(14, RTE_ETHER_TYPE_IPV4), DROP_INVALID_IPV4);
    submit(packet(60, RTE_ETHER_TYPE_IPV6), DROP_UNSUPPORTED_ETHERTYPE);
    m = arp_request(); rte_pktmbuf_mtod_offset(m, struct rte_arp_hdr *, 14)->arp_hlen = 5;
    submit(m, DROP_INVALID_ARP);
    m = arp_request(); rte_pktmbuf_mtod_offset(m, struct rte_arp_hdr *, 14)->arp_data.arp_tip = 0;
    submit(m, DROP_NOT_LOCAL);
    m = echo(0); ip_header(m)->version_ihl = 0x44; submit(m, DROP_INVALID_IPV4);
    m = echo(0); ip_header(m)->version_ihl = 0x65; submit(m, DROP_INVALID_IPV4);
    m = echo(0); ip_header(m)->hdr_checksum ^= 1; submit(m, DROP_INVALID_IPV4);
    m = echo(0); ip_header(m)->total_length = rte_cpu_to_be_16(100); ip_checksum(m); submit(m, DROP_INVALID_IPV4);
    m = echo(0); ip_header(m)->total_length = rte_cpu_to_be_16(19); ip_checksum(m); submit(m, DROP_INVALID_IPV4);
    m = echo(0); ip_header(m)->time_to_live = 0; ip_checksum(m); submit(m, DROP_INVALID_IPV4);
    m = echo(0); ip_header(m)->dst_addr = 0; ip_checksum(m); submit(m, DROP_FORWARDING_DISABLED);
    m = echo(0); ip_header(m)->src_addr = 0; ip_checksum(m); submit(m, DROP_INVALID_SOURCE);
    m = echo(0); ip_header(m)->fragment_offset = rte_cpu_to_be_16(RTE_IPV4_HDR_MF_FLAG); ip_checksum(m); submit(m, DROP_IPV4_FRAGMENT);
    m = echo(0); ip_header(m)->fragment_offset = rte_cpu_to_be_16(1); ip_checksum(m); submit(m, DROP_IPV4_FRAGMENT);
    m = echo(0); ip_header(m)->fragment_offset = rte_cpu_to_be_16(0x8000); ip_checksum(m); submit(m, DROP_INVALID_IPV4);
    m = echo(0); ip_header(m)->version_ihl = 0x46; ip_checksum(m); submit(m, DROP_IPV4_OPTIONS);
    m = echo(0); ip_header(m)->total_length = rte_cpu_to_be_16(27); ip_checksum(m); submit(m, DROP_INVALID_ICMP);
    m = echo(1); rte_pktmbuf_mtod_offset(m, uint8_t *, 42)[0] ^= 1; submit(m, DROP_INVALID_ICMP);
    m = echo(0); ip_header(m)->next_proto_id = IPPROTO_UDP; ip_checksum(m); submit(m, DROP_UDP_BAD_LENGTH);
    m = echo(0); ip_header(m)->next_proto_id = IPPROTO_TCP; ip_checksum(m); submit(m, DROP_UNSUPPORTED_PROTOCOL);
    m = echo(0); ip_header(m)->next_proto_id = 99; ip_checksum(m); submit(m, DROP_UNSUPPORTED_PROTOCOL);
    assert(rt.graph.nodes[NODE_UDP_INPUT].stats.packets == 1);
    assert(rt.graph.nodes[NODE_TCP_INPUT].stats.packets == 1);
    m = echo(1473); submit(m, DROP_MTU);
    m = echo(0);
    struct rte_mbuf *tail = packet(8, 0);
    assert(rte_pktmbuf_chain(m, tail) == 0);
    submit(m, DROP_NONCONTIGUOUS);

    udp_tests();

    tx_limit = 0;
    submit(echo(0), DROP_TX_FAILED);
    tx_limit = GRAPH_FRAME_SIZE / 2;
    struct node_frame burst = {.count = GRAPH_FRAME_SIZE};
    for (unsigned i = 0; i < GRAPH_FRAME_SIZE; i++) {
        burst.pkts[i] = echo(3);
        burst.ctxs[i].ingress_port_id = rt.ports[0].port_id;
    }
    uint64_t before = rt.graph.drop_reasons[DROP_TX_FAILED];
    assert(graph_submit(&rt, NODE_ETH_INPUT, &burst) == 0);
    assert(rt.graph.drop_reasons[DROP_TX_FAILED] == before + GRAPH_FRAME_SIZE / 2);

    /* Exhaustion must free the packet and account for the failed destination. */
    before = rt.graph.drop_reasons[DROP_GRAPH_FULL];
    for (unsigned i = 0; i < GRAPH_FRAME_POOL_SIZE; i++) rt.graph.slots[i].used = 1;
    struct node_output out = {.rt = &rt};
    for (unsigned i = 0; i < NODE_MAX; i++) out.pending[i] = UINT16_MAX;
    struct packet_ctx ctx = {0};
    assert(node_enqueue(&out, NODE_ETH_INPUT, echo(0), &ctx) == -1);
    assert(rt.graph.drop_reasons[DROP_GRAPH_FULL] == before + 1);
    for (unsigned i = 0; i < GRAPH_FRAME_POOL_SIZE; i++) rt.graph.slots[i].used = 0;
    assert(graph_submit(&rt, NODE_MAX, &burst) == -1);
    burst.count = GRAPH_FRAME_SIZE + 1;
    assert(graph_submit(&rt, NODE_ETH_INPUT, &burst) == -1);
    assert(rte_mempool_avail_count(rt.mbuf_pool) == 1023);
    multi_tests();
    assert(rte_eth_remove_tx_callback(rt.ports[0].port_id, 0, cb) == 0);
    rte_free((void *)cb); /* Single queue thread; no callback remains in flight. */
    rte_eth_dev_stop(rt.ports[0].port_id);
    rte_eth_dev_close(rt.ports[0].port_id);
    rte_mempool_free(rt.mbuf_pool);
    static struct app_runtime partial;
    struct app_config conf;
    app_config_defaults(&conf);
    conf.netif_count = 2;
    conf.interfaces[0] = (struct netif_config){ .pmd = PMD_PHYS, .device = "net_null_unused",
        .ip_be = rt.ports[0].ip_be, .prefix_len = 24 };
    conf.interfaces[1] = (struct netif_config){ .pmd = PMD_PHYS, .device = "missing" };
    uint16_t unused;
    assert(rte_eth_dev_get_port_by_name("net_null_unused", &unused) == 0);
    assert(port_init(&conf, &partial) == -1);
    assert(partial.ports[0].configured && partial.ports[0].started && partial.mbuf_pool);
    port_fini(&partial);
    assert(!partial.port_count && !partial.mbuf_pool);
    assert(!rte_eth_dev_is_valid_port(unused));
    assert(rte_eal_cleanup() == 0);
    puts("packet, graph, TX and ownership checks passed");
    return 0;
}
