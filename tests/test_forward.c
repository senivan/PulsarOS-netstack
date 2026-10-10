#define _GNU_SOURCE
#include <assert.h>
#include <sched.h>
#include <stdio.h>
#include <string.h>
#include <rte_arp.h>
#include <rte_cycles.h>
#include <rte_eal.h>
#include <rte_ip.h>
#include <rte_malloc.h>
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
    assert(ip->src_addr == netif_by_dpdk_port(&rt, port)->ip_be && ip->dst_addr == destination);
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
