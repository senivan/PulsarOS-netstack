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
#define TARGET rte_cpu_to_be_32(RTE_IPV4(192u, 0, 2, 1))

static struct app_runtime rt;
static const struct rte_ether_addr peer[2] = {{{2, 0, 0, 0, 0, 1}}, {{2, 0, 0, 0, 1, 1}}};
static struct { uint16_t port, length; _Alignas(8) uint8_t data[1600]; } captures[64];
static unsigned capture_count;
static uint16_t tx_limit = UINT16_MAX;

static uint16_t capture(uint16_t port, uint16_t queue, struct rte_mbuf **packets,
                        uint16_t count, void *arg)
{
    (void)queue; (void)arg;
    uint16_t sent = count < tx_limit ? count : tx_limit;
    for (unsigned i = 0; i < sent; i++) {
        assert(capture_count < 64);
        captures[capture_count].port = port;
        captures[capture_count].length = rte_pktmbuf_pkt_len(packets[i]);
        assert(captures[capture_count].length <= sizeof(captures[0].data));
        memcpy(captures[capture_count++].data, rte_pktmbuf_mtod(packets[i], const void *), rte_pktmbuf_pkt_len(packets[i]));
    }
    return sent;
}

static struct pending_neighbour *pending(unsigned p, uint32_t target)
{
    for (unsigned i = 0; i < NEIGHBOUR_PENDING_MAX; i++) {
        struct pending_neighbour *entry = &rt.pending_neighbours.entries[i];
        if (entry->count && entry->netif_id == rt.ports[p].id && entry->ip_be == target) return entry;
    }
    return NULL;
}

static void reset(void)
{
    for (unsigned i = 0; i < NEIGHBOUR_PENDING_MAX; i++) assert(!rt.pending_neighbours.entries[i].count);
    assert(rte_mempool_avail_count(rt.mbuf_pool) == POOL_SIZE);
    memset(&rt.neighbours, 0, sizeof(rt.neighbours));
    assert(!rt.graph.q_count && !rt.active_output);
    capture_count = 0;
    tx_limit = UINT16_MAX;
}

static void send_udp(uint32_t target, int accepted)
{
    struct ps_addr dst = { .ip_be = target, .port = 9001 };
    assert(ps_udp_sendto(&rt, 9000, "arp-test", 8, &dst) == (accepted ? 8 : -EIO));
    assert(!rt.graph.q_count && !rt.active_output);
}

static void inject_arp(unsigned p, uint32_t target, int reply, int malformed)
{
    struct rte_mbuf *m = rte_pktmbuf_alloc(rt.mbuf_pool);
    assert(m);
    struct rte_ether_hdr *eth = (struct rte_ether_hdr *)rte_pktmbuf_append(m, 42);
    memset(eth, 0, 42);
    eth->src_addr = peer[p];
    eth->dst_addr = rt.ports[p].mac;
    eth->ether_type = rte_cpu_to_be_16(RTE_ETHER_TYPE_ARP);
    struct rte_arp_hdr *arp = (struct rte_arp_hdr *)(eth + 1);
    arp->arp_hardware = rte_cpu_to_be_16(RTE_ARP_HRD_ETHER);
    arp->arp_protocol = rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV4);
    arp->arp_hlen = malformed ? 5 : 6;
    arp->arp_plen = 4;
    arp->arp_opcode = rte_cpu_to_be_16(reply ? RTE_ARP_OP_REPLY : RTE_ARP_OP_REQUEST);
    arp->arp_data.arp_sha = peer[p];
    arp->arp_data.arp_sip = target;
    arp->arp_data.arp_tha = rt.ports[p].mac;
    arp->arp_data.arp_tip = rt.ports[p].ip_be;
    struct node_frame frame = { .count = 1 };
    frame.pkts[0] = m;
    frame.ctxs[0].ingress_port_id = rt.ports[p].port_id;
    assert(graph_submit(&rt, NODE_ETH_INPUT, &frame) == 0);
}

static void check_request(unsigned index, unsigned p, uint32_t target)
{
    assert(index < capture_count && captures[index].port == rt.ports[p].port_id);
    assert(captures[index].length == 60);
    const struct rte_ether_hdr *eth = (const struct rte_ether_hdr *)captures[index].data;
    const struct rte_arp_hdr *arp = (const struct rte_arp_hdr *)(eth + 1);
    assert(rte_is_broadcast_ether_addr(&eth->dst_addr));
    assert(rte_is_same_ether_addr(&eth->src_addr, &rt.ports[p].mac));
    assert(eth->ether_type == rte_cpu_to_be_16(RTE_ETHER_TYPE_ARP));
    assert(arp->arp_hardware == rte_cpu_to_be_16(RTE_ARP_HRD_ETHER));
    assert(arp->arp_protocol == rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV4));
    assert(arp->arp_hlen == 6 && arp->arp_plen == 4);
    assert(arp->arp_opcode == rte_cpu_to_be_16(RTE_ARP_OP_REQUEST));
    assert(rte_is_same_ether_addr(&arp->arp_data.arp_sha, &rt.ports[p].mac));
    assert(rte_is_zero_ether_addr(&arp->arp_data.arp_tha));
    assert(arp->arp_data.arp_sip == rt.ports[p].ip_be && arp->arp_data.arp_tip == target);
    for (unsigned i = 42; i < 60; i++) assert(!captures[index].data[i]);
}

static void basic_resolution(void)
{
    reset();
    uint64_t accepted = rt.accepted_sends;
    send_udp(TARGET, 1);
    assert(pending(0, TARGET)->count == 1 && capture_count == 1);
    check_request(0, 0, TARGET);
    uint64_t deadline = pending(0, TARGET)->last_request;
    send_udp(TARGET, 1);
    send_udp(TARGET, 1);
    assert(capture_count == 1 && pending(0, TARGET)->count == 3);
    assert(pending(0, TARGET)->last_request == deadline);
    assert(rte_mempool_avail_count(rt.mbuf_pool) == POOL_SIZE - 3);
    inject_arp(0, TARGET, 1, 1);
    assert(capture_count == 1 && pending(0, TARGET)->count == 3);
    inject_arp(0, TARGET, 1, 0);
    assert(!pending(0, TARGET) && capture_count == 4);
    assert(rt.accepted_sends == accepted + 3);
    for (unsigned i = 1; i < capture_count; i++) {
        const struct rte_ether_hdr *eth = (const struct rte_ether_hdr *)captures[i].data;
        const struct rte_ipv4_hdr *ip = (const struct rte_ipv4_hdr *)(eth + 1);
        const struct rte_udp_hdr *udp = (const struct rte_udp_hdr *)(ip + 1);
        assert(captures[i].port == rt.ports[0].port_id);
        assert(rte_is_same_ether_addr(&eth->src_addr, &rt.ports[0].mac));
        assert(rte_is_same_ether_addr(&eth->dst_addr, &peer[0]));
        assert(ip->dst_addr == TARGET && ip->src_addr == rt.ports[0].ip_be);
        assert(rte_ipv4_cksum(ip) == 0);
        assert(udp->src_port == rte_cpu_to_be_16(9000) && udp->dst_port == rte_cpu_to_be_16(9001));
        assert(udp->dgram_len == rte_cpu_to_be_16(16) && udp->dgram_cksum);
        assert(rte_ipv4_udptcp_cksum(ip, udp) == UINT16_MAX);
        assert(!memcmp(udp + 1, "arp-test", 8));
    }
    reset();
    send_udp(TARGET, 1);
    inject_arp(0, TARGET, 0, 0);
    assert(!pending(0, TARGET) && capture_count == 3);
    reset();
}

static void retry_timeout(void)
{
    send_udp(TARGET, 1);
    send_udp(TARGET, 1);
    uint64_t start = pending(0, TARGET)->last_request;
    uint64_t interval = rte_get_timer_hz() * ARP_RETRY_SECONDS;
    neighbour_tick(&rt, start + interval - 1);
    assert(capture_count == 1);
    for (unsigned i = 1; i < ARP_MAX_REQUESTS; i++) {
        neighbour_tick(&rt, start + interval * i);
        assert(capture_count == i + 1);
        check_request(i, 0, TARGET);
    }
    uint64_t before = rt.graph.drop_reasons[DROP_NEIGHBOUR_RESOLUTION_TIMEOUT];
    neighbour_tick(&rt, start + interval * ARP_MAX_REQUESTS);
    assert(!pending(0, TARGET) && capture_count == ARP_MAX_REQUESTS);
    assert(rt.graph.drop_reasons[DROP_NEIGHBOUR_RESOLUTION_TIMEOUT] == before + 2);
    assert(rte_mempool_avail_count(rt.mbuf_pool) == POOL_SIZE);
    send_udp(TARGET, 1);
    assert(pending(0, TARGET)->requests == 1 && capture_count == ARP_MAX_REQUESTS + 1);
    neighbour_fini(&rt);
    neighbour_fini(&rt);
    reset();
}

static void capacities(void)
{
    for (unsigned i = 0; i < NEIGHBOUR_PENDING_QUEUE_MAX; i++) send_udp(TARGET, 1);
    uint64_t before = rt.graph.drop_reasons[DROP_NEIGHBOUR_QUEUE_FULL];
    send_udp(TARGET, 0);
    assert(rt.graph.drop_reasons[DROP_NEIGHBOUR_QUEUE_FULL] == before + 1);
    assert(capture_count == 1 && pending(0, TARGET)->count == NEIGHBOUR_PENDING_QUEUE_MAX);
    inject_arp(0, TARGET, 1, 0);
    assert(capture_count == NEIGHBOUR_PENDING_QUEUE_MAX + 1);
    reset();
    for (unsigned i = 0; i < NEIGHBOUR_PENDING_MAX; i++)
        send_udp(rte_cpu_to_be_32(RTE_IPV4(192u, 0, 2, 10) + i), 1);
    before = rt.graph.drop_reasons[DROP_NEIGHBOUR_PENDING_FULL];
    send_udp(TARGET, 0);
    assert(rt.graph.drop_reasons[DROP_NEIGHBOUR_PENDING_FULL] == before + 1);
    assert(capture_count == NEIGHBOUR_PENDING_MAX && !pending(0, TARGET));
    before = rt.graph.drop_reasons[DROP_NEIGHBOUR_CANCELLED];
    neighbour_fini(&rt);
    assert(rt.graph.drop_reasons[DROP_NEIGHBOUR_CANCELLED] == before + NEIGHBOUR_PENDING_MAX);
    reset();
}

static void interface_scope(void)
{
    send_udp(TARGET, 1);
    struct node_frame frame = { .count = 1 };
    frame.pkts[0] = rte_pktmbuf_alloc(rt.mbuf_pool);
    assert(frame.pkts[0]);
    struct rte_ipv4_hdr *ip = (struct rte_ipv4_hdr *)rte_pktmbuf_append(frame.pkts[0], sizeof(*ip));
    memset(ip, 0, sizeof(*ip));
    ip->dst_addr = rte_cpu_to_be_32(RTE_IPV4(203u, 0, 113, 8));
    frame.ctxs[0].dst_ip_be = ip->dst_addr;
    frame.ctxs[0].next_hop_ip_be = TARGET;
    frame.ctxs[0].egress_port_id = rt.ports[1].port_id;
    assert(graph_submit(&rt, NODE_ETH_OUTPUT, &frame) == 0);
    assert(pending(0, TARGET) && pending(1, TARGET));
    check_request(1, 1, TARGET);
    inject_arp(0, TARGET, 1, 0);
    assert(!pending(0, TARGET) && pending(1, TARGET) && capture_count == 3);
    inject_arp(1, TARGET, 1, 0);
    assert(!pending(1, TARGET) && capture_count == 4);
    const struct rte_ether_hdr *eth = (const struct rte_ether_hdr *)captures[3].data;
    ip = (struct rte_ipv4_hdr *)(captures[3].data + sizeof(*eth));
    assert(captures[3].port == rt.ports[1].port_id);
    assert(rte_is_same_ether_addr(&eth->dst_addr, &peer[1]));
    assert(ip->dst_addr == rte_cpu_to_be_32(RTE_IPV4(203u, 0, 113, 8)));
    reset();
}

static void failure_ownership(void)
{
    tx_limit = 0;
    uint64_t before = rt.graph.drop_reasons[DROP_TX_FAILED];
    send_udp(TARGET, 1);
    assert(rt.graph.drop_reasons[DROP_TX_FAILED] == before + 1 && pending(0, TARGET));
    tx_limit = UINT16_MAX;
    neighbour_tick(&rt, pending(0, TARGET)->last_request + rte_get_timer_hz() * ARP_RETRY_SECONDS);
    assert(capture_count == 1);
    tx_limit = 0;
    inject_arp(0, TARGET, 1, 0);
    assert(!pending(0, TARGET) && rt.graph.drop_reasons[DROP_TX_FAILED] == before + 2);
    reset();
    for (unsigned i = 0; i < 3; i++) send_udp(TARGET, 1);
    uint64_t accepted = rt.accepted_sends;
    tx_limit = 1;
    before = rt.graph.drop_reasons[DROP_TX_FAILED];
    inject_arp(0, TARGET, 1, 0);
    assert(!pending(0, TARGET) && capture_count == 2);
    assert(rt.graph.drop_reasons[DROP_TX_FAILED] == before + 2);
    assert(rt.accepted_sends == accepted);
    reset();

    struct rte_mbuf *held[POOL_SIZE - 1];
    for (unsigned i = 0; i < POOL_SIZE - 1; i++) { held[i] = rte_pktmbuf_alloc(rt.mbuf_pool); assert(held[i]); }
    before = rt.graph.drop_reasons[DROP_MBUF_ALLOCATION_FAILED];
    send_udp(TARGET, 1);
    assert(!capture_count && pending(0, TARGET));
    assert(rt.graph.drop_reasons[DROP_MBUF_ALLOCATION_FAILED] == before + 1);
    for (unsigned i = 0; i < POOL_SIZE - 1; i++) rte_pktmbuf_free(held[i]);
    neighbour_tick(&rt, pending(0, TARGET)->last_request + rte_get_timer_hz() * ARP_RETRY_SECONDS);
    assert(capture_count == 1);
    inject_arp(0, TARGET, 1, 0);
    reset();

    send_udp(TARGET, 1);
    for (unsigned i = 0; i < GRAPH_FRAME_POOL_SIZE; i++) rt.graph.slots[i].used = 1;
    before = rt.graph.drop_reasons[DROP_GRAPH_FULL];
    assert(neighbour_update(&rt, rt.ports[0].id, TARGET, &peer[0]) == 0);
    assert(rt.graph.drop_reasons[DROP_GRAPH_FULL] == before + 1 && !pending(0, TARGET));
    for (unsigned i = 0; i < GRAPH_FRAME_POOL_SIZE; i++) rt.graph.slots[i].used = 0;
    reset();
    send_udp(TARGET, 1);
    rt.ports[0].started = 0;
    before = rt.graph.drop_reasons[DROP_INVALID_EGRESS];
    neighbour_tick(&rt, rte_get_timer_cycles());
    assert(rt.graph.drop_reasons[DROP_INVALID_EGRESS] == before + 1 && !pending(0, TARGET));
    rt.ports[0].started = 1;
    reset();

    for (unsigned i = 0; i < NEIGHBOUR_CAPACITY; i++)
        assert(neighbour_learn(&rt.neighbours, rt.ports[0].id,
               rte_cpu_to_be_32(RTE_IPV4(10u, 0, 0, 1) + i), &peer[0]) == 0);
    send_udp(TARGET, 1);
    before = rt.neighbour_learn_failures;
    inject_arp(0, TARGET, 1, 0);
    assert(pending(0, TARGET) && rt.neighbour_learn_failures == before + 1);
    uint64_t start = pending(0, TARGET)->last_request;
    for (unsigned i = 1; i <= ARP_MAX_REQUESTS; i++)
        neighbour_tick(&rt, start + rte_get_timer_hz() * ARP_RETRY_SECONDS * i);
    assert(!pending(0, TARGET));
    reset();

    static struct app_runtime partial;
    partial.pending_neighbours.entries[0].count = 1;
    partial.pending_neighbours.entries[0].packets[0] = rte_pktmbuf_alloc(rt.mbuf_pool);
    assert(partial.pending_neighbours.entries[0].packets[0]);
    neighbour_fini(&partial);
    neighbour_fini(&partial);
    assert(partial.graph.drop_reasons[DROP_NEIGHBOUR_CANCELLED] == 1);
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
    char *args[] = {"test-resolution", "--lcores", core, "--no-huge", "--no-pci", "--no-shconf",
        "--no-telemetry", "--vdev=net_null0", "--vdev=net_null1", NULL};
    assert(rte_eal_init(9, args) >= 0);
    rt.mbuf_pool = rte_pktmbuf_pool_create("resolution_pool", POOL_SIZE, 0, 0, RTE_MBUF_DEFAULT_BUF_SIZE, rte_socket_id());
    assert(rt.mbuf_pool);
    rt.port_count = 2;
    const struct rte_eth_rxtx_callback *callbacks[2];
    for (unsigned i = 0; i < 2; i++) {
        struct port_state *port = &rt.ports[i];
        char name[32];
        snprintf(name, sizeof(name), "net_null%u", i);
        assert(rte_eth_dev_get_port_by_name(name, &port->port_id) == 0);
        port->id = i ? 42 : 11;
        port->ip_be = rte_cpu_to_be_32(RTE_IPV4(192u, 0, 2, 2) + i);
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
    assert(route_init_connected(&rt) == 0 && graph_init(&rt) == 0);
    assert(ps_udp_bind(&rt, 9000) == 0);
    basic_resolution();
    retry_timeout();
    capacities();
    interface_scope();
    failure_ownership();
    send_udp(TARGET, 1);
    neighbour_fini(&rt);
    reset();
    for (unsigned i = 0; i < 2; i++) {
        assert(rte_eth_remove_tx_callback(rt.ports[i].port_id, 0, callbacks[i]) == 0);
        rte_free((void *)callbacks[i]);
    }
    send_udp(TARGET, 1);
    app_fini(&rt);
    assert(!rt.mbuf_pool && !pending(0, TARGET));
    puts("active ARP, shared queues, scoping, retries, timeout, capacity and ownership passed");
    return 0;
}
