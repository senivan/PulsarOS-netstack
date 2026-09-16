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
#include "runtime.h"

static struct app_runtime rt;
static const struct rte_ether_addr peer = {{2, 0, 0, 0, 0, 1}};
static _Alignas(8) uint8_t captured[2048];
static uint16_t captured_len, tx_limit = UINT16_MAX;
static unsigned captured_count;

static uint16_t capture(uint16_t port, uint16_t queue, struct rte_mbuf **pkts,
                        uint16_t count, void *arg)
{
    (void)port; (void)queue; (void)arg;
    uint16_t sent = count < tx_limit ? count : tx_limit;
    for (uint16_t i = 0; i < sent; i++) {
        captured_len = rte_pktmbuf_pkt_len(pkts[i]);
        assert(captured_len <= sizeof(captured));
        memcpy(captured, rte_pktmbuf_mtod(pkts[i], const void *), captured_len);
        assert(pkts[i]->ol_flags == 0 && pkts[i]->tx_offload == 0);
        captured_count++;
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
        eth->dst_addr = rt.port.mac;
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
    arp->arp_data.arp_sip = rte_cpu_to_be_32(RTE_IPV4(192, 0, 2, 1));
    arp->arp_data.arp_tip = rt.port.ip_be;
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
    ip->src_addr = rte_cpu_to_be_32(RTE_IPV4(192, 0, 2, 1));
    ip->dst_addr = rt.port.ip_be;
    struct rte_icmp_hdr *icmp = (struct rte_icmp_hdr *)(ip + 1);
    icmp->icmp_type = RTE_IP_ICMP_ECHO_REQUEST;
    icmp->icmp_ident = rte_cpu_to_be_16(123);
    icmp->icmp_seq_nb = rte_cpu_to_be_16(456);
    for (unsigned i = 0; i < payload; i++) ((uint8_t *)(icmp + 1))[i] = (uint8_t)(i + 1);
    icmp->icmp_cksum = (uint16_t)~rte_raw_cksum(icmp, 8 + payload);
    ip_checksum(m);
    return m;
}

static void submit(struct rte_mbuf *m, enum drop_reason reason)
{
    uint64_t before = rt.graph.drop_reasons[reason];
    unsigned tx_before = captured_count;
    struct node_frame frame = { .count = 1 };
    frame.pkts[0] = m;
    frame.ctxs[0].ingress_port_id = rt.port.port_id;
    assert(graph_submit(&rt, NODE_ETH_INPUT, &frame) == 0);
    assert(rt.graph.q_count == 0 && rt.active_output == NULL);
    for (unsigned i = 0; i < GRAPH_FRAME_POOL_SIZE; i++) assert(!rt.graph.slots[i].used);
    if (reason != DROP_NONE) {
        assert(rt.graph.drop_reasons[reason] == before + 1);
        assert(captured_count == tx_before);
    }
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
                     "--no-shconf", "--no-telemetry", "--vdev=net_null0", NULL };
    assert(rte_eal_init(8, argv) >= 0);
    rt.mbuf_pool = rte_pktmbuf_pool_create("test_pool", 1023, 0, 0, RTE_MBUF_DEFAULT_BUF_SIZE, rte_socket_id());
    assert(rt.mbuf_pool);
    assert(rte_eth_dev_get_port_by_name("net_null0", &rt.port.port_id) == 0);
    struct rte_eth_conf ec = {0};
    assert(rte_eth_dev_configure(rt.port.port_id, 1, 1, &ec) == 0);
    assert(rte_eth_rx_queue_setup(rt.port.port_id, 0, 128, rte_socket_id(), NULL, rt.mbuf_pool) == 0);
    assert(rte_eth_tx_queue_setup(rt.port.port_id, 0, 128, rte_socket_id(), NULL) == 0);
    assert(rte_eth_dev_start(rt.port.port_id) == 0);
    rt.port.mac = (struct rte_ether_addr){{2, 0, 0, 0, 0, 2}};
    rt.port.ip_be = rte_cpu_to_be_32(RTE_IPV4(192, 0, 2, 2));
    rt.port.prefix_len = 24;
    rt.port.mtu = 1500;
    const struct rte_eth_rxtx_callback *cb = rte_eth_add_tx_callback(rt.port.port_id, 0, capture, NULL);
    assert(cb && graph_init(&rt) == 0);

    struct neighbour_table table = {0};
    struct rte_ether_addr learned;
    assert(neighbour_lookup(&table, 1, &learned) == -ENOENT);
    for (unsigned i = 1; i <= NEIGHBOUR_CAPACITY; i++)
        assert(neighbour_learn(&table, rte_cpu_to_be_32(i), &peer) == 0);
    assert(neighbour_learn(&table, rte_cpu_to_be_32(NEIGHBOUR_CAPACITY + 1), &peer) == -ENOSPC);
    assert(neighbour_learn(&table, rte_cpu_to_be_32(1), &rt.port.mac) == 0);
    assert(neighbour_lookup(&table, rte_cpu_to_be_32(1), &learned) == 0);
    assert(rte_is_same_ether_addr(&learned, &rt.port.mac));

    submit(arp_request(), DROP_NONE);
    uint32_t peer_ip = rte_cpu_to_be_32(RTE_IPV4(192, 0, 2, 1));
    assert(neighbour_lookup(&rt.neighbours, peer_ip, &learned) == 0);
    assert(rte_is_same_ether_addr(&learned, &peer));
    assert(captured_count == 1 && captured_len == 60);
    const struct rte_ether_hdr *eth = (const struct rte_ether_hdr *)captured;
    const struct rte_arp_hdr *arp = (const struct rte_arp_hdr *)(eth + 1);
    assert(rte_is_same_ether_addr(&eth->src_addr, &rt.port.mac));
    assert(rte_is_same_ether_addr(&eth->dst_addr, &peer));
    assert(arp->arp_opcode == rte_cpu_to_be_16(RTE_ARP_OP_REPLY));
    assert(arp->arp_data.arp_sip == rt.port.ip_be);
    assert(arp->arp_data.arp_tip == rte_cpu_to_be_32(RTE_IPV4(192, 0, 2, 1)));
    for (unsigned i = 42; i < 60; i++) assert(captured[i] == 0);
    struct rte_mbuf *m = arp_request();
    rte_pktmbuf_mtod_offset(m, struct rte_arp_hdr *, 14)->arp_data.arp_sip = 0;
    submit(m, DROP_NONE);
    assert(arp->arp_data.arp_tip == 0); /* RFC 5227 probe. */
    assert(neighbour_lookup(&rt.neighbours, 0, &learned) == -ENOENT);
    m = arp_request();
    struct rte_arp_hdr *update = rte_pktmbuf_mtod_offset(m, struct rte_arp_hdr *, 14);
    update->arp_data.arp_sha.addr_bytes[5] = 3;
    rte_pktmbuf_mtod(m, struct rte_ether_hdr *)->src_addr = update->arp_data.arp_sha;
    submit(m, DROP_NONE);
    assert(neighbour_lookup(&rt.neighbours, peer_ip, &learned) == 0 && learned.addr_bytes[5] == 3);
    m = arp_request();
    update = rte_pktmbuf_mtod_offset(m, struct rte_arp_hdr *, 14);
    update->arp_hlen = 5;
    submit(m, DROP_INVALID_ARP);
    assert(neighbour_lookup(&rt.neighbours, peer_ip, &learned) == 0 && learned.addr_bytes[5] == 3);
    m = arp_request();
    update = rte_pktmbuf_mtod_offset(m, struct rte_arp_hdr *, 14);
    update->arp_opcode = rte_cpu_to_be_16(RTE_ARP_OP_REPLY);
    update->arp_data.arp_tha = rt.port.mac;
    submit(m, DROP_NONE);
    assert(neighbour_lookup(&rt.neighbours, peer_ip, &learned) == 0);
    assert(rte_is_same_ether_addr(&learned, &peer));

    for (unsigned payload = 0; payload <= 65; payload++) {
        unsigned before = captured_count;
        submit(echo(payload), DROP_NONE);
        assert(captured_count == before + 1);
        const struct rte_ipv4_hdr *ip = (const struct rte_ipv4_hdr *)(captured + 14);
        const struct rte_icmp_hdr *icmp = (const struct rte_icmp_hdr *)(ip + 1);
        assert(ip->src_addr == rt.port.ip_be && ip->dst_addr == rte_cpu_to_be_32(RTE_IPV4(192, 0, 2, 1)));
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
    m = echo(0); ip_header(m)->dst_addr = 0; ip_checksum(m); submit(m, DROP_NOT_LOCAL);
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

    tx_limit = 0;
    submit(echo(0), DROP_TX_FAILED);
    tx_limit = GRAPH_FRAME_SIZE / 2;
    struct node_frame burst = {.count = GRAPH_FRAME_SIZE};
    for (unsigned i = 0; i < GRAPH_FRAME_SIZE; i++) {
        burst.pkts[i] = echo(3);
        burst.ctxs[i].ingress_port_id = rt.port.port_id;
    }
    uint64_t before = rt.graph.drop_reasons[DROP_TX_FAILED];
    assert(graph_submit(&rt, NODE_ETH_INPUT, &burst) == 0);
    assert(rt.graph.drop_reasons[DROP_TX_FAILED] == before + GRAPH_FRAME_SIZE / 2);

    /* Exhaustion must free the packet and account for the failed destination. */
    for (unsigned i = 0; i < GRAPH_FRAME_POOL_SIZE; i++) rt.graph.slots[i].used = 1;
    struct node_output out = {.rt = &rt};
    for (unsigned i = 0; i < NODE_MAX; i++) out.pending[i] = UINT16_MAX;
    struct packet_ctx ctx = {0};
    assert(node_enqueue(&out, NODE_ETH_INPUT, echo(0), &ctx) == -1);
    assert(rt.graph.drop_reasons[DROP_GRAPH_FULL] == 1);
    for (unsigned i = 0; i < GRAPH_FRAME_POOL_SIZE; i++) rt.graph.slots[i].used = 0;
    assert(graph_submit(&rt, NODE_MAX, &burst) == -1);
    burst.count = GRAPH_FRAME_SIZE + 1;
    assert(graph_submit(&rt, NODE_ETH_INPUT, &burst) == -1);
    assert(rte_mempool_avail_count(rt.mbuf_pool) == 1023);
    assert(rte_eth_remove_tx_callback(rt.port.port_id, 0, cb) == 0);
    rte_free((void *)cb); /* Single queue thread; no callback remains in flight. */
    rte_eth_dev_stop(rt.port.port_id);
    rte_eth_dev_close(rt.port.port_id);
    rte_mempool_free(rt.mbuf_pool);
    assert(rte_eal_cleanup() == 0);
    puts("packet, graph, TX and ownership checks passed");
    return 0;
}
