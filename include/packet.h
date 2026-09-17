#pragma once

#include <stdint.h>

enum drop_reason {
    DROP_NONE, DROP_PORT_BINDING, DROP_TRUNCATED_ETH, DROP_UNSUPPORTED_ETHERTYPE,
    DROP_INVALID_ARP, DROP_INVALID_IPV4, DROP_IPV4_FRAGMENT, DROP_NOT_LOCAL,
    DROP_IPV4_OPTIONS, DROP_INVALID_ICMP, DROP_UNSUPPORTED_ICMP,
    DROP_UNSUPPORTED_PROTOCOL, DROP_GRAPH_FULL, DROP_TX_FAILED,
    DROP_MTU, DROP_NO_TAILROOM, DROP_NONCONTIGUOUS, DROP_INVALID_SOURCE,
    DROP_NEIGHBOUR_NOT_FOUND, DROP_INVALID_DESTINATION,
    DROP_INVALID_UDP, DROP_UDP_BAD_LENGTH, DROP_UDP_BAD_CHECKSUM,
    DROP_UDP_UNBOUND_PORT, DROP_UDP_RX_QUEUE_FULL,
    DROP_MBUF_ALLOCATION_FAILED, DROP_NO_HEADROOM,
    DROP_NO_ROUTE, DROP_INVALID_EGRESS, DROP_FORWARDING_DISABLED,
    DROP_REASON_MAX
};

struct packet_ctx {
    uint16_t ingress_port_id, egress_port_id; /* DPDK port IDs, not interface indices. */
    uint16_t l3_offset, l4_offset;
    uint32_t src_ip_be, dst_ip_be, next_hop_ip_be;
    uint16_t src_port, dst_port; /* Host order, for locally generated UDP. */
    uint8_t ip_protocol;
    uint8_t drop_reason;
};
