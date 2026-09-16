#pragma once

#include "ps_udp.h"

/* Protocol/application handoff. No mbuf is retained by an endpoint. */
struct udp_datagram {
    struct ps_addr source;
    uint16_t length;
    uint8_t payload[PS_UDP_MAX_PAYLOAD];
};

struct udp_endpoint {
    uint16_t port, head, count;
    struct udp_datagram queue[PS_UDP_RX_QUEUE_SIZE];
};

struct udp_endpoints { struct udp_endpoint entries[PS_UDP_MAX_ENDPOINTS]; };

int udp_deliver(struct app_runtime *, uint16_t port, const struct ps_addr *,
                const void *payload, size_t len);
