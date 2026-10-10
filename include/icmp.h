#pragma once

#include <stdint.h>

#define ICMP_ERROR_RATE 10
#define ICMP_ERROR_BURST 10

struct app_runtime;
struct rte_mbuf;
struct packet_ctx;
struct icmp_error_state {
    uint64_t generated, suppressed, rate_limited, failed;
    uint64_t last_refill;
    uint32_t tokens;
    uint8_t initialized;
};

/* Borrows the original packet; the caller retains ownership. */
void icmp_send_error(struct app_runtime *, const struct rte_mbuf *, const struct packet_ctx *,
                     uint8_t type, uint8_t code, uint16_t mtu, uint64_t now);
