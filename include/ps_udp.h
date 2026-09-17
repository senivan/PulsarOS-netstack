#pragma once

#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

struct app_runtime;

#define PS_UDP_MAX_ENDPOINTS 8
#define PS_UDP_RX_QUEUE_SIZE 16
#define PS_UDP_MAX_PAYLOAD 1472

/* IPv4 is in network byte order; ports are in host byte order. */
struct ps_addr { uint32_t ip_be; uint16_t port; };

/* Single runtime/lcore only. Port zero and duplicate binds are rejected. */
int ps_udp_bind(struct app_runtime *rt, uint16_t port);

/* Nonblocking: -EAGAIN when empty. -EMSGSIZE leaves the datagram queued.
 * A zero return consumes a zero-length datagram. Other errors are negative errno.
 * The caller owns buf; the stack never retains it. */
ssize_t ps_udp_recvfrom(struct app_runtime *rt, uint16_t port, void *buf,
                        size_t len, struct ps_addr *src);

/* Copies buf; success means accepted by TX or queued for neighbour resolution.
 * Queued packets may later time out. Errors are negative errno.
 * For -EIO, see drop-reason counters. Call between app_step() calls. */
ssize_t ps_udp_sendto(struct app_runtime *rt, uint16_t source_port, const void *buf,
                      size_t len, const struct ps_addr *dst);
