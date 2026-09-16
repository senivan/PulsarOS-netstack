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

/* Copy into a new packet and synchronously submit it to the output graph.
 * Success means accepted by DPDK, not delivery confirmation. -EIO means a
 * graph/output/TX rejection; the specific cause is in the drop-reason counters.
 * -ENOMEM and -EMSGSIZE are reported before graph submission. A bound source
 * port and a nonzero destination port are required. Never call inside a node. */
ssize_t ps_udp_sendto(struct app_runtime *rt, uint16_t source_port, const void *buf,
                      size_t len, const struct ps_addr *dst);
