#pragma once

#include "ps_socket.h"

struct app_runtime;
struct ps_socket_entry;

struct udp_datagram {
    struct ps_sockaddr source;
    uint16_t length;
    uint8_t payload[PS_DGRAM_MAX_PAYLOAD];
};

struct udp_endpoint {
    uint16_t head, count;
    struct udp_datagram queue[PS_DGRAM_QUEUE_SIZE];
};

int udp_deliver(struct app_runtime *, uint32_t local_ip_be, uint16_t port, const struct ps_sockaddr *,
                const void *payload, size_t len);
ssize_t udp_recv(struct ps_socket_entry *, void *, size_t, struct ps_sockaddr *);
ssize_t udp_send(struct app_runtime *, struct ps_socket_entry *, const void *, size_t,
                 const struct ps_sockaddr *);
