#pragma once

#include <stdint.h>
#include "packet.h"

#define ROUTE_CAPACITY 32

struct app_runtime;
struct app_config;
struct route_entry {
    uint32_t prefix_be, gateway_be;
    uint16_t netif_id;
    uint8_t prefix_len;
};
struct route_table {
    struct route_entry entries[ROUTE_CAPACITY];
    uint16_t count;
};
struct route_result {
    uint16_t netif_id, mtu;
    uint32_t next_hop_be, source_ip_be;
};

int route_add(struct route_table *, uint32_t prefix_be, uint8_t prefix_len, uint16_t netif_id);
int route_add_gateway(struct route_table *, uint32_t prefix_be, uint8_t prefix_len,
                      uint16_t netif_id, uint32_t gateway_be);
int route_config_init(const struct app_config *, struct route_table *);
int route_is_direct(const struct route_table *, uint16_t netif_id, uint32_t ip_be);
int ipv4_destination_valid(const struct app_runtime *, uint32_t ip_be);
int route_init_connected(struct app_runtime *);
enum drop_reason ipv4_route_lookup(const struct app_runtime *, uint32_t dst_ip_be,
                                   struct route_result *);
