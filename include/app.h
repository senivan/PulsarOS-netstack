#pragma once

#include <stdint.h>
#include "constants.h"
#include "route.h"

enum app_pmd { PMD_TAP, PMD_AFPKT, PMD_PHYS };

#define NETIF_MAX 8

struct netif_config {
    enum app_pmd pmd;
    char device[64]; /* Interface name for virtual PMDs; PCI BDF for physical. */
    uint32_t ip_be;
    uint8_t prefix_len;
};

struct route_config {
    uint32_t prefix_be, gateway_be;
    uint8_t prefix_len;
    char device[64];
};

struct app_config {
    unsigned lcore;
    uint16_t netif_count;
    struct netif_config interfaces[NETIF_MAX];
    uint8_t no_huge;
    uint8_t ipv4_forwarding;
    uint16_t route_count;
    struct route_config routes[ROUTE_CAPACITY];
    uint32_t mbufs, mbuf_cache;
    uint16_t rx_desc, tx_desc;
};
