#pragma once

#include <stdint.h>
#include <rte_ether.h>

#define NEIGHBOUR_CAPACITY 64

struct neighbour_entry {
    uint32_t ip_be;
    struct rte_ether_addr mac;
    uint8_t in_use;
};

struct neighbour_table { struct neighbour_entry entries[NEIGHBOUR_CAPACITY]; };

/* Zero-initialize the table. Full tables reject new keys but permit updates. */
int neighbour_learn(struct neighbour_table *, uint32_t ip_be, const struct rte_ether_addr *);
int neighbour_lookup(const struct neighbour_table *, uint32_t ip_be, struct rte_ether_addr *);
