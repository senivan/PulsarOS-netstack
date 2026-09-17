#include <errno.h>
#include "neighbour.h"

static uint32_t hash(uint32_t x)
{
    x ^= x >> 16;
    x *= 0x7feb352dU;
    x ^= x >> 15;
    x *= 0x846ca68bU;
    return x ^ (x >> 16);
}

int neighbour_learn(struct neighbour_table *table, uint16_t netif_id, uint32_t ip_be,
                    const struct rte_ether_addr *mac)
{
    if (!ip_be || !rte_is_valid_assigned_ether_addr(mac)) return -EINVAL;
    uint32_t start = hash(ip_be ^ netif_id) % NEIGHBOUR_CAPACITY;
    for (unsigned i = 0; i < NEIGHBOUR_CAPACITY; i++) {
        struct neighbour_entry *entry = &table->entries[(start + i) % NEIGHBOUR_CAPACITY];
        if (!entry->in_use || (entry->ip_be == ip_be && entry->netif_id == netif_id)) {
            *entry = (struct neighbour_entry){ .ip_be = ip_be, .netif_id = netif_id, .mac = *mac, .in_use = 1 };
            return 0;
        }
    }
    return -ENOSPC;
}

int neighbour_lookup(const struct neighbour_table *table, uint16_t netif_id, uint32_t ip_be,
                     struct rte_ether_addr *mac)
{
    uint32_t start = hash(ip_be ^ netif_id) % NEIGHBOUR_CAPACITY;
    for (unsigned i = 0; i < NEIGHBOUR_CAPACITY; i++) {
        const struct neighbour_entry *entry = &table->entries[(start + i) % NEIGHBOUR_CAPACITY];
        if (!entry->in_use) break;
        if (entry->ip_be == ip_be && entry->netif_id == netif_id) { *mac = entry->mac; return 0; }
    }
    return -ENOENT;
}
