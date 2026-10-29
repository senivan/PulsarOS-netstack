#include <errno.h>
#include "runtime.h"
#include "admin.h"

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
    struct neighbour_entry *empty = NULL;
    uint32_t start = hash(ip_be ^ netif_id) % NEIGHBOUR_CAPACITY;
    for (unsigned i = 0; i < NEIGHBOUR_CAPACITY; i++) {
        struct neighbour_entry *entry = &table->entries[(start + i) % NEIGHBOUR_CAPACITY];
        if (!entry->in_use) { if (!empty) empty = entry; continue; }
        if (entry->ip_be == ip_be && entry->netif_id == netif_id) {
            if (!entry->permanent) entry->mac = *mac;
            return 0;
        }
    }
    if (empty) {
        *empty = (struct neighbour_entry){ .ip_be = ip_be, .netif_id = netif_id, .mac = *mac, .in_use = 1 };
        return 0;
    }
    return -ENOSPC;
}

int neighbour_lookup(const struct neighbour_table *table, uint16_t netif_id, uint32_t ip_be,
                     struct rte_ether_addr *mac)
{
    uint32_t start = hash(ip_be ^ netif_id) % NEIGHBOUR_CAPACITY;
    for (unsigned i = 0; i < NEIGHBOUR_CAPACITY; i++) {
        const struct neighbour_entry *entry = &table->entries[(start + i) % NEIGHBOUR_CAPACITY];
        if (!entry->in_use) continue;
        if (entry->ip_be == ip_be && entry->netif_id == netif_id) { *mac = entry->mac; return 0; }
    }
    return -ENOENT;
}

int neighbour_set(struct app_runtime *rt, uint16_t dev, uint32_t ip, const struct rte_ether_addr *mac, int replace)
{
    if (!netif_by_id(rt, dev) || !ipv4_destination_valid(rt, ip) || !rte_is_valid_assigned_ether_addr(mac)) return -EINVAL;
    struct neighbour_entry *empty = NULL, *found = NULL;
    for (unsigned i = 0; i < NEIGHBOUR_CAPACITY; i++) {
        struct neighbour_entry *e = &rt->neighbours.entries[i];
        if (!e->in_use) { if (!empty) empty = e; }
        else if (e->ip_be == ip && e->netif_id == dev) found = e;
    }
    if (found && !replace) return -EEXIST;
    if (!found) found = empty;
    if (!found) return -ENOSPC;
    *found = (struct neighbour_entry){ .ip_be = ip, .netif_id = dev, .mac = *mac, .in_use = 1, .permanent = 1 };
    admin_neighbour_event(rt, dev, ip, replace ? ADM_REPLACE : ADM_ADD);
    return neighbour_update(rt, dev, ip, mac);
}
int neighbour_delete(struct app_runtime *rt, uint16_t dev, uint32_t ip)
{
    for (unsigned i = 0; i < NEIGHBOUR_CAPACITY; i++) {
        struct neighbour_entry *e = &rt->neighbours.entries[i];
        if (!e->in_use || e->netif_id != dev || e->ip_be != ip) continue;
        *e = (struct neighbour_entry){0};
        admin_neighbour_event(rt, dev, ip, ADM_DEL);
        neighbour_cancel(rt, dev, ip);
        return 0;
    }
    return -ENOENT;
}
