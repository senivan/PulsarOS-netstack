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

static struct neighbour_entry *find_slot(struct neighbour_table *table, uint16_t dev, uint32_t ip)
{
    uint32_t start = hash(ip ^ dev) % NEIGHBOUR_CAPACITY;
    for (unsigned i = 0; i < NEIGHBOUR_CAPACITY; i++) {
        struct neighbour_entry *e = &table->entries[(start+i) % NEIGHBOUR_CAPACITY];
        if (!e->in_use || (e->ip_be == ip && e->netif_id == dev)) return e;
    }
    return NULL;
}

int neighbour_learn(struct neighbour_table *table, uint16_t netif_id, uint32_t ip_be,
                    const struct rte_ether_addr *mac)
{
    if (!ip_be || !rte_is_valid_assigned_ether_addr(mac)) return -EINVAL;
    struct neighbour_entry *entry = find_slot(table, netif_id, ip_be);
    if (!entry) return -ENOSPC;
    if (!entry->in_use)
        *entry = (struct neighbour_entry){ .ip_be=ip_be, .netif_id=netif_id, .mac=*mac, .in_use=1 };
    else if (!entry->permanent) entry->mac = *mac;
    return 0;
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

int neighbour_set(struct app_runtime *rt, uint16_t dev, uint32_t ip, const struct rte_ether_addr *mac, int replace)
{
    if (!netif_by_id(rt, dev) || !ipv4_destination_valid(rt, ip) || !rte_is_valid_assigned_ether_addr(mac)) return -EINVAL;
    struct neighbour_entry *found = find_slot(&rt->neighbours, dev, ip);
    if (!found) return -ENOSPC;
    if (found->in_use && !replace) return -EEXIST;
    *found = (struct neighbour_entry){ .ip_be = ip, .netif_id = dev, .mac = *mac, .in_use = 1, .permanent = 1 };
    admin_neighbour_event(rt, dev, ip, replace ? ADM_REPLACE : ADM_ADD);
    return neighbour_update(rt, dev, ip, mac);
}
int neighbour_delete(struct app_runtime *rt, uint16_t dev, uint32_t ip)
{
    struct neighbour_entry *e = find_slot(&rt->neighbours, dev, ip);
    if (!e || !e->in_use) return -ENOENT;
    unsigned hole = (unsigned)(e-rt->neighbours.entries);
    /* Close the probe-chain gap, including clusters that wrap around the table. */
    for (unsigned n = 1, i = (hole+1)%NEIGHBOUR_CAPACITY; n < NEIGHBOUR_CAPACITY; n++, i = (i+1)%NEIGHBOUR_CAPACITY) {
        struct neighbour_entry *next = &rt->neighbours.entries[i];
        if (!next->in_use) break;
        unsigned home = hash(next->ip_be ^ next->netif_id) % NEIGHBOUR_CAPACITY;
        if ((i-home+NEIGHBOUR_CAPACITY)%NEIGHBOUR_CAPACITY >= (i-hole+NEIGHBOUR_CAPACITY)%NEIGHBOUR_CAPACITY) {
            rt->neighbours.entries[hole] = *next;
            hole = i;
        }
    }
    rt->neighbours.entries[hole] = (struct neighbour_entry){0};
    admin_neighbour_event(rt, dev, ip, ADM_DEL);
    neighbour_cancel(rt, dev, ip);
    return 0;
}
