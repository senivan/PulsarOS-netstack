#include <errno.h>
#include "runtime.h"

static uint32_t prefix_mask(uint8_t length)
{
    return length ? UINT32_MAX << (32 - length) : 0;
}

int route_add(struct route_table *table, uint32_t prefix_be, uint8_t length, uint16_t id)
{
    if (length > 32) return -EINVAL;
    if (table->count == ROUTE_CAPACITY) return -ENOSPC;
    table->entries[table->count++] = (struct route_entry){
        .prefix_be = prefix_be & rte_cpu_to_be_32(prefix_mask(length)),
        .prefix_len = length, .netif_id = id
    };
    return 0;
}

int route_init_connected(struct app_runtime *rt)
{
    rt->routes.count = 0;
    for (uint16_t i = 0; i < rt->port_count; i++) {
        const struct port_state *port = &rt->ports[i];
        if (port->configured && route_add(&rt->routes, port->ip_be, port->prefix_len, port->id))
            return -1;
    }
    return 0;
}

enum drop_reason ipv4_route_lookup(const struct app_runtime *rt, uint32_t dst_ip_be,
                                   struct route_result *result)
{
    uint32_t dst = rte_be_to_cpu_32(dst_ip_be);
    if ((dst >> 24) == 0 || (dst >> 24) == 127 || dst >= 0xe0000000u ||
        netif_is_local_ip(rt, dst_ip_be)) return DROP_INVALID_DESTINATION;
    const struct route_entry *best = NULL;
    for (uint16_t i = 0; i < rt->routes.count; i++) {
        const struct route_entry *route = &rt->routes.entries[i];
        uint32_t mask = rte_cpu_to_be_32(prefix_mask(route->prefix_len));
        if ((dst_ip_be & mask) == route->prefix_be &&
            (!best || route->prefix_len > best->prefix_len)) best = route;
    }
    if (!best) return DROP_NO_ROUTE;
    const struct port_state *port = netif_by_id(rt, best->netif_id);
    if (!port || !port->started) return DROP_INVALID_EGRESS;
    uint32_t mask = prefix_mask(port->prefix_len);
    if (port->prefix_len <= 30 && (dst & mask) == (rte_be_to_cpu_32(port->ip_be) & mask) &&
        ((dst & ~mask) == 0 || (dst & ~mask) == ~mask)) return DROP_INVALID_DESTINATION;
    *result = (struct route_result){ .netif_id = port->id, .mtu = port->mtu,
        .source_ip_be = port->ip_be, .next_hop_be = dst_ip_be };
    return DROP_NONE;
}
