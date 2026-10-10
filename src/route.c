#include <errno.h>
#include <string.h>
#include "runtime.h"

static uint32_t prefix_mask(uint8_t length)
{
    return length ? UINT32_MAX << (32 - length) : 0;
}

int route_add(struct route_table *table, uint32_t prefix_be, uint8_t length, uint16_t id)
{
    return route_add_gateway(table, prefix_be, length, id, 0);
}

int route_add_gateway(struct route_table *table, uint32_t prefix_be, uint8_t length,
                      uint16_t id, uint32_t gateway_be)
{
    if (length > 32) return -EINVAL;
    if (table->count == ROUTE_CAPACITY) return -ENOSPC;
    table->entries[table->count++] = (struct route_entry){
        .prefix_be = prefix_be & rte_cpu_to_be_32(prefix_mask(length)),
        .prefix_len = length, .netif_id = id, .gateway_be = gateway_be
    };
    return 0;
}

static int unicast(uint32_t ip_be)
{
    uint32_t ip = rte_be_to_cpu_32(ip_be);
    return (ip >> 24) != 0 && (ip >> 24) != 127 && ip < 0xe0000000u;
}

static int subnet_host(uint32_t prefix_be, uint8_t length, uint32_t ip_be)
{
    uint32_t mask = prefix_mask(length), ip = rte_be_to_cpu_32(ip_be);
    return length >= 31 || (ip & mask) != (rte_be_to_cpu_32(prefix_be) & mask) ||
           ((ip & ~mask) != 0 && (ip & ~mask) != ~mask);
}

int route_is_direct(const struct route_table *table, uint16_t id, uint32_t ip_be)
{
    if (!unicast(ip_be)) return 0;
    for (uint16_t i = 0; i < table->count; i++) {
        const struct route_entry *route = &table->entries[i];
        uint32_t mask = rte_cpu_to_be_32(prefix_mask(route->prefix_len));
        if (route->netif_id == id && !route->gateway_be &&
            (ip_be & mask) == route->prefix_be &&
            subnet_host(route->prefix_be, route->prefix_len, ip_be)) return 1;
    }
    return 0;
}

int route_config_init(const struct app_config *conf, struct route_table *table)
{
    if (!conf->netif_count || conf->netif_count > NETIF_MAX ||
        conf->route_count > ROUTE_CAPACITY || conf->ipv4_forwarding > 1) return -EINVAL;
    table->count = 0;
    for (uint16_t i = 0; i < conf->netif_count; i++) {
        int rc = route_add(table, conf->interfaces[i].ip_be, conf->interfaces[i].prefix_len, i);
        if (rc) return rc;
    }
    for (uint16_t i = 0; i < conf->route_count; i++) {
        const struct route_config *route = &conf->routes[i];
        uint16_t id;
        for (id = 0; id < conf->netif_count; id++)
            if (!strcmp(route->device, conf->interfaces[id].device)) break;
        if (id == conf->netif_count) return -ENODEV;
        int rc = route_add_gateway(table, route->prefix_be, route->prefix_len, id, route->gateway_be);
        if (rc) return rc;
    }
    for (uint16_t i = 0; i < table->count; i++) {
        const struct route_entry *route = &table->entries[i];
        if (!route->gateway_be) continue;
        if (!route_is_direct(table, route->netif_id, route->gateway_be)) return -EINVAL;
        for (uint16_t j = 0; j < conf->netif_count; j++)
            if (route->gateway_be == conf->interfaces[j].ip_be ||
                !subnet_host(conf->interfaces[j].ip_be, conf->interfaces[j].prefix_len,
                             route->gateway_be)) return -EINVAL;
    }
    return 0;
}

int ipv4_destination_valid(const struct app_runtime *rt, uint32_t ip_be)
{
    if (!unicast(ip_be) || netif_is_local_ip(rt, ip_be)) return 0;
    for (uint16_t i = 0; i < rt->port_count; i++) {
        const struct port_state *port = &rt->ports[i];
        if (port->configured && !subnet_host(port->ip_be, port->prefix_len, ip_be)) return 0;
    }
    return 1;
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
    if (!ipv4_destination_valid(rt, dst_ip_be)) return DROP_INVALID_DESTINATION;
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
    uint32_t next_hop = best->gateway_be ? best->gateway_be : dst_ip_be;
    if (!best->gateway_be && !subnet_host(best->prefix_be, best->prefix_len, dst_ip_be))
        return DROP_INVALID_DESTINATION;
    if (best->gateway_be && (!ipv4_destination_valid(rt, next_hop) ||
        !route_is_direct(&rt->routes, best->netif_id, next_hop))) return DROP_INVALID_EGRESS;
    *result = (struct route_result){ .netif_id = port->id, .mtu = port->mtu,
        .source_ip_be = port->ip_be, .next_hop_be = next_hop };
    return DROP_NONE;
}
