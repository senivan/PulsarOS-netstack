#include <errno.h>
#include "runtime.h"

static enum drop_reason action(uint32_t type)
{
    switch (type) {
    case NET_BLACKHOLE: return DROP_ROUTE_BLACKHOLE;
    case NET_UNREACHABLE: return DROP_ROUTE_UNREACHABLE;
    case NET_PROHIBIT: return DROP_ROUTE_PROHIBIT;
    default: return DROP_NONE;
    }
}

static enum drop_reason table_lookup(const struct app_runtime *rt, uint32_t dst, uint32_t src,
                                      uint32_t table, uint32_t pref, struct route_result *out)
{
    const struct net_config *c = rt->network;
    const struct net_route *best = NULL;
    for (unsigned i = 0; i < c->route_count; i++) {
        const struct net_route *r = &c->routes[i];
        const struct port_state *p = netif_by_id(rt, r->dev);
        if (r->table != table || !net_match(dst, r->ip, r->prefix) ||
            (!r->type && (!p || !p->started || p->admin_down))) continue;
        if (!best || r->prefix > best->prefix) best = r;
    }
    if (!best) return DROP_NO_ROUTE;
    *out = (struct route_result){ .table = table, .rule_pref = pref, .type = best->type,
        .netif_id = best->dev, .next_hop_be = best->gateway ? best->gateway : dst };
    if (best->type) return action(best->type);
    if (!best->gateway && !net_host(dst, best->prefix)) return DROP_INVALID_DESTINATION;
    const struct port_state *p = netif_by_id(rt, best->dev);
    out->mtu = p->mtu;
    out->source_ip_be = src ? src : net_source(rt, p->id, out->next_hop_be);
    return out->source_ip_be ? DROP_NONE : DROP_INVALID_EGRESS;
}

enum drop_reason ipv4_route_query(const struct app_runtime *rt, uint32_t dst, uint32_t src,
                                    uint32_t iif, struct route_result *out)
{
    if (!rt->network) return ipv4_route_lookup(rt, dst, out);
    const struct net_config *c = rt->network;
    for (unsigned i = 0; i < c->address_count; i++) {
        const struct net_address *a = &c->addresses[i];
        if (dst != a->ip) continue;
        *out = (struct route_result){ .table = NET_TABLE_LOCAL, .netif_id = a->dev,
            .source_ip_be = dst, .next_hop_be = dst, .mtu = rt->ports[a->dev].mtu, .local = 1 };
        return DROP_NONE;
    }
    if (!ipv4_destination_valid(rt, dst)) return DROP_INVALID_DESTINATION;
    for (unsigned i = 0; i < c->rule_count; i++) {
        const struct net_rule *r = &c->rules[i];
        if (!net_match(src, r->src, r->src_prefix) || !net_match(dst, r->dst, r->dst_prefix) ||
            (r->iif != NET_IIF_NONE && r->iif != iif)) continue;
        if (r->type) { *out = (struct route_result){ .rule_pref = r->pref, .type = r->type }; return action(r->type); }
        enum drop_reason reason = table_lookup(rt, dst, src, r->table, r->pref, out);
        if (reason != DROP_NO_ROUTE) return reason;
    }
    enum drop_reason reason = table_lookup(rt, dst, src, NET_TABLE_MAIN, 32766, out);
    if (reason != DROP_NO_ROUTE) return reason;
    return table_lookup(rt, dst, src, NET_TABLE_DEFAULT, 32767, out);
}

int ipv4_route_errno(enum drop_reason reason)
{
    if (reason == DROP_ROUTE_PROHIBIT) return EACCES;
    if (reason == DROP_ROUTE_BLACKHOLE) return EINVAL;
    return ENETUNREACH;
}
