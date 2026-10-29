#include <arpa/inet.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include "runtime.h"


int net_connected_rebuild(struct net_config *c)
{
    if (c->address_count > NET_ADDR_MAX || c->route_count > NET_ROUTE_MAX) return -EINVAL;
    for (unsigned i = 0; i < c->address_count; i++) if (c->addresses[i].prefix > 32) return -EINVAL;
    unsigned n = 0;
    for (unsigned i = 0; i < c->route_count; i++)
        if (!c->routes[i].connected) c->routes[n++] = c->routes[i];
    c->route_count = n;
    for (unsigned i = 0; i < c->address_count; i++) {
        const struct net_address *a = &c->addresses[i];
        uint32_t ip = a->ip & net_mask(a->prefix);
        unsigned j;
        for (j = 0; j < c->route_count; j++) {
            struct net_route *r = &c->routes[j];
            if (r->table == NET_TABLE_MAIN && r->ip == ip && r->prefix == a->prefix && r->dev == a->dev && r->connected) break;
        }
        if (j < c->route_count) continue;
        if (c->route_count == NET_ROUTE_MAX) return -ENOSPC;
        c->routes[c->route_count++] = (struct net_route){ .ip = ip, .prefix = a->prefix,
            .dev = a->dev, .table = NET_TABLE_MAIN, .connected = 1 };
    }
    return 0;
}

int net_config_validate(const struct net_config *c, unsigned ports)
{
    if (c->address_count > NET_ADDR_MAX || c->route_count > NET_ROUTE_MAX ||
        c->rule_count > NET_RULE_MAX || c->acl_count > NET_ACL_MAX || c->default_drop > 1) return -EINVAL;
    for (unsigned i = 0; i < c->address_count; i++) {
        const struct net_address *a = &c->addresses[i];
        if (a->dev >= ports || a->prefix > 32 || !net_unicast(a->ip) || !net_host(a->ip, a->prefix)) return -EINVAL;
        for (unsigned j = 0; j < i; j++) if (c->addresses[j].ip == a->ip) return -EEXIST;
    }
    for (unsigned i = 0; i < c->route_count; i++) {
        const struct net_route *r = &c->routes[i];
        if (!net_prefix_valid(r->ip, r->prefix) || !r->table || r->table == NET_TABLE_LOCAL ||
            r->type > NET_PROHIBIT || r->connected > 1 ||
            (r->type == NET_UNICAST && r->dev >= ports) || (r->type && r->gateway)) return -EINVAL;
        for (unsigned j = 0; j < i; j++) {
            const struct net_route *p = &c->routes[j];
            if (r->table == p->table && r->ip == p->ip && r->prefix == p->prefix &&
                !(r->connected && p->connected && r->dev != p->dev)) return -EEXIST;
        }
        if (!r->gateway) continue;
        if (!net_unicast(r->gateway)) return -EINVAL;
        int reachable = 0;
        for (unsigned j = 0; j < c->address_count; j++) {
            const struct net_address *a = &c->addresses[j];
            if (a->ip == r->gateway ||
                (net_match(r->gateway, a->ip & net_mask(a->prefix), a->prefix) && !net_host(r->gateway, a->prefix))) return -EINVAL;
            if (a->dev == r->dev && net_match(r->gateway, a->ip & net_mask(a->prefix), a->prefix) && net_host(r->gateway, a->prefix)) reachable = 1;
        }
        for (unsigned j = 0; j < c->route_count; j++) {
            const struct net_route *p = &c->routes[j];
            if (p->table == r->table && p->dev == r->dev && p->type == NET_UNICAST && !p->gateway &&
                net_match(r->gateway, p->ip, p->prefix) && net_host(r->gateway, p->prefix)) reachable = 1;
        }
        if (!reachable) return -ENETUNREACH;
    }
    for (unsigned i = 0; i < c->rule_count; i++) {
        const struct net_rule *r = &c->rules[i];
        if (!r->pref || r->pref >= 32766 || !net_prefix_valid(r->src, r->src_prefix) ||
            !net_prefix_valid(r->dst, r->dst_prefix) || (r->iif != NET_IIF_NONE && r->iif >= ports) ||
            r->type > NET_PROHIBIT || (!r->type && (!r->table || r->table == NET_TABLE_LOCAL)) ||
            (i && c->rules[i-1].pref >= r->pref)) return -EINVAL;
    }
    for (unsigned i = 0; i < c->acl_count; i++) {
        const struct net_acl *a = &c->acls[i];
        if (!net_prefix_valid(a->src, a->src_prefix) || !net_prefix_valid(a->dst, a->dst_prefix) ||
            (a->iif != NET_IIF_NONE && a->iif >= ports) || a->proto > 255 || a->drop > 1 || a->ports > 3 ||
            (a->ports && a->proto != 6 && a->proto != 17) || a->sport_min > a->sport_max ||
            a->dport_min > a->dport_max || a->sport_max > 65535 || a->dport_max > 65535 ||
            (i && c->acls[i-1].pref >= a->pref)) return -EINVAL;
    }
    return 0;
}

int net_acl_classify(const struct net_config *c, const struct acl_key *k)
{
    for (unsigned i = 0; i < c->acl_count; i++) {
        const struct net_acl *a = &c->acls[i];
        if (!net_match(k->src, a->src, a->src_prefix) || !net_match(k->dst, a->dst, a->dst_prefix) ||
            (a->iif != NET_IIF_NONE && a->iif != k->iif) || (a->proto && a->proto != k->proto)) continue;
        if (a->ports && !k->ports_valid) continue;
        if ((a->ports & 1) && (k->sport < a->sport_min || k->sport > a->sport_max)) continue;
        if ((a->ports & 2) && (k->dport < a->dport_min || k->dport > a->dport_max)) continue;
        return (int)i;
    }
    return -1;
}
void net_acl_classify_batch(const struct net_config *c, const struct acl_key *keys, size_t count, int *results)
{
    for (size_t i = 0; i < count; i++) results[i] = net_acl_classify(c, &keys[i]);
}
int net_acl_account(const struct net_config *c, struct acl_counters *s, int i, size_t bytes)
{
    unsigned drop = c->default_drop;
    if (i >= 0 && (unsigned)i < c->acl_count) { s->rules[i].packets++; s->rules[i].bytes += bytes; drop = c->acls[i].drop; }
    else s->defaults++;
    if (drop) s->dropped++; else s->accepted++;
    return !drop;
}
int net_acl_accept(const struct net_config *c, struct acl_counters *s, const struct acl_key *k, size_t bytes)
{
    return net_acl_account(c, s, net_acl_classify(c, k), bytes);
}
void net_acl_counters_migrate(const struct net_config *old, const struct net_config *next, struct acl_counters *s)
{
    struct acl_counters saved = *s;
    memset(s->rules, 0, sizeof(s->rules));
    for (unsigned i = 0; i < next->acl_count; i++)
        for (unsigned j = 0; j < old->acl_count; j++)
            if (!memcmp(&next->acls[i], &old->acls[j], sizeof(struct net_acl))) s->rules[i] = saved.rules[j];
}
int net_address_on(const struct app_runtime *rt, uint32_t dev, uint32_t ip)
{
    if (!rt->network) { const struct port_state *p = netif_by_id(rt, dev); return p && p->ip_be == ip; }
    for (unsigned i = 0; i < rt->network->address_count; i++) {
        const struct net_address *a = &rt->network->addresses[i];
        if (a->dev == dev && a->ip == ip) return 1;
    }
    return 0;
}
uint32_t net_source(const struct app_runtime *rt, uint32_t dev, uint32_t dst)
{
    if (!rt->network) { const struct port_state *p = netif_by_id(rt, dev); return p ? p->ip_be : 0; }
    uint32_t first = 0, best = 0, prefix = 0;
    for (unsigned i = 0; i < rt->network->address_count; i++) {
        const struct net_address *a = &rt->network->addresses[i];
        if (a->dev != dev) continue;
        if (!first) first = a->ip;
        if (net_match(dst, a->ip & net_mask(a->prefix), a->prefix) && (!best || a->prefix > prefix)) { best = a->ip; prefix = a->prefix; }
    }
    return best ? best : first;
}
int net_config_init(struct app_runtime *rt)
{
    struct net_config *c = calloc(1, sizeof(*c));
    if (!c) return -ENOMEM;
    c->generation = 1;
    for (unsigned i = 0; i < rt->port_count; i++) {
        struct port_state *p = &rt->ports[i];
        c->addresses[c->address_count++] = (struct net_address){ p->ip_be, p->prefix_len, p->id };
    }
    for (unsigned i = rt->port_count; i < rt->routes.count; i++) {
        const struct route_entry *r = &rt->routes.entries[i];
        c->routes[c->route_count++] = (struct net_route){ .ip = r->prefix_be, .prefix = r->prefix_len,
            .gateway = r->gateway_be, .dev = r->netif_id, .table = NET_TABLE_MAIN };
    }
    int rc = net_connected_rebuild(c);
    if (!rc) rc = net_config_validate(c, rt->port_count);
    if (rc) { free(c); return rc; }
    rt->network = c;
    return 0;
}

int net_direct(const struct app_runtime *rt, uint32_t dev, uint32_t ip)
{
    if (!rt->network) return route_is_direct(&rt->routes, dev, ip);
    if (!net_unicast(ip)) return 0;
    for (unsigned i=0; i<rt->network->route_count; i++) {
        const struct net_route *r=&rt->network->routes[i];
        if (r->dev==dev && !r->type && !r->gateway && net_match(ip,r->ip,r->prefix) && net_host(ip,r->prefix)) return 1;
    }
    return 0;
}
