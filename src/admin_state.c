#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include "admin_service.h"

int admin_device(const struct admin_view *v, const char *name)
{
    for (unsigned i = 0; i < v->port_count; i++) if (!strcmp(v->links[i].port.name, name)) return (int)i;
    return -ENODEV;
}
static int acl_compare(const void *a, const void *b)
{
    uint32_t x = ((const struct net_acl *)a)->pref, y = ((const struct net_acl *)b)->pref;
    return (x > y) - (x < y);
}
static int rule_compare(const void *a, const void *b)
{
    uint32_t x = ((const struct net_rule *)a)->pref, y = ((const struct net_rule *)b)->pref;
    return (x > y) - (x < y);
}
int admin_mutate(const struct admin_view *view, const struct admin_request *r, struct net_config *c)
{
    *c = view->config;
    const uint32_t *v = r->v;
    int dev = *r->dev ? admin_device(view, r->dev) : -1;
    if (*r->dev && dev < 0) return dev;
    if (r->group == ADM_ADDR) {
        if (dev < 0) return -ENODEV;
        unsigned i;
        for (i = 0; i < c->address_count; i++)
            if (c->addresses[i].ip == v[F_IP] && c->addresses[i].dev == (unsigned)dev) break;
        if (r->verb == ADM_FLUSH) {
            unsigned n = 0;
            for (i = 0; i < c->address_count; i++)
                if (c->addresses[i].dev != (unsigned)dev) c->addresses[n++] = c->addresses[i];
            c->address_count = n;
        } else if (r->verb == ADM_DEL) {
            if (i == c->address_count || c->addresses[i].prefix != v[F_PREFIX]) return -ENOENT;
            memmove(c->addresses+i, c->addresses+i+1, (--c->address_count-i)*sizeof(c->addresses[0]));
        } else if (r->verb == ADM_ADD || r->verb == ADM_REPLACE) {
            if (i < c->address_count && r->verb == ADM_ADD) return -EEXIST;
            if (i == c->address_count) { if (i == NET_ADDR_MAX) return -ENOSPC; c->address_count++; }
            c->addresses[i] = (struct net_address){v[F_IP], v[F_PREFIX], (unsigned)dev};
        } else return -EOPNOTSUPP;
        int rc = net_connected_rebuild(c);
        if (rc) return rc;
    } else if (r->group == ADM_ROUTE) {
        if (!v[F_TABLE] || v[F_TABLE] == NET_TABLE_LOCAL) return -EPERM;
        unsigned i;
        for (i = 0; i < c->route_count; i++) {
            const struct net_route *p = &c->routes[i];
            if (p->table == v[F_TABLE] && p->ip == v[F_IP] && p->prefix == v[F_PREFIX]) break;
        }
        if (r->verb == ADM_FLUSH) {
            unsigned n = 0;
            for (i = 0; i < c->route_count; i++)
                if (c->routes[i].table != v[F_TABLE] || c->routes[i].connected) c->routes[n++] = c->routes[i];
            c->route_count = n;
        } else if (r->verb == ADM_DEL) {
            if (i == c->route_count) return -ENOENT;
            if (c->routes[i].connected) return -EPERM;
            memmove(c->routes+i, c->routes+i+1, (--c->route_count-i)*sizeof(c->routes[0]));
        } else if (r->verb == ADM_ADD || r->verb == ADM_REPLACE) {
            if (i < c->route_count && (r->verb == ADM_ADD || c->routes[i].connected)) return -EEXIST;
            if (!v[F_ACTION] && (dev < 0 || view->links[dev].port.admin_down || !view->links[dev].port.started)) return -ENETDOWN;
            if (i == c->route_count) { if (i == NET_ROUTE_MAX) return -ENOSPC; c->route_count++; }
            c->routes[i] = (struct net_route){.ip=v[F_IP], .prefix=v[F_PREFIX], .gateway=v[F_GATEWAY],
                .dev=dev < 0 ? 0 : (unsigned)dev, .table=v[F_TABLE], .type=v[F_ACTION]};
        } else return -EOPNOTSUPP;
    } else if (r->group == ADM_RULE) {
        unsigned i;
        for (i = 0; i < c->rule_count; i++) if (c->rules[i].pref == v[F_PREF]) break;
        if (r->verb == ADM_FLUSH) c->rule_count = 0;
        else if (r->verb == ADM_DEL) {
            if (i == c->rule_count) return -ENOENT;
            memmove(c->rules+i, c->rules+i+1, (--c->rule_count-i)*sizeof(c->rules[0]));
        } else if (r->verb == ADM_ADD) {
            if (i < c->rule_count) return -EEXIST;
            if (i == NET_RULE_MAX) return -ENOSPC;
            c->rules[c->rule_count++] = (struct net_rule){v[F_PREF], v[F_SRC], v[F_SRC_PREFIX],
                v[F_DST], v[F_DST_PREFIX], dev < 0 ? NET_IIF_NONE : (unsigned)dev, v[F_TABLE], v[F_ACTION]};
            qsort(c->rules, c->rule_count, sizeof(c->rules[0]), rule_compare);
        } else return -EOPNOTSUPP;
    } else if (r->group == ADM_ACL) {
        unsigned i;
        for (i = 0; i < c->acl_count; i++) if (c->acls[i].pref == v[F_PREF]) break;
        if (r->verb == ADM_FLUSH) c->acl_count = 0;
        else if (r->verb == ADM_DEFAULT) c->default_drop = v[F_ACTION];
        else if (r->verb == ADM_APPLY) {
            if (r->count > NET_ACL_MAX) return -ENOSPC;
            c->acl_count = r->count; c->default_drop = v[F_ACTION];
            for (i = 0; i < r->count; i++) {
                c->acls[i] = r->acls[i].rule;
                int id = *r->acls[i].dev ? admin_device(view, r->acls[i].dev) : -1;
                if (*r->acls[i].dev && id < 0) return id;
                c->acls[i].iif = id < 0 ? NET_IIF_NONE : (unsigned)id;
            }
            qsort(c->acls, c->acl_count, sizeof(c->acls[0]), acl_compare);
        } else if (r->verb == ADM_DEL) {
            if (i == c->acl_count) return -ENOENT;
            memmove(c->acls+i, c->acls+i+1, (--c->acl_count-i)*sizeof(c->acls[0]));
        } else if (r->verb == ADM_ADD) {
            if (i < c->acl_count) return -EEXIST;
            if (i == NET_ACL_MAX) return -ENOSPC;
            c->acls[c->acl_count++] = (struct net_acl){v[F_PREF], v[F_SRC], v[F_SRC_PREFIX], v[F_DST], v[F_DST_PREFIX],
                dev < 0 ? NET_IIF_NONE : (unsigned)dev, v[F_PROTO], v[F_SPORT_MIN], v[F_SPORT_MAX],
                v[F_DPORT_MIN], v[F_DPORT_MAX], v[F_PORTS], v[F_ACTION]};
            qsort(c->acls, c->acl_count, sizeof(c->acls[0]), acl_compare);
        } else return -EOPNOTSUPP;
    } else return -EOPNOTSUPP;
    if (c->generation == UINT64_MAX) return -EOVERFLOW;
    c->generation++;
    return net_config_prepare(c, view->port_count);
}
