#include <errno.h>
#include <string.h>
#include <stdio.h>
#include <rte_cycles.h>
#include "admin_service.h"

static int removed_binding(const struct app_runtime *rt, const struct net_config *next)
{
    for (unsigned i = 0; i < rt->sockets.capacity; i++) {
        const struct ps_socket_entry *s = &rt->sockets.entries[i];
        if (!s->allocated || !s->local.ip_be) continue;
        unsigned j;
        for (j = 0; j < next->address_count; j++) if (next->addresses[j].ip == s->local.ip_be) break;
        if (j == next->address_count) return 1;
    }
    return 0;
}

static void capture(struct app_runtime *rt, struct admin_view *v, const struct admin_request *r)
{
    memset(v, 0, sizeof(*v));
    v->config = *rt->network;
    v->acl = rt->acl_stats;
    v->events = rt->events;
    v->neighbours = rt->neighbours;
    v->port_count = rt->port_count;
    v->forwarding = rt->ipv4_forwarding;
    v->uptime = (rte_get_timer_cycles() - rt->admin_started) / rte_get_timer_hz();
    for (unsigned i = 0; i < rt->port_count; i++) {
        struct admin_link *p = &v->links[i];
        p->port = rt->ports[i];
        struct rte_eth_link link = {0};
        rte_eth_link_get_nowait(p->port.port_id, &link);
        p->carrier = link.link_status;
        rte_eth_stats_get(p->port.port_id, &p->hardware);
        struct rte_eth_dev_info info = {0};
        if (!rte_eth_dev_info_get(p->port.port_id, &info) && info.driver_name)
            snprintf(p->driver, sizeof(p->driver), "%s", info.driver_name);
    }
    for (unsigned i = 0; i < rt->sockets.capacity; i++) {
        const struct ps_socket_entry *s = &rt->sockets.entries[i];
        if (!s->allocated) continue;
        struct admin_socket *out = &v->sockets[v->socket_count++];
        *out = (struct admin_socket){ .owner=s->owner, .fd=s->fd, .open=s->open, .type=s->type, .local=s->local, .remote=s->remote };
        if (s->type == PS_SOCK_STREAM) { out->state=s->transport.tcp.state; out->rx=s->transport.tcp.rx_len; out->tx=s->transport.tcp.tx_len; }
        else out->rx=s->transport.udp.count;
    }
    for (unsigned i = 0; i < NODE_MAX; i++) v->nodes[i] = rt->graph.nodes[i].stats;
    memcpy(v->drops, rt->graph.drop_reasons, sizeof(v->drops));
    if (r->group == ADM_ROUTE && r->verb == ADM_GET)
        v->route_reason = ipv4_route_query(rt, r->v[F_IP], r->v[F_SRC], NET_IIF_NONE, &v->route);
}

static int mtu_set(struct port_state *p, uint32_t mtu)
{
    if (mtu < 68 || mtu > 1500) return -EINVAL;
    struct rte_eth_dev_info info;
    int rc = rte_eth_dev_info_get(p->port_id, &info);
    if (rc) return rc;
    if ((info.min_mtu && mtu < info.min_mtu) || (info.max_mtu && mtu > info.max_mtu)) return -EINVAL;
    uint16_t old = p->mtu;
    rc = rte_eth_dev_set_mtu(p->port_id, (uint16_t)mtu);
    if (rc == -EBUSY && p->started) {
        rc = rte_eth_dev_stop(p->port_id);
        if (rc) return rc;
        p->started = 0;
        rc = rte_eth_dev_set_mtu(p->port_id, (uint16_t)mtu);
        if (!rc) rc = rte_eth_dev_start(p->port_id);
        if (rc) {
            rte_eth_dev_set_mtu(p->port_id, old);
            if (rte_eth_dev_start(p->port_id)) p->admin_down = 1;
            else p->started = 1;
            return rc;
        }
        p->started = 1;
    }
    if (rc) return rc;
    uint16_t actual;
    rc = rte_eth_dev_get_mtu(p->port_id, &actual);
    if (rc || actual != mtu) { rte_eth_dev_set_mtu(p->port_id, old); return rc ? rc : -EIO; }
    p->mtu = actual;
    return 0;
}
int admin_worker_operation(struct app_runtime *rt, const struct admin_request *r)
{
    int dev = -1;
    for (unsigned i = 0; i < rt->port_count; i++) if (!strcmp(r->dev, rt->ports[i].name)) dev = (int)i;
    if (dev < 0) return -ENODEV;
    struct port_state *p = &rt->ports[dev];
    int rc;
    if (r->group == ADM_LINK && r->verb == ADM_SET) {
        if (r->v[F_PORTS] == 1) {
            if (r->v[F_ACTION] > 1) return -EINVAL;
            if (r->v[F_ACTION]) {
                if (p->started && !p->admin_down) return 0;
                rc = rte_eth_dev_start(p->port_id);
                if (rc) return rc;
                p->started = 1; p->admin_down = 0;
            } else {
                if (p->admin_down) return 0;
                rc = rte_eth_dev_stop(p->port_id);
                if (rc) return rc;
                p->started = 0; p->admin_down = 1;
            }
        } else if (r->v[F_PORTS] == 2) {
            rc = mtu_set(p, r->v[F_IP]);
            if (rc) return rc;
        } else return -EINVAL;
        neighbour_cancel(rt, dev, 0);
        admin_event_emit(rt, ADM_LINK, dev, ADM_SET);
        return 0;
    }
    if (r->group != ADM_NEIGH) return -EOPNOTSUPP;
    uint32_t ip = r->v[F_IP];
    if (r->verb == ADM_FLUSH) {
        for (unsigned i = 0; i < NEIGHBOUR_CAPACITY; i++) {
            struct neighbour_entry *e = &rt->neighbours.entries[i];
            if (e->in_use && e->netif_id == (unsigned)dev) neighbour_delete(rt, dev, e->ip_be);
        }
        neighbour_cancel(rt, dev, 0);
        return 0;
    }
    if (r->verb == ADM_DEL) return neighbour_delete(rt, dev, ip);
    if (r->verb != ADM_ADD && r->verb != ADM_REPLACE) return -EOPNOTSUPP;
    struct rte_ether_addr mac;
    if (r->v[F_SPORT_MIN] > UINT16_MAX) return -EINVAL;
    uint32_t first = r->v[F_SPORT_MIN], rest = r->v[F_SPORT_MAX];
    mac.addr_bytes[0] = first >> 8; mac.addr_bytes[1] = first;
    for (unsigned i = 0; i < 4; i++) mac.addr_bytes[2+i] = (uint8_t)(rest >> (24-i*8));
    return neighbour_set(rt, dev, ip, &mac, r->verb == ADM_REPLACE);
}
unsigned admin_progress(struct admin_service *service, struct app_runtime *rt)
{
    uint64_t now = rte_get_timer_cycles();
    if (now - rt->carrier_checked >= rte_get_timer_hz()) {
        rt->carrier_checked = now;
        for (unsigned i = 0; i < rt->port_count; i++) {
            struct rte_eth_link link = {0};
            if (!rte_eth_link_get_nowait(rt->ports[i].port_id, &link) && rt->carrier[i] != link.link_status) {
                rt->carrier[i] = link.link_status;
                admin_event_emit(rt, ADM_LINK, i, ADM_SHOW);
            }
        }
    }
    if (atomic_load_explicit(&service->state, memory_order_acquire) != 1) return 0;
    struct admin_job *j = &service->job;
    j->result = 0;
    if (j->type == ADMIN_ACTIVATE) {
        if (!j->next || j->next->generation != rt->network->generation+1) j->result = -ESTALE;
        else if (removed_binding(rt, j->next)) j->result = -EBUSY;
        else {
            j->retired = rt->network;
            net_acl_counters_migrate(j->retired, j->next, &rt->acl_stats);
            rt->network = j->next;
            if (j->request.group == ADM_ADDR || j->request.group == ADM_ROUTE || j->request.group == ADM_RULE) neighbour_fini(rt);
            admin_event_emit(rt, j->request.group, j->request.v[F_PREF], j->request.verb);
            admin_event_emit(rt, ADM_STATUS, 0, ADM_APPLY);
        }
    } else if (j->type == ADMIN_HARDWARE) j->result = admin_worker_operation(rt, &j->request);
    capture(rt, &j->view, &j->request);
    atomic_store_explicit(&service->state, 2, memory_order_release);
    return 1;
}
