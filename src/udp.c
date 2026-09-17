#include <errno.h>
#include <string.h>
#include <rte_ip.h>
#include <rte_udp.h>
#include "runtime.h"
#include "udp.h"

static struct udp_endpoint *endpoint(struct app_runtime *rt, uint16_t port)
{
    if (!port) return NULL;
    for (unsigned i = 0; i < PS_UDP_MAX_ENDPOINTS; i++)
        if (rt->udp.entries[i].port == port) return &rt->udp.entries[i];
    return NULL;
}

int ps_udp_bind(struct app_runtime *rt, uint16_t port)
{
    if (!rt || !port) return -EINVAL;
    if (endpoint(rt, port)) return -EADDRINUSE;
    for (unsigned i = 0; i < PS_UDP_MAX_ENDPOINTS; i++) {
        if (!rt->udp.entries[i].port) { rt->udp.entries[i].port = port; return 0; }
    }
    return -ENOSPC;
}

int udp_deliver(struct app_runtime *rt, uint16_t port, const struct ps_addr *source,
                const void *payload, size_t len)
{
    struct udp_endpoint *ep = endpoint(rt, port);
    if (!ep) return -ENOENT;
    if (len > PS_UDP_MAX_PAYLOAD) return -EMSGSIZE;
    if (ep->count == PS_UDP_RX_QUEUE_SIZE) return -ENOBUFS;
    struct udp_datagram *datagram = &ep->queue[(ep->head + ep->count) % PS_UDP_RX_QUEUE_SIZE];
    datagram->source = *source;
    datagram->length = (uint16_t)len;
    if (len) memcpy(datagram->payload, payload, len);
    ep->count++;
    return 0;
}

ssize_t ps_udp_recvfrom(struct app_runtime *rt, uint16_t port, void *buf,
                        size_t len, struct ps_addr *source)
{
    if (!rt || !source || (!buf && len)) return -EINVAL;
    struct udp_endpoint *ep = endpoint(rt, port);
    if (!ep) return -ENOENT;
    if (!ep->count) return -EAGAIN;
    struct udp_datagram *datagram = &ep->queue[ep->head];
    if (len < datagram->length) return -EMSGSIZE;
    *source = datagram->source;
    if (datagram->length) memcpy(buf, datagram->payload, datagram->length);
    ep->head = (ep->head + 1) % PS_UDP_RX_QUEUE_SIZE;
    ep->count--;
    return datagram->length;
}

static ssize_t send_failure(struct app_runtime *rt, enum drop_reason reason, int error)
{
    rt->graph.nodes[NODE_UDP_OUTPUT].stats.drops++;
    rt->graph.nodes[NODE_UDP_OUTPUT].stats.errors++;
    rt->graph.drop_reasons[reason]++;
    return -error;
}

ssize_t ps_udp_sendto(struct app_runtime *rt, uint16_t source_port, const void *buf,
                      size_t len, const struct ps_addr *destination)
{
    if (!rt || !destination || !destination->port || (!buf && len)) return -EINVAL;
    if (rt->active_output) return -EBUSY;
    if (!endpoint(rt, source_port)) return -ENOENT;
    if (len > PS_UDP_MAX_PAYLOAD)
        return send_failure(rt, DROP_MTU, EMSGSIZE);
    struct route_result route;
    if (ipv4_route_lookup(rt, destination->ip_be, &route) == DROP_NONE &&
        len + sizeof(struct rte_ipv4_hdr) + sizeof(struct rte_udp_hdr) > route.mtu)
        return send_failure(rt, DROP_MTU, EMSGSIZE);
    struct rte_mbuf *m = rte_pktmbuf_alloc(rt->mbuf_pool);
    if (!m) return send_failure(rt, DROP_MBUF_ALLOCATION_FAILED, ENOMEM);
    void *payload = rte_pktmbuf_append(m, (uint16_t)len);
    if (!payload) {
        rte_pktmbuf_free(m);
        return send_failure(rt, DROP_NO_TAILROOM, ENOBUFS);
    }
    if (len) memcpy(payload, buf, len);
    struct node_frame frame = { .count = 1 };
    frame.pkts[0] = m;
    frame.ctxs[0].src_port = source_port;
    frame.ctxs[0].dst_port = destination->port;
    frame.ctxs[0].dst_ip_be = destination->ip_be;
    frame.ctxs[0].ip_protocol = IPPROTO_UDP;
    uint64_t sent_before = rt->tx_packets;
    /* The graph consumes the mbuf on success and failure. */
    graph_submit(rt, NODE_IPV4_ROUTE, &frame);
    return rt->tx_packets != sent_before ? (ssize_t)len : -EIO;
}
