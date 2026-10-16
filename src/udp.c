#include <errno.h>
#include <string.h>
#include <rte_ip.h>
#include <rte_udp.h>
#include "runtime.h"
#include "udp.h"

int udp_deliver(struct app_runtime *rt, uint32_t local_ip_be, uint16_t port, const struct ps_sockaddr *source,
                const void *payload, size_t len)
{
    struct ps_socket_entry *s = socket_bound(rt, PS_SOCK_DGRAM, local_ip_be, port);
    if (!s || (s->remote.port && (s->remote.port != source->port || s->remote.ip_be != source->ip_be))) return -ENOENT;
    struct udp_endpoint *ep = &s->transport.udp;
    if (len > PS_DGRAM_MAX_PAYLOAD) return -EMSGSIZE;
    if (ep->count == PS_DGRAM_QUEUE_SIZE) return -ENOBUFS;
    struct udp_datagram *datagram = &ep->queue[(ep->head + ep->count) % PS_DGRAM_QUEUE_SIZE];
    datagram->source = *source;
    datagram->length = (uint16_t)len;
    if (len) memcpy(datagram->payload, payload, len);
    ep->count++;
    return 0;
}

ssize_t udp_recv(struct ps_socket_entry *s, void *buf, size_t len, struct ps_sockaddr *source)
{
    struct udp_endpoint *ep = &s->transport.udp;
    if (!ep->count) return -EAGAIN;
    struct udp_datagram *datagram = &ep->queue[ep->head];
    if (len < datagram->length) return -EMSGSIZE;
    *source = datagram->source;
    if (datagram->length) memcpy(buf, datagram->payload, datagram->length);
    ep->head = (ep->head + 1) % PS_DGRAM_QUEUE_SIZE;
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

ssize_t udp_send(struct app_runtime *rt, struct ps_socket_entry *s, const void *buf,
                  size_t len, const struct ps_sockaddr *destination)
{
    if (len > PS_DGRAM_MAX_PAYLOAD)
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
    frame.ctxs[0].src_port = s->local.port;
    frame.ctxs[0].src_ip_be = s->local.ip_be;
    frame.ctxs[0].dst_port = destination->port;
    frame.ctxs[0].dst_ip_be = destination->ip_be;
    frame.ctxs[0].ip_protocol = IPPROTO_UDP;
    frame.ctxs[0].report_acceptance = 1;
    uint64_t accepted_before = rt->accepted_sends;
    /* The graph consumes the mbuf on success and failure. */
    graph_submit(rt, NODE_IPV4_ROUTE, &frame);
    return rt->accepted_sends != accepted_before ? (ssize_t)len : -EIO;
}
