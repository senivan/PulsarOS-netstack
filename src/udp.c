#include <errno.h>
#include <string.h>
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
