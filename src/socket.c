#include <errno.h>
#include <limits.h>
#include <string.h>
#include <rte_cycles.h>
#include "runtime.h"

int socket_subsystem_init(struct app_runtime *rt)
{
    if (!rt) return -EINVAL;
    if (rt->sockets.capacity) return -EBUSY;
    memset(&rt->sockets, 0, sizeof(rt->sockets));
    rt->sockets.next_port = 49152;
    rt->sockets.capacity = PS_SOCKET_MAX;
    rt->tcp_timer_next = 0;
    return 0;
}

void socket_subsystem_fini(struct app_runtime *rt)
{
    memset(&rt->sockets, 0, sizeof(rt->sockets));
}

struct ps_socket_entry *socket_lookup(struct app_runtime *rt, ps_fd_t fd)
{
    if (fd <= 0) return NULL;
    unsigned slot = (unsigned)(fd-1) % PS_SOCKET_MAX;
    if (slot >= rt->sockets.capacity) return NULL;
    struct ps_socket_entry *s = &rt->sockets.entries[slot];
    return s->allocated && s->fd == fd ? s : NULL;
}

struct ps_socket_entry *socket_allocate(struct app_runtime *rt, int type)
{
    for (unsigned i = 0; i < rt->sockets.capacity; i++) {
        struct ps_socket_entry *s = &rt->sockets.entries[i];
        if (s->allocated) continue;
        /* The slot is encoded in the handle; generations survive entry cleanup. */
        uint32_t generation = rt->sockets.generations[i];
        unsigned fd = generation * PS_SOCKET_MAX + i + 1;
        rt->sockets.generations[i] = generation == (INT_MAX-i-1)/PS_SOCKET_MAX ? 0 : generation+1;
        memset(s, 0, sizeof(*s));
        s->fd = (ps_fd_t)fd;
        s->allocated = s->open = 1;
        s->type = (uint8_t)type;
        return s;
    }
    return NULL;
}

struct ps_socket_entry *socket_bound(struct app_runtime *rt, int type, uint32_t ip_be, uint16_t port)
{
    if (!port) return NULL;
    for (unsigned i = 0; i < rt->sockets.capacity; i++) {
        struct ps_socket_entry *s = &rt->sockets.entries[i];
        if (s->allocated && s->type == type && s->local.port == port &&
            (!s->local.ip_be || s->local.ip_be == ip_be)) return s;
    }
    return NULL;
}

static int port_available(struct app_runtime *rt, struct ps_socket_entry *s,
                           const struct ps_sockaddr *addr)
{
    for (unsigned i = 0; i < rt->sockets.capacity; i++) {
        struct ps_socket_entry *other = &rt->sockets.entries[i];
        if (other != s && other->allocated && other->type == s->type &&
            other->local.port == addr->port && (!addr->ip_be || !other->local.ip_be ||
            addr->ip_be == other->local.ip_be)) return 0;
    }
    return 1;
}

int socket_bind(struct app_runtime *rt, struct ps_socket_entry *s, const struct ps_sockaddr *addr)
{
    if (!addr || s->local.port) return -EINVAL;
    if (addr->ip_be && !netif_is_local_ip(rt, addr->ip_be)) return -EADDRNOTAVAIL;
    struct ps_sockaddr local = *addr;
    if (!local.port) {
        for (unsigned i = 0; i < 16384; i++) {
            local.port = rt->sockets.next_port++;
            if (rt->sockets.next_port < 49152) rt->sockets.next_port = 49152;
            if (port_available(rt, s, &local)) break;
            local.port = 0;
        }
        if (!local.port) return -EADDRINUSE;
    } else if (!port_available(rt, s, &local)) return -EADDRINUSE;
    s->local = local;
    return 0;
}

static struct ps_socket_entry *get(struct app_runtime *rt, ps_fd_t fd)
{
    struct ps_socket_entry *s = rt ? socket_lookup(rt, fd) : NULL;
    return s && s->open ? s : NULL;
}

ps_fd_t core_socket(struct app_runtime *rt, int domain, int type, int protocol)
{
    if (!rt || !rt->sockets.capacity) return -ENETDOWN;
    if (rt->active_output) return -EBUSY;
    if (domain != PS_AF_INET) return -EAFNOSUPPORT;
    if (type != PS_SOCK_DGRAM && type != PS_SOCK_STREAM) return -EPROTOTYPE;
    if (protocol && protocol != (type == PS_SOCK_DGRAM ? 17 : 6)) return -EPROTONOSUPPORT;
    struct ps_socket_entry *s = socket_allocate(rt, type);
    return s ? s->fd : -EMFILE;
}

int core_bind(struct app_runtime *rt, ps_fd_t fd, const struct ps_sockaddr *addr)
{
    struct ps_socket_entry *s = get(rt, fd);
    if (!s) return -EBADF;
    return socket_bind(rt, s, addr);
}

int core_close(struct app_runtime *rt, ps_fd_t fd)
{
    struct ps_socket_entry *s = get(rt, fd);
    if (!s) return -EBADF;
    if (s->type == PS_SOCK_STREAM) tcp_close(rt, s, rte_get_timer_cycles());
    else memset(s, 0, sizeof(*s));
    return 0;
}

ssize_t core_sendto(struct app_runtime *rt, ps_fd_t fd, const void *buf, size_t len, const struct ps_sockaddr *dst)
{
    struct ps_socket_entry *s = get(rt, fd);
    if (!s) return -EBADF;
    if (s->type != PS_SOCK_DGRAM) return -EOPNOTSUPP;
    if (!dst || !dst->port || (!buf && len)) return -EINVAL;
    if (rt->active_output) return -EBUSY;
    if (!s->local.port) {
        int rc = socket_bind(rt, s, &(struct ps_sockaddr){0});
        if (rc) return rc;
    }
    return udp_send(rt, s, buf, len, dst);
}

ssize_t core_recvfrom(struct app_runtime *rt, ps_fd_t fd, void *buf, size_t len, struct ps_sockaddr *src)
{
    struct ps_socket_entry *s = get(rt, fd);
    if (!s) return -EBADF;
    if (s->type != PS_SOCK_DGRAM) return -EOPNOTSUPP;
    if (!src || (!buf && len)) return -EINVAL;
    return udp_recv(s, buf, len, src);
}

int core_connect(struct app_runtime *rt, ps_fd_t fd, const struct ps_sockaddr *addr)
{
    struct ps_socket_entry *s = get(rt, fd);
    if (!s) return -EBADF;
    if (!addr || !addr->port || !ipv4_destination_valid(rt, addr->ip_be)) return -EINVAL;
    if (s->type == PS_SOCK_STREAM) return tcp_connect(rt, s, addr);
    if (!s->local.port) {
        int rc = socket_bind(rt, s, &(struct ps_sockaddr){0});
        if (rc) return rc;
    }
    s->remote = *addr;
    return 0;
}

int core_listen(struct app_runtime *rt, ps_fd_t fd, int backlog)
{
    struct ps_socket_entry *s = get(rt, fd);
    if (!s) return -EBADF;
    if (s->type != PS_SOCK_STREAM) return -EOPNOTSUPP;
    return tcp_listen(s, backlog > (int)rt->sockets.capacity - 1 ? (int)rt->sockets.capacity - 1 : backlog);
}

ps_fd_t core_accept(struct app_runtime *rt, ps_fd_t fd, struct ps_sockaddr *peer)
{
    struct ps_socket_entry *s = get(rt, fd);
    if (!s) return -EBADF;
    if (s->type != PS_SOCK_STREAM) return -EOPNOTSUPP;
    return tcp_accept(rt, s, peer);
}

ssize_t core_send(struct app_runtime *rt, ps_fd_t fd, const void *buf, size_t len)
{
    struct ps_socket_entry *s = get(rt, fd);
    if (!s) return -EBADF;
    if (!buf && len) return -EINVAL;
    if (s->type == PS_SOCK_STREAM) return tcp_send(rt, s, buf, len);
    if (!s->remote.port) return -ENOTCONN;
    return core_sendto(rt, fd, buf, len, &s->remote);
}

ssize_t core_recv(struct app_runtime *rt, ps_fd_t fd, void *buf, size_t len)
{
    struct ps_socket_entry *s = get(rt, fd);
    if (!s) return -EBADF;
    if (!buf && len) return -EINVAL;
    if (s->type == PS_SOCK_STREAM) return tcp_recv(rt, s, buf, len);
    struct ps_sockaddr peer;
    return core_recvfrom(rt, fd, buf, len, &peer);
}
