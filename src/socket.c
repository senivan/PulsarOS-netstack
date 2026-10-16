#include <errno.h>
#include <limits.h>
#include <string.h>
#include "runtime.h"

static struct app_runtime *active;

int socket_subsystem_init(struct app_runtime *rt)
{
    if (!rt) return -EINVAL;
    if (active) return -EBUSY;
    memset(&rt->sockets, 0, sizeof(rt->sockets));
    rt->sockets.next_fd = 1;
    rt->sockets.next_port = 49152;
    active = rt;
    return 0;
}

void socket_subsystem_fini(struct app_runtime *rt)
{
    if (active == rt) active = NULL;
    memset(&rt->sockets, 0, sizeof(rt->sockets));
}

struct ps_socket_entry *socket_lookup(struct app_runtime *rt, ps_fd_t fd)
{
    for (unsigned i = 0; i < PS_SOCKET_MAX; i++) {
        struct ps_socket_entry *s = &rt->sockets.entries[i];
        if (s->allocated && s->fd == fd) return s;
    }
    return NULL;
}

struct ps_socket_entry *socket_allocate(struct app_runtime *rt, int type)
{
    for (unsigned i = 0; i < PS_SOCKET_MAX; i++) {
        struct ps_socket_entry *s = &rt->sockets.entries[i];
        if (s->allocated) continue;
        unsigned fd;
        do {
            fd = rt->sockets.next_fd++;
            if (rt->sockets.next_fd > INT_MAX) rt->sockets.next_fd = 1;
        } while (socket_lookup(rt, (ps_fd_t)fd));
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
    for (unsigned i = 0; i < PS_SOCKET_MAX; i++) {
        struct ps_socket_entry *s = &rt->sockets.entries[i];
        if (s->allocated && s->type == type && s->local.port == port &&
            (!s->local.ip_be || s->local.ip_be == ip_be)) return s;
    }
    return NULL;
}

static int port_available(struct app_runtime *rt, struct ps_socket_entry *s,
                           const struct ps_sockaddr *addr)
{
    for (unsigned i = 0; i < PS_SOCKET_MAX; i++) {
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

static struct ps_socket_entry *get(ps_fd_t fd)
{
    struct ps_socket_entry *s = active ? socket_lookup(active, fd) : NULL;
    return s && s->open ? s : NULL;
}

ps_fd_t ps_socket(int domain, int type, int protocol)
{
    if (!active) return -ENETDOWN;
    if (active->active_output) return -EBUSY;
    if (domain != PS_AF_INET) return -EAFNOSUPPORT;
    if (type != PS_SOCK_DGRAM && type != PS_SOCK_STREAM) return -EPROTOTYPE;
    if (protocol && protocol != (type == PS_SOCK_DGRAM ? 17 : 6)) return -EPROTONOSUPPORT;
    struct ps_socket_entry *s = socket_allocate(active, type);
    return s ? s->fd : -EMFILE;
}

int ps_bind(ps_fd_t fd, const struct ps_sockaddr *addr)
{
    struct ps_socket_entry *s = get(fd);
    if (!s) return -EBADF;
    return socket_bind(active, s, addr);
}

int ps_close(ps_fd_t fd)
{
    struct ps_socket_entry *s = get(fd);
    if (!s) return -EBADF;
    memset(s, 0, sizeof(*s));
    return 0;
}

ssize_t ps_sendto(ps_fd_t fd, const void *buf, size_t len, const struct ps_sockaddr *dst)
{
    struct ps_socket_entry *s = get(fd);
    if (!s) return -EBADF;
    if (s->type != PS_SOCK_DGRAM) return -EOPNOTSUPP;
    if (!dst || !dst->port || (!buf && len)) return -EINVAL;
    if (active->active_output) return -EBUSY;
    if (!s->local.port) {
        int rc = socket_bind(active, s, &(struct ps_sockaddr){0});
        if (rc) return rc;
    }
    return udp_send(active, s, buf, len, dst);
}

ssize_t ps_recvfrom(ps_fd_t fd, void *buf, size_t len, struct ps_sockaddr *src)
{
    struct ps_socket_entry *s = get(fd);
    if (!s) return -EBADF;
    if (s->type != PS_SOCK_DGRAM) return -EOPNOTSUPP;
    if (!src || (!buf && len)) return -EINVAL;
    return udp_recv(s, buf, len, src);
}

int ps_connect(ps_fd_t fd, const struct ps_sockaddr *addr)
{
    struct ps_socket_entry *s = get(fd);
    if (!s) return -EBADF;
    if (!addr || !addr->port || !ipv4_destination_valid(active, addr->ip_be)) return -EINVAL;
    if (s->type == PS_SOCK_STREAM) return -EOPNOTSUPP;
    if (!s->local.port) {
        int rc = socket_bind(active, s, &(struct ps_sockaddr){0});
        if (rc) return rc;
    }
    s->remote = *addr;
    return 0;
}

int ps_listen(ps_fd_t fd, int backlog)
{
    (void)backlog;
    return get(fd) ? -EOPNOTSUPP : -EBADF;
}

ps_fd_t ps_accept(ps_fd_t fd, struct ps_sockaddr *peer)
{
    (void)peer;
    return get(fd) ? -EOPNOTSUPP : -EBADF;
}

ssize_t ps_send(ps_fd_t fd, const void *buf, size_t len)
{
    struct ps_socket_entry *s = get(fd);
    if (!s) return -EBADF;
    if (s->type != PS_SOCK_DGRAM) return -EOPNOTSUPP;
    if (!s->remote.port) return -ENOTCONN;
    return ps_sendto(fd, buf, len, &s->remote);
}

ssize_t ps_recv(ps_fd_t fd, void *buf, size_t len)
{
    struct ps_sockaddr peer;
    return ps_recvfrom(fd, buf, len, &peer);
}
