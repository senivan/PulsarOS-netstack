#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include "runtime.h"

static struct app_runtime rt, other;

int main(void)
{
    assert(ps_socket(PS_AF_INET, PS_SOCK_DGRAM, 0) == -ENETDOWN);
    assert(socket_subsystem_init(&rt) == 0);
    assert(socket_subsystem_init(&other) == -EBUSY);
    assert(ps_socket(99, PS_SOCK_DGRAM, 0) == -EAFNOSUPPORT);
    assert(ps_socket(PS_AF_INET, 99, 0) == -EPROTOTYPE);
    assert(ps_socket(PS_AF_INET, PS_SOCK_DGRAM, 6) == -EPROTONOSUPPORT);
    assert(ps_close(-1) == -EBADF && ps_bind(-1, NULL) == -EBADF);
    ps_fd_t first = ps_socket(PS_AF_INET, PS_SOCK_DGRAM, 17);
    ps_fd_t second = ps_socket(PS_AF_INET, PS_SOCK_DGRAM, 0);
    struct ps_sockaddr addr = { .port = 9000 };
    assert(ps_bind(first, &addr) == 0);
    assert(ps_bind(second, &addr) == -EADDRINUSE);
    addr.ip_be = rte_cpu_to_be_32(RTE_IPV4(192u, 0, 2, 2));
    assert(ps_bind(second, &addr) == -EADDRNOTAVAIL);
    rt.port_count = 1;
    rt.ports[0].configured = rt.ports[0].started = 1;
    rt.ports[0].ip_be = addr.ip_be;
    assert(ps_bind(second, &addr) == -EADDRINUSE);
    assert(ps_close(first) == 0 && ps_close(first) == -EBADF);
    assert(ps_bind(second, &addr) == 0);
    ps_fd_t replacement = ps_socket(PS_AF_INET, PS_SOCK_DGRAM, 0);
    assert(replacement >= 0 && replacement != first);
    assert(!socket_bound(&rt, PS_SOCK_DGRAM, addr.ip_be, 0));
    assert(ps_send(first, "x", 1) == -EBADF);
    struct ps_sockaddr peer = { .ip_be = rte_cpu_to_be_32(RTE_IPV4(192u, 0, 2, 1)), .port = 1234 }, source;
    assert(udp_deliver(&rt, addr.ip_be, 9000, &peer, "hello", 5) == 0);
    char data[8];
    assert(ps_recvfrom(second, data, 4, &source) == -EMSGSIZE);
    assert(ps_recvfrom(second, data, sizeof(data), &source) == 5);
    assert(!memcmp(data, "hello", 5) && source.ip_be == peer.ip_be && source.port == peer.port);
    assert(ps_recvfrom(second, data, sizeof(data), &source) == -EAGAIN);
    assert(ps_connect(second, &peer) == 0);
    peer.port++;
    assert(udp_deliver(&rt, addr.ip_be, 9000, &peer, "x", 1) == -ENOENT);
    assert(ps_send(replacement, "x", 1) == -ENOTCONN);
    assert(ps_bind(replacement, &(struct ps_sockaddr){0}) == 0);
    assert(socket_lookup(&rt, replacement)->local.port >= 49152);
    ps_fd_t stream = ps_socket(PS_AF_INET, PS_SOCK_STREAM, 0);
    assert(stream >= 0 && ps_bind(stream, &addr) == 0 && ps_listen(stream, 2) == 0);
    assert(ps_accept(stream, NULL) == -EAGAIN);
    assert(ps_send(stream, "x", 1) == -ENOTCONN);
    assert(ps_recvfrom(stream, data, sizeof(data), &source) == -EOPNOTSUPP);
    assert(ps_close(stream) == 0);
    for (unsigned i = 2; i < PS_SOCKET_MAX; i++) assert(ps_socket(PS_AF_INET, PS_SOCK_STREAM, 0) >= 0);
    assert(ps_socket(PS_AF_INET, PS_SOCK_DGRAM, 0) == -EMFILE);
    socket_subsystem_fini(&rt);
    for (unsigned i = 0; i < PS_SOCKET_MAX; i++) assert(!rt.sockets.entries[i].allocated);
    puts("socket allocation, handles, binds, datagram delivery and lifetime passed");
    return 0;
}
