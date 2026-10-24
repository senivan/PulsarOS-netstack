#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include "runtime.h"

static struct app_runtime rt, other;

int main(void)
{
    assert(core_socket(&rt, PS_AF_INET, PS_SOCK_DGRAM, 0) == -ENETDOWN);
    assert(socket_subsystem_init(&rt) == 0);
    assert(socket_subsystem_init(&other) == 0);
    assert(core_socket(&other, PS_AF_INET, PS_SOCK_DGRAM, 0) > 0);
    socket_subsystem_fini(&other);
    assert(core_socket(&rt, 99, PS_SOCK_DGRAM, 0) == -EAFNOSUPPORT);
    assert(core_socket(&rt, PS_AF_INET, 99, 0) == -EPROTOTYPE);
    assert(core_socket(&rt, PS_AF_INET, PS_SOCK_DGRAM, 6) == -EPROTONOSUPPORT);
    assert(core_close(&rt, -1) == -EBADF && core_bind(&rt, -1, NULL) == -EBADF);
    ps_fd_t first = core_socket(&rt, PS_AF_INET, PS_SOCK_DGRAM, 17);
    ps_fd_t second = core_socket(&rt, PS_AF_INET, PS_SOCK_DGRAM, 0);
    struct ps_sockaddr addr = { .port = 9000 };
    assert(core_bind(&rt, first, &addr) == 0);
    assert(core_bind(&rt, second, &addr) == -EADDRINUSE);
    addr.ip_be = rte_cpu_to_be_32(RTE_IPV4(192u, 0, 2, 2));
    assert(core_bind(&rt, second, &addr) == -EADDRNOTAVAIL);
    rt.port_count = 1;
    rt.ports[0].configured = rt.ports[0].started = 1;
    rt.ports[0].ip_be = addr.ip_be;
    assert(core_bind(&rt, second, &addr) == -EADDRINUSE);
    assert(core_close(&rt, first) == 0 && core_close(&rt, first) == -EBADF);
    assert(core_bind(&rt, second, &addr) == 0);
    ps_fd_t replacement = core_socket(&rt, PS_AF_INET, PS_SOCK_DGRAM, 0);
    assert(replacement >= 0 && replacement != first);
    assert(!socket_bound(&rt, PS_SOCK_DGRAM, addr.ip_be, 0));
    assert(core_send(&rt, first, "x", 1) == -EBADF);
    struct ps_sockaddr peer = { .ip_be = rte_cpu_to_be_32(RTE_IPV4(192u, 0, 2, 1)), .port = 1234 }, source;
    assert(udp_deliver(&rt, addr.ip_be, 9000, &peer, "hello", 5) == 0);
    char data[8];
    assert(core_recvfrom(&rt, second, data, 4, &source) == -EMSGSIZE);
    assert(core_recvfrom(&rt, second, data, sizeof(data), &source) == 5);
    assert(!memcmp(data, "hello", 5) && source.ip_be == peer.ip_be && source.port == peer.port);
    assert(core_recvfrom(&rt, second, data, sizeof(data), &source) == -EAGAIN);
    assert(core_connect(&rt, second, &peer) == 0);
    peer.port++;
    assert(udp_deliver(&rt, addr.ip_be, 9000, &peer, "x", 1) == -ENOENT);
    assert(core_send(&rt, replacement, "x", 1) == -ENOTCONN);
    assert(core_bind(&rt, replacement, &(struct ps_sockaddr){0}) == 0);
    assert(socket_lookup(&rt, replacement)->local.port >= 49152);
    ps_fd_t stream = core_socket(&rt, PS_AF_INET, PS_SOCK_STREAM, 0);
    assert(stream >= 0 && core_bind(&rt, stream, &addr) == 0 && core_listen(&rt, stream, 2) == 0);
    assert(core_accept(&rt, stream, NULL) == -EAGAIN);
    assert(core_send(&rt, stream, "x", 1) == -ENOTCONN);
    assert(core_recvfrom(&rt, stream, data, sizeof(data), &source) == -EOPNOTSUPP);
    assert(core_close(&rt, stream) == 0);
    for (unsigned i = 2; i < PS_SOCKET_MAX; i++) assert(core_socket(&rt, PS_AF_INET, PS_SOCK_STREAM, 0) >= 0);
    assert(core_socket(&rt, PS_AF_INET, PS_SOCK_DGRAM, 0) == -EMFILE);
    socket_subsystem_fini(&rt);
    for (unsigned i = 0; i < PS_SOCKET_MAX; i++) assert(!rt.sockets.entries[i].allocated);
    puts("socket allocation, handles, binds, datagram delivery and lifetime passed");
    return 0;
}
