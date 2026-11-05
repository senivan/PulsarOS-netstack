#define _GNU_SOURCE
#include <assert.h>
#include <arpa/inet.h>
#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <poll.h>
#include <sys/eventfd.h>
#include <unistd.h>
#include "daemon.h"
#include "runtime.h"

static struct app_runtime rt;
static struct daemon_queue queue;

static struct ipc_message dispatch(uint64_t owner, uint32_t op, int fd, int arg)
{
    struct daemon_item in = { .owner = owner, .message = { .id = 1, .op = op, .fd = fd, .a = arg } }, out;
    if (op == IPC_SOCKET) { in.message.a = PS_AF_INET; in.message.b = arg; }
    if (op == IPC_BIND) in.message.addr.port = (uint16_t)arg;
    daemon_dispatch(&rt, &in, &out);
    return out.message;
}

static void *produce(void *unused)
{
    (void)unused;
    for (unsigned i = 1; i <= 4096; i++) {
        struct daemon_item item = { .owner = i, .message = { .id = i, .length = 1 } };
        item.message.data[0] = (uint8_t)i;
        while (daemon_queue_push(&queue, &item)) sched_yield();
    }
    return NULL;
}

static void batches(void)
{
    int fd = dispatch(1, IPC_SOCKET, 0, PS_SOCK_DGRAM).result;
    assert(dispatch(1, IPC_BIND, fd, 9001).result == 0);
    struct ps_sockaddr peer = { .ip_be = inet_addr("192.0.2.1"), .port = 1234 };
    struct daemon_item in = { .owner = 1, .message = { .op = IPC_RECVMMSG, .id = 1,
        .fd = fd, .a = 3, .length = 12 } }, out;
    uint32_t cap = htonl(PS_DGRAM_MAX_PAYLOAD);
    for (unsigned i = 0; i < 3; i++) memcpy(in.message.data + i * 4, &cap, 4);
    assert(udp_deliver(&rt, 0, 9001, &peer, "", 0) == 0);
    assert(udp_deliver(&rt, 0, 9001, &peer, "abc", 3) == 0);
    in.owner = 2;
    daemon_dispatch(&rt, &in, &out);
    assert(out.message.result == -EBADF && socket_lookup(&rt, fd)->transport.udp.count == 2);
    in.owner = 1;
    daemon_dispatch(&rt, &in, &out);
    assert(out.message.result == 2 && !socket_lookup(&rt, fd)->transport.udp.count);
    struct ps_sockaddr source;
    uint32_t length;
    assert(!ipc_datagram_decode(out.message.data, out.message.length, &source, &length));
    assert(!length && source.ip_be == peer.ip_be && source.port == peer.port);
    assert(!ipc_datagram_decode(out.message.data + 12, out.message.length - 12, &source, &length));
    assert(length == 3 && !memcmp(out.message.data + 24, "abc", 3));
    daemon_dispatch(&rt, &in, &out);
    assert(out.message.result == -EAGAIN);
    uint8_t payload[PS_DGRAM_MAX_PAYLOAD] = {0};
    for (unsigned i = 0; i < PS_DGRAM_BATCH_MAX; i++) assert(!udp_deliver(&rt, 0, 9001, &peer, payload, sizeof(payload)));
    in.message.a = PS_DGRAM_BATCH_MAX;
    in.message.length = PS_DGRAM_BATCH_MAX * 4;
    for (unsigned i = 0; i < PS_DGRAM_BATCH_MAX; i++) memcpy(in.message.data + i * 4, &cap, 4);
    cap = htonl(PS_DGRAM_MAX_PAYLOAD + 1);
    memcpy(in.message.data, &cap, 4);
    daemon_dispatch(&rt, &in, &out);
    assert(out.message.result == -EINVAL && socket_lookup(&rt, fd)->transport.udp.count == 16);
    cap = htonl(1);
    memcpy(in.message.data, &cap, 4);
    daemon_dispatch(&rt, &in, &out);
    assert(out.message.result == -EMSGSIZE && socket_lookup(&rt, fd)->transport.udp.count == 16);
    cap = htonl(PS_DGRAM_MAX_PAYLOAD);
    memcpy(in.message.data, &cap, 4);
    daemon_dispatch(&rt, &in, &out);
    assert(out.message.result == 5 && out.message.length == 5 * (IPC_DGRAM_HEADER + PS_DGRAM_MAX_PAYLOAD));
    assert(socket_lookup(&rt, fd)->transport.udp.count == 11);
    in.message.op = IPC_SENDMMSG;
    in.message.a = 2;
    in.message.length = 2 * IPC_DGRAM_HEADER;
    ipc_datagram_encode(in.message.data, &peer, 0);
    ipc_datagram_encode(in.message.data + IPC_DGRAM_HEADER, &peer, 1);
    uint64_t drops = rt.graph.nodes[NODE_UDP_OUTPUT].stats.drops;
    daemon_dispatch(&rt, &in, &out);
    assert(out.message.result == -EINVAL && rt.graph.nodes[NODE_UDP_OUTPUT].stats.drops == drops);
    in.message.length = IPC_DGRAM_HEADER;
    in.message.a = 1;
    peer.port = 0;
    ipc_datagram_encode(in.message.data, &peer, 0);
    daemon_dispatch(&rt, &in, &out);
    assert(out.message.result == -EINVAL);
    int stream = dispatch(1, IPC_SOCKET, 0, PS_SOCK_STREAM).result;
    in.message.fd = stream;
    daemon_dispatch(&rt, &in, &out);
    assert(out.message.result == -EOPNOTSUPP);
    assert(core_close(&rt, stream) == 0 && core_close(&rt, fd) == 0);
}

int main(void)
{
    daemon_queue_init(&queue);
    struct daemon_item item = {0};
    assert(daemon_queue_pop(&queue, &item) < 0);
    for (unsigned i = 0; i < DAEMON_QUEUE_SIZE; i++) assert(!daemon_queue_push(&queue, &item));
    assert(!daemon_queue_room(&queue) && daemon_queue_push(&queue, &item) < 0);
    for (unsigned i = 0; i < DAEMON_QUEUE_SIZE; i++) assert(!daemon_queue_pop(&queue, &item));
    atomic_store(&queue.read, UINT_MAX - 2);
    atomic_store(&queue.write, UINT_MAX - 2);
    for (unsigned i = 0; i < 4; i++) assert(!daemon_queue_push(&queue, &item) && !daemon_queue_pop(&queue, &item));
    pthread_t producer;
    assert(!pthread_create(&producer, NULL, produce, NULL));
    for (unsigned i = 1; i <= 4096; i++) {
        while (daemon_queue_pop(&queue, &item)) sched_yield();
        assert(item.owner == i && item.message.id == i && item.message.data[0] == (uint8_t)i);
    }
    assert(!pthread_join(producer, NULL));

    assert(!socket_subsystem_init(&rt));
    batches();
    int a = dispatch(1, IPC_SOCKET, 0, PS_SOCK_DGRAM).result;
    int b = dispatch(2, IPC_SOCKET, 0, PS_SOCK_DGRAM).result;
    assert(a > 0 && b > 0 && a != b);
    assert(dispatch(1, IPC_BIND, a, 9000).result == 0);
    const uint32_t ops[] = {IPC_BIND, IPC_CONNECT, IPC_LISTEN, IPC_ACCEPT, IPC_SEND, IPC_RECV,
        IPC_SENDTO, IPC_RECVFROM, IPC_CLOSE};
    for (unsigned i = 0; i < sizeof(ops) / sizeof(ops[0]); i++) assert(dispatch(2, ops[i], a, 0).result == -EBADF);
    assert(dispatch(2, IPC_BIND, b, 9000).result == -EADDRINUSE);
    int stream = dispatch(2, IPC_SOCKET, 0, PS_SOCK_STREAM).result;
    assert(dispatch(2, IPC_BIND, stream, 9000).result == 0);
    assert(dispatch(1, IPC_CLEANUP, 0, 0).result == 0);
    assert(!socket_lookup(&rt, a) && socket_lookup(&rt, b));
    assert(dispatch(2, IPC_BIND, b, 9000).result == 0);
    for (unsigned i = 0; i < 40; i++) assert(dispatch(1, IPC_SOCKET, 0, PS_SOCK_DGRAM).result > 0);
    assert(!dispatch(1, IPC_CLEANUP, 0, 0).result && !dispatch(2, IPC_CLEANUP, 0, 0).result);
    for (unsigned i = 0; i < PS_SOCKET_MAX; i++) assert(!rt.sockets.entries[i].allocated);
    rt.sockets.capacity = 2;
    assert(dispatch(1, IPC_SOCKET, 0, PS_SOCK_DGRAM).result > 0);
    assert(dispatch(2, IPC_SOCKET, 0, PS_SOCK_DGRAM).result > 0);
    assert(dispatch(1, IPC_SOCKET, 0, PS_SOCK_DGRAM).result == -EMFILE);
    dispatch(1, IPC_CLEANUP, 0, 0);
    dispatch(2, IPC_CLEANUP, 0, 0);

    struct daemon_service *service = calloc(1, sizeof(*service));
    assert(service);
    service->response_fd = eventfd(0, EFD_NONBLOCK | EFD_CLOEXEC);
    assert(service->response_fd >= 0);
    daemon_queue_init(&service->requests);
    daemon_queue_init(&service->responses);
    for (unsigned i = 0; i < DAEMON_QUEUE_SIZE; i++) assert(!daemon_queue_push(&service->responses, &item));
    item = (struct daemon_item){ .owner = 1, .message = { .op = IPC_SOCKET, .id = 5,
        .a = PS_AF_INET, .b = PS_SOCK_DGRAM } };
    assert(!daemon_queue_push(&service->requests, &item));
    assert(!daemon_progress(service, &rt));
    struct pollfd notification = { .fd = service->response_fd, .events = POLLIN };
    assert(poll(&notification, 1, 0) == 0);
    assert(!daemon_queue_pop(&service->responses, &item));
    assert(daemon_progress(service, &rt) == 1);
    assert(poll(&notification, 1, 0) == 1 && (notification.revents & POLLIN));
    uint64_t wakes;
    assert(read(service->response_fd, &wakes, sizeof(wakes)) == sizeof(wakes) && wakes == 1);
    for (unsigned i = 0; i < DAEMON_QUEUE_SIZE; i++) assert(!daemon_queue_pop(&service->responses, &item));
    assert(item.message.id == 5 && item.message.result > 0);
    item.message.result = 0;
    item.message.id++;
    assert(!daemon_queue_push(&service->requests, &item));
    assert(daemon_progress(service, &rt) == 1);
    assert(read(service->response_fd, &wakes, sizeof(wakes)) == sizeof(wakes) && wakes == 1);
    assert(!daemon_queue_pop(&service->responses, &item));
    wakes = UINT64_MAX - 1;
    assert(write(service->response_fd, &wakes, sizeof(wakes)) == sizeof(wakes));
    item.message.result = 0;
    item.message.id++;
    assert(!daemon_queue_push(&service->requests, &item) && daemon_progress(service, &rt) == 1);
    assert(!atomic_load(&service->failed));
    assert(read(service->response_fd, &wakes, sizeof(wakes)) == sizeof(wakes) && wakes == UINT64_MAX - 1);
    close(service->response_fd);
    free(service);
    dispatch(1, IPC_CLEANUP, 0, 0);
    socket_subsystem_fini(&rt);
    puts("SPSC saturation/wrap/concurrency, ownership, shared capacity and cleanup passed");
    return 0;
}
