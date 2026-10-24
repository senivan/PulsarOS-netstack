#define _GNU_SOURCE
#include <assert.h>
#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
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
    daemon_queue_init(&service->requests);
    daemon_queue_init(&service->responses);
    for (unsigned i = 0; i < DAEMON_QUEUE_SIZE; i++) assert(!daemon_queue_push(&service->responses, &item));
    item = (struct daemon_item){ .owner = 1, .message = { .op = IPC_SOCKET, .id = 5,
        .a = PS_AF_INET, .b = PS_SOCK_DGRAM } };
    assert(!daemon_queue_push(&service->requests, &item));
    assert(!daemon_progress(service, &rt));
    assert(!daemon_queue_pop(&service->responses, &item));
    assert(daemon_progress(service, &rt) == 1);
    free(service);
    dispatch(1, IPC_CLEANUP, 0, 0);
    socket_subsystem_fini(&rt);
    puts("SPSC saturation/wrap/concurrency, ownership, shared capacity and cleanup passed");
    return 0;
}
