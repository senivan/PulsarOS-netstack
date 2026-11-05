#include <errno.h>
#include <arpa/inet.h>
#include <string.h>
#include <unistd.h>
#include "daemon.h"
#include "runtime.h"

static void send_batch(struct app_runtime *rt, const struct ipc_message *in, struct ipc_message *out)
{
    struct ps_sockaddr destinations[PS_DGRAM_BATCH_MAX];
    uint32_t lengths[PS_DGRAM_BATCH_MAX];
    unsigned offsets[PS_DGRAM_BATCH_MAX], used = 0;
    for (int i = 0; i < in->a; i++) {
        offsets[i] = used + IPC_DGRAM_HEADER;
        if (ipc_datagram_decode(in->data + used, in->length - used, &destinations[i], &lengths[i])) {
            out->result = -EINVAL;
            return;
        }
        used += IPC_DGRAM_HEADER + lengths[i];
    }
    if (used != in->length) { out->result = -EINVAL; return; }
    for (int i = 0; i < in->a; i++) {
        ssize_t n = core_sendto(rt, in->fd, in->data + offsets[i], lengths[i], &destinations[i]);
        if (n < 0) { out->result = i ? i : (int)n; return; }
        out->result = i + 1;
    }
}

static void receive_batch(struct app_runtime *rt, const struct ipc_message *in, struct ipc_message *out)
{
    uint32_t capacities[PS_DGRAM_BATCH_MAX];
    for (int i = 0; i < in->a; i++) {
        memcpy(&capacities[i], in->data + i * 4, 4);
        capacities[i] = ntohl(capacities[i]);
        if (capacities[i] > PS_DGRAM_MAX_PAYLOAD) { out->result = -EINVAL; return; }
    }
    for (int i = 0; i < in->a; i++) {
        if (IPC_PAYLOAD_MAX - out->length < IPC_DGRAM_HEADER) break;
        uint32_t available = IPC_PAYLOAD_MAX - out->length - IPC_DGRAM_HEADER;
        size_t capacity = capacities[i] < available ? capacities[i] : available;
        struct ps_sockaddr source;
        ssize_t n = core_recvfrom(rt, in->fd, out->data + out->length + IPC_DGRAM_HEADER, capacity, &source);
        if (n < 0) { if (!i) out->result = (int)n; return; }
        ipc_datagram_encode(out->data + out->length, &source, (uint32_t)n);
        out->length += IPC_DGRAM_HEADER + (uint32_t)n;
        out->result = i + 1;
    }
}

void daemon_dispatch(struct app_runtime *rt, const struct daemon_item *request, struct daemon_item *response)
{
    const struct ipc_message *in = &request->message;
    *response = (struct daemon_item){ .owner = request->owner,
        .message = { .op = in->op, .id = in->id, .fd = in->fd, .result = -EOPNOTSUPP } };
    struct ipc_message *out = &response->message;
    if (!request->owner) { out->result = -EINVAL; return; }
    if (in->op == IPC_CLEANUP) {
        for (unsigned i = 0; i < rt->sockets.capacity; i++) {
            struct ps_socket_entry *s = &rt->sockets.entries[i];
            if (s->allocated && s->open && s->owner == request->owner) core_close(rt, s->fd);
        }
        out->result = 0;
        return;
    }
    if (!ipc_request_valid(in)) { out->result = -EINVAL; return; }
    if (in->op == IPC_SOCKET) {
        out->result = core_socket(rt, in->a, in->b, in->c);
        if (out->result >= 0) socket_lookup(rt, out->result)->owner = request->owner;
        return;
    }
    struct ps_socket_entry *s = socket_lookup(rt, in->fd);
    if (!s || !s->open || s->owner != request->owner) { out->result = -EBADF; return; }
    if ((in->op == IPC_SENDMMSG || in->op == IPC_RECVMMSG) && s->type != PS_SOCK_DGRAM) {
        out->result = -EOPNOTSUPP;
        return;
    }
    switch (in->op) {
    case IPC_BIND: out->result = core_bind(rt, in->fd, &in->addr); break;
    case IPC_CONNECT: out->result = core_connect(rt, in->fd, &in->addr); break;
    case IPC_LISTEN: out->result = core_listen(rt, in->fd, in->a); break;
    case IPC_ACCEPT: out->result = core_accept(rt, in->fd, &out->addr); break;
    case IPC_CLOSE: out->result = core_close(rt, in->fd); break;
    case IPC_SEND: out->result = core_send(rt, in->fd, in->data, in->length); break;
    case IPC_SENDTO: out->result = core_sendto(rt, in->fd, in->data, in->length, &in->addr); break;
    case IPC_RECV: out->result = core_recv(rt, in->fd, out->data, (size_t)in->a); break;
    case IPC_RECVFROM: out->result = core_recvfrom(rt, in->fd, out->data, (size_t)in->a, &out->addr); break;
    case IPC_SENDMMSG: send_batch(rt, in, out); break;
    case IPC_RECVMMSG: receive_batch(rt, in, out); break;
    default: break;
    }
    if ((in->op == IPC_RECV || in->op == IPC_RECVFROM) && out->result >= 0) out->length = (uint32_t)out->result;
}

unsigned daemon_progress(struct daemon_service *service, struct app_runtime *rt)
{
    struct daemon_item request, response;
    unsigned count = 0;
    while (count < 16 && daemon_queue_room(&service->responses) && !daemon_queue_pop(&service->requests, &request)) {
        daemon_dispatch(rt, &request, &response);
        /* This thread is the sole response producer; room cannot disappear. */
        daemon_queue_push(&service->responses, &response);
        count++;
    }
    if (count) {
        /* Publish before waking the consumer; a saturated eventfd is already readable. */
        uint64_t notification = 1;
        ssize_t n;
        do { n = write(service->response_fd, &notification, sizeof(notification)); }
        while (n < 0 && errno == EINTR);
        if (n < 0 && errno != EAGAIN) atomic_store(&service->failed, 1);
    }
    return count;
}
