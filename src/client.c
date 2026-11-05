#define _POSIX_C_SOURCE 200809L
#include <errno.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <limits.h>
#include <poll.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <time.h>
#include <unistd.h>
#include "ipc.h"

/* Only client-side session state is process-local. Transport state is remote. */
static struct { int fd, error; uint32_t next_id, features; pid_t pid; } client = { .fd = -1 };

static int64_t milliseconds(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (int64_t)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

static int wait_socket(short events, int64_t deadline)
{
    for (;;) {
        int64_t remaining = deadline - milliseconds();
        if (remaining <= 0) return -ETIMEDOUT;
        struct pollfd p = { .fd = client.fd, .events = events };
        int rc = poll(&p, 1, (int)remaining);
        if (rc < 0) { if (errno == EINTR) continue; return -errno; }
        if (!rc) return -ETIMEDOUT;
        if (p.revents & events) return 0;
        if (p.revents & (POLLERR | POLLHUP | POLLNVAL)) return -ECONNRESET;
    }
}

static int transfer(void *data, size_t size, int writing, int64_t deadline)
{
    uint8_t *p = data;
    while (size) {
        int rc = wait_socket(writing ? POLLOUT : POLLIN, deadline);
        if (rc) return rc;
        ssize_t n = writing ? send(client.fd, p, size, MSG_NOSIGNAL) : recv(client.fd, p, size, 0);
        if (n < 0) { if (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK) continue; return -errno; }
        if (!n) return -ECONNRESET;
        p += n;
        size -= (size_t)n;
    }
    return 0;
}

static int broken(int error)
{
    if (client.fd >= 0) close(client.fd);
    client.fd = -1;
    client.error = -ECONNRESET;
    return error;
}

static int request(struct ipc_message *m)
{
    if (client.pid != getpid()) {
        if (client.fd >= 0) close(client.fd);
        client.fd = -1;
        client.error = 0;
        client.pid = getpid();
    }
    if (client.fd < 0) return client.error ? client.error : -ENOTCONN;
    m->id = ++client.next_id;
    if (!m->id) m->id = ++client.next_id;
    uint32_t id = m->id, op = m->op;
    uint8_t header[IPC_HEADER_SIZE];
    ipc_encode(header, m);
    int64_t deadline = milliseconds() + IPC_TIMEOUT_MS;
    int rc = transfer(header, sizeof(header), 1, deadline);
    if (!rc && m->length) rc = transfer(m->data, m->length, 1, deadline);
    if (!rc) rc = transfer(header, sizeof(header), 0, deadline);
    if (!rc) rc = ipc_decode(header, m);
    if (!rc && (m->id != id || m->op != op || (m->result < 0 && m->length))) rc = -EPROTO;
    if (!rc && m->length) rc = transfer(m->data, m->length, 0, deadline);
    if (rc) return broken(rc);
    return m->result;
}

int ps_init(const char *path)
{
    if (client.pid == getpid() && client.fd >= 0) return -EALREADY;
    ps_fini();
    client.pid = getpid();
    if (!path) path = PS_DEFAULT_SOCKET;
    struct sockaddr_un addr = { .sun_family = AF_UNIX };
    if (!*path || strlen(path) >= sizeof(addr.sun_path)) return -ENAMETOOLONG;
    memcpy(addr.sun_path, path, strlen(path) + 1);
    client.fd = socket(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
    if (client.fd < 0) return -errno;
    int rc = connect(client.fd, (const struct sockaddr *)&addr, sizeof(addr));
    if (rc && errno != EINPROGRESS) return broken(-errno);
    if (rc) {
        rc = wait_socket(POLLOUT, milliseconds() + IPC_TIMEOUT_MS);
        if (rc) return broken(rc);
        int error = 0;
        socklen_t size = sizeof(error);
        if (getsockopt(client.fd, SOL_SOCKET, SO_ERROR, &error, &size)) return broken(-errno);
        if (error) return broken(-error);
    }
    struct ipc_message m = { .op = IPC_HELLO };
    rc = request(&m);
    if (rc) return broken(rc);
    client.features = (uint32_t)m.b;
    return 0;
}

void ps_fini(void)
{
    if (client.fd >= 0) close(client.fd);
    client.fd = -1;
    client.error = 0;
    client.next_id = 0;
    client.features = 0;
    client.pid = getpid();
}

ps_fd_t ps_socket(int domain, int type, int protocol)
{
    struct ipc_message m = { .op = IPC_SOCKET, .a = domain, .b = type, .c = protocol };
    return request(&m);
}

static int address_request(uint32_t op, ps_fd_t fd, const struct ps_sockaddr *addr)
{
    if (!addr) return -EINVAL;
    struct ipc_message m = { .op = op, .fd = fd, .addr = *addr };
    return request(&m);
}

int ps_bind(ps_fd_t fd, const struct ps_sockaddr *addr) { return address_request(IPC_BIND, fd, addr); }
int ps_connect(ps_fd_t fd, const struct ps_sockaddr *addr) { return address_request(IPC_CONNECT, fd, addr); }
int ps_close(ps_fd_t fd)
{
    struct ipc_message m = { .op = IPC_CLOSE, .fd = fd };
    return request(&m);
}
int ps_listen(ps_fd_t fd, int backlog)
{
    struct ipc_message m = { .op = IPC_LISTEN, .fd = fd, .a = backlog };
    return request(&m);
}
ps_fd_t ps_accept(ps_fd_t fd, struct ps_sockaddr *peer)
{
    struct ipc_message m = { .op = IPC_ACCEPT, .fd = fd };
    int rc = request(&m);
    if (rc >= 0 && peer) *peer = m.addr;
    return rc;
}

static ssize_t send_request(uint32_t op, ps_fd_t fd, const void *buf, size_t len, const struct ps_sockaddr *dst)
{
    if (!buf && len) return -EINVAL;
    if (op == IPC_SENDTO && (!dst || len > PS_DGRAM_MAX_PAYLOAD)) return dst ? -EMSGSIZE : -EINVAL;
    struct ipc_message m = { .op = op, .fd = fd };
    m.length = len > IPC_PAYLOAD_MAX ? IPC_PAYLOAD_MAX : (uint32_t)len;
    if (dst) m.addr = *dst;
    if (m.length) memcpy(m.data, buf, m.length);
    int rc = request(&m);
    if (rc >= 0 && (uint32_t)rc > (len < IPC_PAYLOAD_MAX ? len : IPC_PAYLOAD_MAX)) return broken(-EPROTO);
    return rc;
}
ssize_t ps_send(ps_fd_t fd, const void *buf, size_t len) { return send_request(IPC_SEND, fd, buf, len, NULL); }
ssize_t ps_sendto(ps_fd_t fd, const void *buf, size_t len, const struct ps_sockaddr *dst)
{
    return send_request(IPC_SENDTO, fd, buf, len, dst);
}

static ssize_t recv_request(uint32_t op, ps_fd_t fd, void *buf, size_t len, struct ps_sockaddr *src)
{
    if (!buf && len) return -EINVAL;
    struct ipc_message m = { .op = op, .fd = fd, .a = len > IPC_PAYLOAD_MAX ? IPC_PAYLOAD_MAX : (int32_t)len };
    uint32_t requested = (uint32_t)m.a;
    int rc = request(&m);
    if (rc < 0) return rc;
    if ((uint32_t)rc != m.length || m.length > requested) return broken(-EPROTO);
    if (m.length) memcpy(buf, m.data, m.length);
    if (src) *src = m.addr;
    return rc;
}
ssize_t ps_recv(ps_fd_t fd, void *buf, size_t len) { return recv_request(IPC_RECV, fd, buf, len, NULL); }
ssize_t ps_recvfrom(ps_fd_t fd, void *buf, size_t len, struct ps_sockaddr *src)
{
    if (!src) return -EINVAL;
    return recv_request(IPC_RECVFROM, fd, buf, len, src);
}

static int batch_valid(const struct ps_mmsg *messages, unsigned count)
{
    if (client.pid != getpid()) { ps_fini(); return -ENOTCONN; }
    if (client.fd < 0) return client.error ? client.error : -ENOTCONN;
    if (!messages || !count || count > PS_DGRAM_BATCH_MAX) return -EINVAL;
    if (!(client.features & IPC_FEATURE_DGRAM_BATCH)) return -EOPNOTSUPP;
    return 0;
}

int ps_sendmmsg(ps_fd_t fd, const struct ps_mmsg *messages, unsigned count)
{
    int error = batch_valid(messages, count);
    if (error) return error;
    struct ipc_message m = { .op = IPC_SENDMMSG, .fd = fd };
    for (unsigned i = 0; i < count; i++) {
        const struct ps_mmsg *message = &messages[i];
        if (!message->data && message->len) return -EINVAL;
        if (message->len > PS_DGRAM_MAX_PAYLOAD) return -EMSGSIZE;
        if (IPC_DGRAM_HEADER + message->len > IPC_PAYLOAD_MAX - m.length) break;
        ipc_datagram_encode(m.data + m.length, &message->addr, (uint32_t)message->len);
        if (message->len) memcpy(m.data + m.length + IPC_DGRAM_HEADER, message->data, message->len);
        m.length += IPC_DGRAM_HEADER + (uint32_t)message->len;
        m.a++;
    }
    unsigned encoded = (unsigned)m.a;
    int result = request(&m);
    if (result >= 0 && (!result || (unsigned)result > encoded || m.length)) return broken(-EPROTO);
    return result;
}

int ps_recvmmsg(ps_fd_t fd, struct ps_mmsg *messages, unsigned count)
{
    int error = batch_valid(messages, count);
    if (error) return error;
    struct ipc_message m = { .op = IPC_RECVMMSG, .fd = fd, .a = (int32_t)count, .length = count * 4 };
    for (unsigned i = 0; i < count; i++) {
        if (!messages[i].data && messages[i].len) return -EINVAL;
        uint32_t capacity = htonl(messages[i].len > PS_DGRAM_MAX_PAYLOAD ? PS_DGRAM_MAX_PAYLOAD : (uint32_t)messages[i].len);
        memcpy(m.data + i * 4, &capacity, 4);
    }
    int result = request(&m);
    if (result < 0) return result;
    if (!result || (unsigned)result > count) return broken(-EPROTO);
    unsigned offsets[PS_DGRAM_BATCH_MAX], used = 0;
    uint32_t lengths[PS_DGRAM_BATCH_MAX];
    struct ps_sockaddr sources[PS_DGRAM_BATCH_MAX];
    for (int i = 0; i < result; i++) {
        offsets[i] = used + IPC_DGRAM_HEADER;
        if (ipc_datagram_decode(m.data + used, m.length - used, &sources[i], &lengths[i]) ||
            lengths[i] > messages[i].len) return broken(-EPROTO);
        used += IPC_DGRAM_HEADER + lengths[i];
    }
    if (used != m.length) return broken(-EPROTO);
    for (int i = 0; i < result; i++) {
        if (lengths[i]) memcpy(messages[i].data, m.data + offsets[i], lengths[i]);
        messages[i].len = lengths[i];
        messages[i].addr = sources[i];
    }
    return result;
}
