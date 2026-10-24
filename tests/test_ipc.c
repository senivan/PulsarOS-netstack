#define _POSIX_C_SOURCE 200809L
#include <arpa/inet.h>
#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <unistd.h>
#include "ipc.h"

static void framing(void)
{
    struct ipc_message original = { .op = IPC_SEND, .id = 123, .fd = 7, .length = 3,
        .a = -1, .b = 17, .c = 99, .result = -EAGAIN,
        .addr = { .ip_be = inet_addr("192.0.2.1"), .port = 65535 } }, decoded;
    uint8_t wire[IPC_HEADER_SIZE];
    ipc_encode(wire, &original);
    assert(wire[0] == 0x50 && wire[1] == 0x53 && wire[2] == 0x4e && wire[3] == 0x53);
    assert(wire[36] == 192 && wire[37] == 0 && wire[38] == 2 && wire[39] == 1);
    assert(ipc_decode(wire, &decoded) == 0 && decoded.id == 123 && decoded.result == -EAGAIN);
    assert(decoded.fd == 7 && decoded.length == 3 && decoded.a == -1 && decoded.b == 17 && decoded.c == 99);
    assert(decoded.addr.ip_be == original.addr.ip_be && decoded.addr.port == 65535);
    const unsigned offsets[] = {0, 7, 16, 40, 48};
    for (unsigned i = 0; i < sizeof(offsets) / sizeof(offsets[0]); i++) {
        ipc_encode(wire, &original);
        wire[offsets[i]] ^= 0xff;
        assert(ipc_decode(wire, &decoded) == -EPROTO);
    }
    original.id = 0;
    ipc_encode(wire, &original);
    assert(ipc_decode(wire, &decoded) == -EPROTO);
    original.result = 0;
    assert(ipc_request_valid(&original));
    original.op = IPC_BIND;
    assert(!ipc_request_valid(&original));
    original.length = 0;
    assert(ipc_request_valid(&original));
    original.op = IPC_RECV;
    assert(!ipc_request_valid(&original));
    original.a = IPC_PAYLOAD_MAX + 1;
    assert(!ipc_request_valid(&original));
    original.a = 0;
    assert(ipc_request_valid(&original));
    original.op = IPC_CLEANUP;
    assert(!ipc_request_valid(&original));
}

static void read_all(int fd, void *data, size_t length)
{
    uint8_t *p = data;
    while (length) {
        ssize_t n = recv(fd, p, length, 0);
        assert(n > 0);
        p += n; length -= (size_t)n;
    }
}

static struct ipc_message read_request(int fd, uint32_t op)
{
    uint8_t header[IPC_HEADER_SIZE];
    read_all(fd, header, sizeof(header));
    struct ipc_message m;
    assert(ipc_decode(header, &m) == 0 && ipc_request_valid(&m) && m.op == op);
    if (m.length) read_all(fd, m.data, m.length);
    return m;
}

static void fragmented_response(int fd, struct ipc_message *m)
{
    uint8_t wire[IPC_FRAME_MAX];
    ipc_encode(wire, m);
    memcpy(wire + IPC_HEADER_SIZE, m->data, m->length);
    for (unsigned i = 0; i < IPC_HEADER_SIZE + m->length;) {
        unsigned n = IPC_HEADER_SIZE + m->length - i;
        if (n > 7) n = 7;
        ssize_t sent = send(fd, wire + i, n, MSG_NOSIGNAL);
        assert(sent > 0);
        i += (unsigned)sent;
    }
}

static void client_test(const char *path)
{
    assert(ps_socket(PS_AF_INET, PS_SOCK_STREAM, 0) == -ENOTCONN);
    assert(ps_init(path) == 0 && ps_init(path) == -EALREADY);
    ps_fd_t fd = ps_socket(PS_AF_INET, PS_SOCK_STREAM, 0);
    assert(fd == 7);
    assert(ps_bind(fd, &(struct ps_sockaddr){.port = 9000}) == 0);
    pid_t forked = fork();
    assert(forked >= 0);
    if (!forked) {
        assert(ps_socket(PS_AF_INET, PS_SOCK_STREAM, 0) == -ENOTCONN);
        ps_fini();
        exit(0);
    }
    int child_status;
    assert(waitpid(forked, &child_status, 0) == forked && WIFEXITED(child_status) && !WEXITSTATUS(child_status));
    uint8_t data[IPC_PAYLOAD_MAX];
    for (unsigned i = 0; i < sizeof(data); i++) data[i] = (uint8_t)i;
    assert(ps_send(fd, data, sizeof(data)) == (ssize_t)sizeof(data));
    memset(data, 0, sizeof(data));
    assert(ps_recv(fd, data, sizeof(data)) == (ssize_t)sizeof(data));
    for (unsigned i = 0; i < sizeof(data); i++) assert(data[i] == (uint8_t)i);
    assert(ps_close(fd) == -EPROTO);
    assert(ps_socket(PS_AF_INET, PS_SOCK_STREAM, 0) == -ECONNRESET);
    ps_fini();
    assert(ps_close(fd) == -ENOTCONN);
    exit(0);
}

int main(void)
{
    framing();
    char directory[] = "/tmp/pulsaros-client-XXXXXX";
    assert(mkdtemp(directory));
    struct sockaddr_un address = { .sun_family = AF_UNIX };
    snprintf(address.sun_path, sizeof(address.sun_path), "%s/ipc", directory);
    int listener = socket(AF_UNIX, SOCK_STREAM, 0);
    assert(listener >= 0 && !bind(listener, (const struct sockaddr *)&address, sizeof(address)) && !listen(listener, 1));
    pid_t child = fork();
    assert(child >= 0);
    if (!child) { close(listener); client_test(address.sun_path); }
    int fd = accept(listener, NULL, NULL);
    assert(fd >= 0);
    struct timeval timeout = { .tv_sec = 10 };
    assert(!setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)));
    struct ipc_message m = read_request(fd, IPC_HELLO);
    fragmented_response(fd, &m);
    m = read_request(fd, IPC_SOCKET);
    assert(m.a == PS_AF_INET && m.b == PS_SOCK_STREAM && !m.c);
    m.result = 7;
    fragmented_response(fd, &m);
    m = read_request(fd, IPC_BIND);
    assert(m.fd == 7 && m.addr.port == 9000);
    fragmented_response(fd, &m);
    m = read_request(fd, IPC_SEND);
    assert(m.length == IPC_PAYLOAD_MAX);
    for (unsigned i = 0; i < m.length; i++) assert(m.data[i] == (uint8_t)i);
    m.result = (int32_t)m.length;
    m.length = 0;
    fragmented_response(fd, &m);
    m = read_request(fd, IPC_RECV);
    m.result = (int32_t)(m.length = IPC_PAYLOAD_MAX);
    for (unsigned i = 0; i < m.length; i++) m.data[i] = (uint8_t)i;
    fragmented_response(fd, &m);
    m = read_request(fd, IPC_CLOSE);
    m.id++;
    fragmented_response(fd, &m);
    close(fd);
    int status;
    assert(waitpid(child, &status, 0) == child && WIFEXITED(status) && !WEXITSTATUS(status));
    pid_t stalled = fork();
    assert(stalled >= 0);
    if (!stalled) {
        close(listener);
        assert(ps_init(address.sun_path) == -ETIMEDOUT);
        assert(ps_socket(PS_AF_INET, PS_SOCK_DGRAM, 0) == -ECONNRESET);
        ps_fini();
        exit(0);
    }
    fd = accept(listener, NULL, NULL);
    assert(fd >= 0);
    m = read_request(fd, IPC_HELLO);
    assert(waitpid(stalled, &status, 0) == stalled && WIFEXITED(status) && !WEXITSTATUS(status));
    close(fd);
    close(listener);
    assert(!unlink(address.sun_path) && !rmdir(directory));
    puts("IPC framing, limits, fragmented responses, payloads, correlation, fork isolation, timeout and disconnect passed");
    return 0;
}
