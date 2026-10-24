#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <poll.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <sys/file.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/un.h>
#include <unistd.h>
#include "daemon.h"

static void disconnect_client(struct daemon_client *c)
{
    if (c->fd >= 0) close(c->fd);
    c->fd = -1;
    if (c->pidfd >= 0) close(c->pidfd);
    c->pidfd = -1;
    c->dead = 1;
    c->output_length = 0;
}

static struct daemon_handle *handle(struct daemon_client *c, int fd)
{
    for (unsigned i = 0; i < DAEMON_SOCKET_MAX; i++)
        if (c->handles[i].local == fd && fd > 0) return &c->handles[i];
    return NULL;
}

static int add_handle(struct daemon_client *c, int core)
{
    for (unsigned i = 0; i < DAEMON_SOCKET_MAX; i++) {
        if (c->handles[i].local) continue;
        int fd;
        do {
            fd = c->next_handle;
            c->next_handle = fd == INT_MAX ? 1 : fd + 1;
        } while (handle(c, fd));
        c->handles[i] = (struct daemon_handle){ .local = fd, .core = core };
        return fd;
    }
    return -EMFILE;
}

static void reply(struct daemon_client *c, const struct ipc_message *message)
{
    ipc_encode(c->output, message);
    if (message->length) memcpy(c->output + IPC_HEADER_SIZE, message->data, message->length);
    c->output_length = IPC_HEADER_SIZE + message->length;
    c->sent = c->have = 0;
    c->target = IPC_HEADER_SIZE;
}

static void collect_responses(struct daemon_service *service)
{
    struct daemon_item item;
    while (!daemon_queue_pop(&service->responses, &item)) {
        struct daemon_client *c = NULL;
        for (unsigned i = 0; i < service->max_clients; i++)
            if (service->clients[i].owner == item.owner) { c = &service->clients[i]; break; }
        if (!c) continue;
        c->pending = 0;
        if (item.message.op == IPC_CLEANUP && c->cleanup) {
            memset(c, 0, sizeof(*c));
            c->fd = c->pidfd = -1;
            continue;
        }
        if (c->dead) continue;
        struct ipc_message *m = &item.message;
        if (m->id != c->input.id || m->op != c->input.op) { disconnect_client(c); continue; }
        if (m->result >= 0 && (m->op == IPC_SOCKET || m->op == IPC_ACCEPT)) {
            m->result = add_handle(c, m->result);
            if (m->result < 0) { disconnect_client(c); continue; }
        }
        if (!m->result && m->op == IPC_CLOSE) {
            struct daemon_handle *entry = handle(c, c->input.fd);
            if (entry) memset(entry, 0, sizeof(*entry));
        }
        m->fd = c->input.fd;
        reply(c, m);
    }
}

static void submit_client(struct daemon_service *service, struct daemon_client *c)
{
    if (!c->owner || c->pending) return;
    if (c->dead) {
        struct daemon_item item = { .owner = c->owner, .message = { .op = IPC_CLEANUP } };
        if (!daemon_queue_push(&service->requests, &item)) c->pending = c->cleanup = 1;
        return;
    }
    if (c->output_length || c->have != c->target) return;
    struct ipc_message *m = &c->input;
    if (!c->hello) {
        if (m->op != IPC_HELLO) { disconnect_client(c); return; }
        struct ipc_message response = { .op = m->op, .id = m->id, .a = (int32_t)service->max_sockets };
        c->hello = 1;
        reply(c, &response);
        return;
    }
    if (m->op == IPC_HELLO) {
        struct ipc_message response = { .op = m->op, .id = m->id, .result = -EALREADY };
        reply(c, &response);
        return;
    }
    struct daemon_item item = { .owner = c->owner, .message = *m };
    if (m->op != IPC_SOCKET) {
        struct daemon_handle *entry = handle(c, m->fd);
        if (!entry) {
            struct ipc_message response = { .op = m->op, .id = m->id, .fd = m->fd, .result = -EBADF };
            reply(c, &response);
            return;
        }
        item.message.fd = entry->core;
    }
    if (!daemon_queue_push(&service->requests, &item)) c->pending = 1;
}

static void read_client(struct daemon_client *c)
{
    void *destination = c->have < IPC_HEADER_SIZE ?
        (void *)(c->header + c->have) : (void *)(c->input.data + c->have - IPC_HEADER_SIZE);
    ssize_t n = recv(c->fd, destination, c->target - c->have, 0);
    if (n <= 0) {
        if (!n || (errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR)) disconnect_client(c);
        return;
    }
    c->have += (size_t)n;
    if (c->have == IPC_HEADER_SIZE && c->target == IPC_HEADER_SIZE) {
        if (ipc_decode(c->header, &c->input) || !ipc_request_valid(&c->input) || c->input.id == c->last_id) {
            disconnect_client(c);
            return;
        }
        c->last_id = c->input.id;
        c->target += c->input.length;
    }
}

static void write_client(struct daemon_client *c)
{
    ssize_t n = send(c->fd, c->output + c->sent, c->output_length - c->sent, MSG_NOSIGNAL);
    if (n <= 0) {
        if (!n || (errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR)) disconnect_client(c);
        return;
    }
    c->sent += (size_t)n;
    if (c->sent == c->output_length) c->output_length = c->sent = 0;
}

static void accept_clients(struct daemon_service *service)
{
    for (unsigned n = 0; n < DAEMON_CLIENT_MAX; n++) {
        int fd = accept4(service->listener, NULL, NULL, SOCK_NONBLOCK | SOCK_CLOEXEC);
        if (fd < 0) return;
        struct daemon_client *c = NULL;
        for (unsigned i = 0; i < service->max_clients; i++)
            if (!service->clients[i].owner) { c = &service->clients[i]; break; }
        if (!c || service->next_owner == UINT64_MAX) { close(fd); continue; }
        memset(c, 0, sizeof(*c));
        c->fd = fd;
        c->pidfd = -1;
        int buffer = 4096;
        setsockopt(fd, SOL_SOCKET, SO_SNDBUF, &buffer, sizeof(buffer));
#ifdef SYS_pidfd_open
        struct ucred credentials;
        socklen_t size = sizeof(credentials);
        if (!getsockopt(fd, SOL_SOCKET, SO_PEERCRED, &credentials, &size))
            c->pidfd = (int)syscall(SYS_pidfd_open, credentials.pid, 0);
#endif
        c->owner = ++service->next_owner;
        c->next_handle = 1;
        c->target = IPC_HEADER_SIZE;
    }
}

static void *control_run(void *arg)
{
    struct daemon_service *service = arg;
    pthread_setaffinity_np(pthread_self(), sizeof(service->control_cpus), &service->control_cpus);
    for (;;) {
        collect_responses(service);
        int stopping = atomic_load_explicit(&service->stopping, memory_order_acquire);
        if (stopping && service->listener >= 0) {
            close(service->listener);
            service->listener = -1;
        }
        unsigned live = 0;
        for (unsigned i = 0; i < service->max_clients; i++) {
            struct daemon_client *c = &service->clients[i];
            if (!c->owner) continue;
            live++;
            if (stopping && !c->dead) disconnect_client(c);
            submit_client(service, c);
        }
        if (stopping && !live) break;
        struct pollfd fds[2 * DAEMON_CLIENT_MAX + 1];
        unsigned indices[2 * DAEMON_CLIENT_MAX + 1], count = 1;
        fds[0] = (struct pollfd){ .fd = stopping ? -1 : service->listener, .events = POLLIN };
        for (unsigned i = 0; i < service->max_clients; i++) {
            struct daemon_client *c = &service->clients[i];
            if (c->fd < 0) continue;
            short events = c->output_length ? POLLOUT :
                (!c->pending && c->have < c->target ? POLLIN : 0);
            indices[count] = i;
            fds[count++] = (struct pollfd){ .fd = c->fd, .events = events };
            if (c->pidfd >= 0) {
                indices[count] = i + DAEMON_CLIENT_MAX;
                fds[count++] = (struct pollfd){ .fd = c->pidfd, .events = POLLIN };
            }
        }
        int rc = poll(fds, count, 10);
        if (rc < 0) {
            if (errno == EINTR) continue;
            atomic_store(&service->failed, 1);
            atomic_store(&service->stopping, 1);
            continue;
        }
        if (fds[0].revents & POLLIN) accept_clients(service);
        if (fds[0].revents & (POLLERR | POLLHUP | POLLNVAL)) {
            atomic_store(&service->failed, 1);
            atomic_store(&service->stopping, 1);
        }
        for (unsigned n = 1; n < count; n++) {
            struct daemon_client *c = &service->clients[indices[n] % DAEMON_CLIENT_MAX];
            if (indices[n] >= DAEMON_CLIENT_MAX) {
                if (fds[n].revents) disconnect_client(c);
                continue;
            }
            if (c->fd < 0) continue;
            if (fds[n].revents & (POLLERR | POLLHUP | POLLNVAL)) { disconnect_client(c); continue; }
            if (fds[n].revents & POLLOUT) write_client(c);
            if (c->fd >= 0 && (fds[n].revents & POLLIN)) read_client(c);
        }
    }
    atomic_store_explicit(&service->done, 1, memory_order_release);
    return NULL;
}

int daemon_prepare(struct daemon_service *service, const char *path, unsigned max_clients, unsigned max_sockets)
{
    memset(service, 0, sizeof(*service));
    service->listener = service->lock_fd = -1;
    atomic_init(&service->stopping, 0);
    atomic_init(&service->done, 0);
    atomic_init(&service->failed, 0);
    daemon_queue_init(&service->requests);
    daemon_queue_init(&service->responses);
    for (unsigned i = 0; i < DAEMON_CLIENT_MAX; i++) service->clients[i].fd = service->clients[i].pidfd = -1;
    if (!max_clients || max_clients > DAEMON_CLIENT_MAX || !max_sockets || max_sockets > DAEMON_SOCKET_MAX ||
        !*path || strlen(path) >= sizeof(service->path)) return -EINVAL;
    service->max_clients = max_clients;
    service->max_sockets = max_sockets;
    memcpy(service->path, path, strlen(path) + 1);
    char lock_path[sizeof(service->path) + 6];
    snprintf(lock_path, sizeof(lock_path), "%s.lock", path);
    service->lock_fd = open(lock_path, O_CREAT | O_RDWR | O_CLOEXEC | O_NOFOLLOW, 0600);
    if (service->lock_fd < 0) return -errno;
    struct stat info;
    if (fstat(service->lock_fd, &info)) return -errno;
    if (!S_ISREG(info.st_mode) || info.st_uid != geteuid() || info.st_nlink != 1) return -EACCES;
    if (flock(service->lock_fd, LOCK_EX | LOCK_NB)) return -errno;
    struct sockaddr_un address = { .sun_family = AF_UNIX };
    memcpy(address.sun_path, path, strlen(path) + 1);
    if (!lstat(path, &info)) {
        if (!S_ISSOCK(info.st_mode) || info.st_uid != geteuid()) return -EEXIST;
        int probe = socket(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
        if (probe < 0) return -errno;
        int connected = connect(probe, (const struct sockaddr *)&address, sizeof(address));
        int error = errno;
        close(probe);
        if (!connected || (error != ECONNREFUSED && error != ENOENT)) return -EADDRINUSE;
        if (unlink(path) && errno != ENOENT) return -errno;
    } else if (errno != ENOENT) return -errno;
    service->listener = socket(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
    if (service->listener < 0) return -errno;
    mode_t mask = umask(0077);
    int rc = bind(service->listener, (const struct sockaddr *)&address, sizeof(address));
    int error = errno;
    umask(mask);
    if (rc) return -error;
    if (lstat(path, &info)) return -errno;
    service->socket_device = info.st_dev;
    service->socket_inode = info.st_ino;
    if (listen(service->listener, (int)max_clients)) return -errno;
    return 0;
}

int daemon_start(struct daemon_service *service)
{
    int rc = pthread_create(&service->thread, NULL, control_run, service);
    return rc ? -rc : 0;
}

void daemon_release(struct daemon_service *service)
{
    if (service->listener >= 0) close(service->listener);
    struct stat info;
    if (service->socket_inode && !lstat(service->path, &info) &&
        info.st_dev == service->socket_device && info.st_ino == service->socket_inode) unlink(service->path);
    if (service->lock_fd >= 0) close(service->lock_fd);
}
