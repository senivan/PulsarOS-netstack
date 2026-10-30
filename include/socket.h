#pragma once

#include "ps_socket.h"
#include "udp.h"
#include "tcp.h"

#define PS_SOCKET_MAX 256

struct app_runtime;

struct ps_socket_entry {
    ps_fd_t fd;
    uint64_t owner;
    uint8_t allocated, open, type;
    int error;
    struct ps_sockaddr local, remote;
    union {
        struct udp_endpoint udp;
        struct tcp_connection tcp;
    } transport;
};

struct socket_subsystem {
    struct ps_socket_entry entries[PS_SOCKET_MAX];
    unsigned capacity;
    uint32_t generations[PS_SOCKET_MAX];
    uint16_t next_port;
};

/* Dataplane-owned, including all core_* calls. Entries contain copied data,
 * never application pointers. owner identifies an IPC session, zero in tests. */
int socket_subsystem_init(struct app_runtime *);
void socket_subsystem_fini(struct app_runtime *);
struct ps_socket_entry *socket_allocate(struct app_runtime *, int type);
struct ps_socket_entry *socket_lookup(struct app_runtime *, ps_fd_t);
struct ps_socket_entry *socket_bound(struct app_runtime *, int type, uint32_t ip_be, uint16_t port);
int socket_bind(struct app_runtime *, struct ps_socket_entry *, const struct ps_sockaddr *);

ps_fd_t core_socket(struct app_runtime *rt, int domain, int type, int protocol);
int core_bind(struct app_runtime *rt, ps_fd_t fd, const struct ps_sockaddr *addr);
ssize_t core_sendto(struct app_runtime *rt, ps_fd_t fd, const void *buf, size_t len, const struct ps_sockaddr *dst);
ssize_t core_recvfrom(struct app_runtime *rt, ps_fd_t fd, void *buf, size_t len, struct ps_sockaddr *src);
int core_connect(struct app_runtime *rt, ps_fd_t fd, const struct ps_sockaddr *addr);
int core_listen(struct app_runtime *rt, ps_fd_t fd, int backlog);
ps_fd_t core_accept(struct app_runtime *rt, ps_fd_t fd, struct ps_sockaddr *peer);
ssize_t core_send(struct app_runtime *rt, ps_fd_t fd, const void *buf, size_t len);
ssize_t core_recv(struct app_runtime *rt, ps_fd_t fd, void *buf, size_t len);
int core_close(struct app_runtime *rt, ps_fd_t fd);
