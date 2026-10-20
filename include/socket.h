#pragma once

#include "ps_socket.h"
#include "udp.h"
#include "tcp.h"

struct app_runtime;

struct ps_socket_entry {
    ps_fd_t fd;
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
    unsigned next_fd;
    uint16_t next_port;
};

/* Startup/shutdown only; one attached runtime, matching the single-lcore model.
 * Entries own copied application data, never RX mbufs or application pointers. */
int socket_subsystem_init(struct app_runtime *);
void socket_subsystem_fini(struct app_runtime *);
struct ps_socket_entry *socket_allocate(struct app_runtime *, int type);
struct ps_socket_entry *socket_lookup(struct app_runtime *, ps_fd_t);
struct ps_socket_entry *socket_bound(struct app_runtime *, int type, uint32_t ip_be, uint16_t port);
int socket_bind(struct app_runtime *, struct ps_socket_entry *, const struct ps_sockaddr *);
