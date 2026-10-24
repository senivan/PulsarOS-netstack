#pragma once

#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

#define PS_AF_INET 2
#define PS_SOCK_STREAM 1
#define PS_SOCK_DGRAM 2
#define PS_DGRAM_QUEUE_SIZE 16
#define PS_DGRAM_MAX_PAYLOAD 1472

typedef int ps_fd_t;

/* IPv4 is in network byte order; ports are in host byte order. IP zero binds
 * all local addresses; port zero selects an ephemeral port. */
struct ps_sockaddr { uint32_t ip_be; uint16_t port; };

/* One IPC connection per process; serialize calls. NULL selects the default
 * path. ps_fini() disconnects and schedules cleanup of all owned sockets.
 * Handles belong to this connection and become invalid after disconnect/fini.
 * Children after fork must ps_init() their own connection before using the API. */
#define PS_DEFAULT_SOCKET "/tmp/pulsaros.sock"
int ps_init(const char *path);
void ps_fini(void);

/* Network operations are nonblocking (-EAGAIN when no data/space). IPC uses
 * synchronous round trips bounded to five seconds; timeout breaks the session.
 * Errors are negative errno. Buffers remain caller-owned; sends copy data.
 * Datagram success means TX/ARP-queue acceptance; streams report bytes buffered.
 * The daemon owns all network progress; no application progress call is needed. */
ps_fd_t ps_socket(int domain, int type, int protocol);
int ps_bind(ps_fd_t fd, const struct ps_sockaddr *addr);
ssize_t ps_sendto(ps_fd_t fd, const void *buf, size_t len, const struct ps_sockaddr *dst);
/* -EAGAIN when empty; -EMSGSIZE leaves a datagram queued. */
ssize_t ps_recvfrom(ps_fd_t fd, void *buf, size_t len, struct ps_sockaddr *src);
/* Stream connect returns -EINPROGRESS; repeat returns -EALREADY while pending
 * or -EISCONN when established. Datagram connect sets a peer/filter. */
int ps_connect(ps_fd_t fd, const struct ps_sockaddr *addr);
int ps_listen(ps_fd_t fd, int backlog);
ps_fd_t ps_accept(ps_fd_t fd, struct ps_sockaddr *peer);
ssize_t ps_send(ps_fd_t fd, const void *buf, size_t len);
/* Stream receive returns zero at EOF after draining buffered data. */
ssize_t ps_recv(ps_fd_t fd, void *buf, size_t len);
/* Invalidates fd immediately. TCP retains its private slot until queued data,
 * FIN/retries and TIME_WAIT finish. Closing a listener cancels its children. */
int ps_close(ps_fd_t fd);
