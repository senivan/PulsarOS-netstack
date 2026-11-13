#pragma once
#include <pthread.h>
#include <stdatomic.h>
#include <sys/types.h>
#include "admin.h"
#include "runtime.h"

#define ADMIN_CLIENT_MAX 16
struct admin_link {
    struct port_state port;
    uint32_t carrier, carrier_known;
    char driver[64];
    struct rte_eth_stats hardware;
};
struct admin_socket {
    uint64_t owner;
    uint32_t fd, open, type, state, rx, tx;
    struct ps_sockaddr local, remote;
};
struct admin_view {
    struct net_config config;
    struct acl_counters acl;
    struct admin_events events;
    struct admin_link links[NETIF_MAX];
    struct admin_socket sockets[PS_SOCKET_MAX];
    struct neighbour_table neighbours;
    struct node_stats nodes[NODE_MAX];
    char node_names[NODE_MAX][32];
    struct tcp_stats tcp;
    struct icmp_error_state icmp;
    uint64_t drops[DROP_REASON_MAX], uptime;
    uint32_t port_count, socket_count, forwarding;
    struct route_result route;
    enum drop_reason route_reason;
};
enum admin_job_type { ADMIN_READ, ADMIN_ACTIVATE, ADMIN_HARDWARE };
struct admin_job {
    enum admin_job_type type;
    struct admin_request request;
    struct net_config *next, *retired;
    struct admin_view view;
    int result;
};
struct admin_connection {
    int fd, pending, subscribed;
    uint32_t last_id;
    uint64_t sequence;
    size_t have, target, sent, length;
    struct admin_header header;
    uint8_t input[ADMIN_HEADER+ADMIN_REQUEST_MAX];
    uint8_t output[ADMIN_HEADER+ADMIN_RESPONSE_MAX];
    struct admin_request request;
};
struct daemon_service;
enum admin_mailbox_state {
    ADMIN_MAILBOX_CONTROL,
    ADMIN_MAILBOX_WORKER,
    ADMIN_MAILBOX_REPLY
};
/* CONTROL and REPLY belong to control; WORKER belongs to the worker.
 * Release/acquire transfers mailbox ownership. Activation returns the retired
 * snapshot for control-side reclamation after the graph has drained. */
struct admin_service {
    atomic_int state, stopping, done, failed;
    pthread_t thread;
    int listener, lock_fd, current, phase;
    unsigned cursor;
    uint64_t started, last_scan;
    dev_t device;
    ino_t inode;
    char path[108];
    struct daemon_service *applications;
    struct admin_job job;
    struct admin_connection clients[ADMIN_CLIENT_MAX];
};
int admin_prepare(struct admin_service *, const char *path, struct daemon_service *);
int admin_start(struct admin_service *);
void admin_release(struct admin_service *);
unsigned admin_progress(struct admin_service *, struct app_runtime *);
void admin_event_emit(struct app_runtime *, unsigned group, unsigned id, unsigned action);
int admin_mutate(const struct admin_view *, const struct admin_request *, struct net_config *);
int admin_device(const struct admin_view *, const char *);
int admin_worker_operation(struct app_runtime *, const struct admin_request *);
int admin_format(const struct admin_view *, const struct admin_request *, const struct daemon_service *, char *, size_t);
