#pragma once

#include <pthread.h>
#include <sched.h>
#include <stdatomic.h>
#include <stdint.h>
#include <sys/types.h>
#include "ipc.h"

#define DAEMON_CLIENT_MAX 64
#define DAEMON_QUEUE_SIZE 64
#define DAEMON_SOCKET_MAX 256

struct app_runtime;
struct daemon_item { uint64_t owner; struct ipc_message message; };

/* SPSC: control produces requests, worker consumes. Responses reverse roles.
 * Release publishes a full copy; acquire precedes reading/reusing each slot.
 * A full response ring prevents command consumption, never packet progress. */
struct daemon_queue {
    atomic_uint read, write;
    struct daemon_item entries[DAEMON_QUEUE_SIZE];
};
void daemon_queue_init(struct daemon_queue *);
int daemon_queue_push(struct daemon_queue *, const struct daemon_item *);
int daemon_queue_pop(struct daemon_queue *, struct daemon_item *);
int daemon_queue_room(const struct daemon_queue *);
void daemon_dispatch(struct app_runtime *, const struct daemon_item *, struct daemon_item *);

struct daemon_handle { int local, core; };
struct daemon_client {
    int fd, pidfd, dead, pending, cleanup, hello, next_handle;
    uint64_t owner;
    uint32_t last_id;
    size_t have, target, sent, output_length;
    struct ipc_message input;
    uint8_t header[IPC_HEADER_SIZE], output[IPC_FRAME_MAX];
    struct daemon_handle handles[DAEMON_SOCKET_MAX];
};

/* The control thread exclusively owns listener, clients, maps and IPC buffers.
 * The worker exclusively owns app_runtime. Only queues and atomic flags cross
 * threads; startup/join bracket access to the remaining service metadata. */
struct daemon_service {
    struct daemon_queue requests, responses;
    atomic_int stopping, done, failed;
    pthread_t thread;
    int listener, lock_fd;
    unsigned max_clients, max_sockets;
    uint64_t next_owner;
    dev_t socket_device;
    ino_t socket_inode;
    cpu_set_t control_cpus;
    char path[108];
    struct daemon_client clients[DAEMON_CLIENT_MAX];
};
int daemon_prepare(struct daemon_service *, const char *path, unsigned max_clients, unsigned max_sockets);
int daemon_start(struct daemon_service *);
unsigned daemon_progress(struct daemon_service *, struct app_runtime *);
void daemon_release(struct daemon_service *);
