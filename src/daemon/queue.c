#include <string.h>
#include "daemon.h"

_Static_assert(ATOMIC_INT_LOCK_FREE == 2, "dataplane queues require lock-free unsigned atomics");

void daemon_queue_init(struct daemon_queue *q)
{
    atomic_init(&q->read, 0);
    atomic_init(&q->write, 0);
}

int daemon_queue_room(const struct daemon_queue *q)
{
    unsigned write = atomic_load_explicit(&q->write, memory_order_relaxed);
    unsigned read = atomic_load_explicit(&q->read, memory_order_acquire);
    return write - read < DAEMON_QUEUE_SIZE;
}

int daemon_queue_push(struct daemon_queue *q, const struct daemon_item *item)
{
    unsigned write = atomic_load_explicit(&q->write, memory_order_relaxed);
    unsigned read = atomic_load_explicit(&q->read, memory_order_acquire);
    if (write - read == DAEMON_QUEUE_SIZE) return -1;
    q->entries[write % DAEMON_QUEUE_SIZE] = *item;
    atomic_store_explicit(&q->write, write + 1, memory_order_release);
    return 0;
}

int daemon_queue_pop(struct daemon_queue *q, struct daemon_item *item)
{
    unsigned read = atomic_load_explicit(&q->read, memory_order_relaxed);
    unsigned write = atomic_load_explicit(&q->write, memory_order_acquire);
    if (read == write) return -1;
    *item = q->entries[read % DAEMON_QUEUE_SIZE];
    atomic_store_explicit(&q->read, read + 1, memory_order_release);
    return 0;
}
