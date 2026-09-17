#pragma once

#include <stdint.h>
#include <rte_ether.h>
#include "packet.h"

#define NEIGHBOUR_CAPACITY 64
#define NEIGHBOUR_PENDING_MAX 16
#define NEIGHBOUR_PENDING_QUEUE_MAX 8
#define ARP_MAX_REQUESTS 3
#define ARP_RETRY_SECONDS 1

struct app_runtime;
struct rte_mbuf;
struct pending_neighbour {
    uint32_t ip_be;
    uint16_t netif_id, count;
    unsigned requests;
    uint64_t last_request;
    struct rte_mbuf *packets[NEIGHBOUR_PENDING_QUEUE_MAX];
    struct packet_ctx contexts[NEIGHBOUR_PENDING_QUEUE_MAX];
};
struct neighbour_pending { struct pending_neighbour entries[NEIGHBOUR_PENDING_MAX]; };

struct neighbour_entry {
    uint32_t ip_be;
    uint16_t netif_id;
    struct rte_ether_addr mac;
    uint8_t in_use;
};

struct neighbour_table { struct neighbour_entry entries[NEIGHBOUR_CAPACITY]; };

/* Zero-initialize the table. Full tables reject new keys but permit updates. */
int neighbour_learn(struct neighbour_table *, uint16_t netif_id, uint32_t ip_be, const struct rte_ether_addr *);
int neighbour_lookup(const struct neighbour_table *, uint16_t netif_id, uint32_t ip_be, struct rte_ether_addr *);

/* Success transfers ownership to the pending queue; failure retains caller ownership. */
enum drop_reason neighbour_queue(struct app_runtime *, uint16_t netif_id,
                                  struct rte_mbuf *, const struct packet_ctx *, uint64_t now);
int neighbour_update(struct app_runtime *, uint16_t netif_id, uint32_t ip_be, const struct rte_ether_addr *);
void neighbour_tick(struct app_runtime *, uint64_t now);
void neighbour_fini(struct app_runtime *);
