#pragma once
#include <stddef.h>
#include <stdint.h>

#define NET_ADDR_MAX 64
#define NET_ROUTE_MAX 256
#define NET_RULE_MAX 64
#define NET_ACL_MAX 128
#define NET_TABLE_LOCAL 255
#define NET_TABLE_MAIN 254
#define NET_TABLE_DEFAULT 253
#define NET_IIF_NONE UINT32_MAX

enum net_action { NET_UNICAST, NET_BLACKHOLE, NET_UNREACHABLE, NET_PROHIBIT };
struct net_address { uint32_t ip, prefix, dev; };
struct net_route { uint32_t ip, prefix, gateway, dev, table, type, connected; };
struct net_rule { uint32_t pref, src, src_prefix, dst, dst_prefix, iif, table, type; };
struct net_route_index { uint32_t table; uint16_t route; uint8_t prefix; };
struct net_acl {
    uint32_t pref, src, src_prefix, dst, dst_prefix, iif, proto;
    uint32_t sport_min, sport_max, dport_min, dport_max, ports, drop;
};
/* Published snapshots are immutable. Counters belong exclusively to the worker. */
struct net_config {
    uint64_t generation;
    uint32_t address_count, route_count, rule_count, acl_count, default_drop;
    struct net_address addresses[NET_ADDR_MAX];
    struct net_route routes[NET_ROUTE_MAX];
    uint32_t routes_indexed;
    struct net_route_index route_index[NET_ROUTE_MAX];
    struct net_rule rules[NET_RULE_MAX];
    struct net_acl acls[NET_ACL_MAX];
};
struct acl_counter { uint64_t packets, bytes; };
struct acl_counters {
    struct acl_counter rules[NET_ACL_MAX];
    uint64_t accepted, dropped, defaults;
};
/* IPv4 fields are network order; ports and interface IDs are host order. */
struct acl_key { uint32_t src, dst, iif; uint16_t sport, dport; uint8_t proto, ports_valid; };
uint32_t net_mask(uint32_t prefix);
int net_match(uint32_t ip, uint32_t network, uint32_t prefix);
int net_prefix_valid(uint32_t ip, uint32_t prefix);
int net_unicast(uint32_t ip);
/* Build candidate lookup indexes before publishing an immutable snapshot. */
int net_config_prepare(struct net_config *, unsigned ports);
int net_config_validate(const struct net_config *, unsigned ports);
int net_connected_rebuild(struct net_config *);
int net_acl_classify(const struct net_config *, const struct acl_key *);
void net_acl_classify_batch(const struct net_config *, const struct acl_key *, size_t count, int *results);
int net_acl_account(const struct net_config *, struct acl_counters *, int result, size_t bytes);
int net_acl_accept(const struct net_config *, struct acl_counters *, const struct acl_key *, size_t bytes);
void net_acl_counters_migrate(const struct net_config *, const struct net_config *, struct acl_counters *);
struct app_runtime;
int net_config_init(struct app_runtime *);
int net_address_on(const struct app_runtime *, uint32_t dev, uint32_t ip);
uint32_t net_source(const struct app_runtime *, uint32_t dev, uint32_t dst);

#define ADMIN_EVENT_MAX 128
struct admin_event { uint64_t sequence, generation; uint32_t group, id, action, ip, prefix, dev, table; };
struct admin_events { uint64_t sequence; struct admin_event entries[ADMIN_EVENT_MAX]; };

int net_direct(const struct app_runtime *, uint32_t dev, uint32_t ip);

int net_host(uint32_t ip, uint32_t prefix);
