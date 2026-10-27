#pragma once
#include <stddef.h>
#include <stdint.h>
#include "net_config.h"

#define ADMIN_DEFAULT_SOCKET "/tmp/pulsaros-admin.sock"
#define ADMIN_MAGIC 0x50534d47u
#define ADMIN_VERSION 1
#define ADMIN_HEADER 32
#define ADMIN_REQUEST_BASE 144
#define ADMIN_ACL_RECORD 116
#define ADMIN_REQUEST_MAX (ADMIN_REQUEST_BASE + NET_ACL_MAX * ADMIN_ACL_RECORD)
#define ADMIN_RESPONSE_MAX 131072
#define ADMIN_JSON 1
#define ADMIN_BRIEF 2
#define ADMIN_STATS 4
#define ADMIN_NODES 8

enum admin_group { ADM_STATUS = 1, ADM_STATS, ADM_LINK, ADM_ADDR, ADM_ROUTE, ADM_RULE, ADM_NEIGH, ADM_ACL, ADM_APP, ADM_SOCKET, ADM_MONITOR };
enum admin_verb { ADM_SHOW = 1, ADM_ADD, ADM_REPLACE, ADM_DEL, ADM_FLUSH, ADM_GET, ADM_SET, ADM_APPLY, ADM_DEFAULT };
enum admin_field { F_PREF, F_SRC, F_SRC_PREFIX, F_DST, F_DST_PREFIX, F_PROTO,
    F_SPORT_MIN, F_SPORT_MAX, F_DPORT_MIN, F_DPORT_MAX, F_PORTS, F_ACTION, F_TABLE, F_GATEWAY, F_IP, F_PREFIX };
struct admin_acl { struct net_acl rule; char dev[64]; };
struct admin_request {
    uint32_t group, verb, flags, count;
    uint32_t v[16];
    char dev[64];
    struct admin_acl acls[NET_ACL_MAX];
};
struct admin_header { uint32_t id, length; int32_t result; uint64_t generation; };
void admin_header_encode(uint8_t *, const struct admin_header *);
int admin_header_decode(const uint8_t *, struct admin_header *);
size_t admin_request_encode(uint8_t *, const struct admin_request *);
int admin_request_decode(const uint8_t *, size_t, struct admin_request *);
int admin_parse(int argc, char **argv, struct admin_request *, char *error, size_t);
void admin_usage(void);
int admin_exchange(const char *path, const struct admin_request *, char *, size_t, uint64_t *);

int admin_open(const char *path);
int admin_receive(int fd, uint32_t id, char *, size_t, uint64_t *);
int admin_call(int fd, const struct admin_request *, char *, size_t, uint64_t *);
