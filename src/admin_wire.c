#include <arpa/inet.h>
#include <errno.h>
#include <string.h>
#include "admin.h"

static void put(uint8_t *p, uint32_t n) { n = htonl(n); memcpy(p, &n, 4); }
static uint32_t get(const uint8_t *p) { uint32_t n; memcpy(&n, p, 4); return ntohl(n); }
void admin_header_encode(uint8_t *b, const struct admin_header *h)
{
    put(b, ADMIN_MAGIC); put(b+4, ADMIN_VERSION); put(b+8, h->id); put(b+12, h->length);
    put(b+16, (uint32_t)h->result); put(b+20, h->generation >> 32); put(b+24, h->generation); put(b+28, 0);
}
int admin_header_decode(const uint8_t *b, struct admin_header *h)
{
    if (get(b) != ADMIN_MAGIC || get(b+4) != ADMIN_VERSION || get(b+28)) return -EPROTO;
    *h = (struct admin_header){ .id = get(b+8), .length = get(b+12), .result = (int32_t)get(b+16),
        .generation = (uint64_t)get(b+20) << 32 | get(b+24) };
    return !h->id || h->length > ADMIN_RESPONSE_MAX ? -EPROTO : 0;
}
static int address_field(unsigned i) { return i == F_SRC || i == F_DST || i == F_GATEWAY || i == F_IP; }
size_t admin_request_encode(uint8_t *b, const struct admin_request *r)
{
    if (r->count > NET_ACL_MAX) return 0;
    put(b, r->group); put(b+4, r->verb); put(b+8, r->flags); put(b+12, r->count);
    for (unsigned i = 0; i < 16; i++) {
        if (address_field(i)) memcpy(b+16+i*4, &r->v[i], 4); else put(b+16+i*4, r->v[i]);
    }
    memcpy(b+80, r->dev, 64);
    for (unsigned i = 0; i < r->count; i++) {
        uint8_t *p = b+ADMIN_REQUEST_BASE+i*ADMIN_ACL_RECORD;
        uint32_t words[13];
        memcpy(words, &r->acls[i].rule, sizeof(words));
        for (unsigned j = 0; j < 13; j++) {
            if (j == 1 || j == 3) memcpy(p+j*4, &words[j], 4); else put(p+j*4, words[j]);
        }
        memcpy(p+52, r->acls[i].dev, 64);
    }
    return ADMIN_REQUEST_BASE + r->count*ADMIN_ACL_RECORD;
}
int admin_request_decode(const uint8_t *b, size_t n, struct admin_request *r)
{
    if (n < ADMIN_REQUEST_BASE) return -EPROTO;
    memset(r, 0, sizeof(*r));
    r->group = get(b); r->verb = get(b+4); r->flags = get(b+8); r->count = get(b+12);
    if (r->group < ADM_STATUS || r->group > ADM_MONITOR || r->verb < ADM_SHOW || r->verb > ADM_DEFAULT ||
        r->flags > 15 || r->count > NET_ACL_MAX || n != ADMIN_REQUEST_BASE+r->count*ADMIN_ACL_RECORD ||
        (r->count && (r->group != ADM_ACL || r->verb != ADM_APPLY))) return -EINVAL;
    for (unsigned i = 0; i < 16; i++) {
        if (address_field(i)) memcpy(&r->v[i], b+16+i*4, 4); else r->v[i] = get(b+16+i*4);
    }
    memcpy(r->dev, b+80, 64);
    if (!memchr(r->dev, 0, 64)) return -EINVAL;
    for (unsigned i = 0; i < r->count; i++) {
        const uint8_t *p = b+ADMIN_REQUEST_BASE+i*ADMIN_ACL_RECORD;
        uint32_t words[13];
        for (unsigned j = 0; j < 13; j++) {
            if (j == 1 || j == 3) memcpy(&words[j], p+j*4, 4); else words[j] = get(p+j*4);
        }
        memcpy(&r->acls[i].rule, words, sizeof(words));
        memcpy(r->acls[i].dev, p+52, 64);
        if (!memchr(r->acls[i].dev, 0, 64)) return -EINVAL;
    }
    int valid = 0;
    switch (r->group) {
    case ADM_STATUS: case ADM_STATS: case ADM_APP: case ADM_SOCKET: case ADM_MONITOR: valid = r->verb == ADM_SHOW; break;
    case ADM_LINK: valid = r->verb == ADM_SHOW || r->verb == ADM_SET; break;
    case ADM_ADDR: case ADM_NEIGH: valid = r->verb == ADM_SHOW || r->verb == ADM_ADD || r->verb == ADM_REPLACE || r->verb == ADM_DEL || r->verb == ADM_FLUSH; break;
    case ADM_ROUTE: valid = r->verb <= ADM_GET; break;
    case ADM_RULE: valid = r->verb == ADM_SHOW || r->verb == ADM_ADD || r->verb == ADM_DEL || r->verb == ADM_FLUSH; break;
    case ADM_ACL: valid = r->verb == ADM_SHOW || r->verb == ADM_ADD || r->verb == ADM_DEL || r->verb == ADM_FLUSH || r->verb == ADM_APPLY || r->verb == ADM_DEFAULT; break;
    }
    if (!valid) return -EOPNOTSUPP;
    uint32_t mask=0;
    int device=0;
    switch (r->group) {
    case ADM_LINK:
        device=1;
        if (r->verb==ADM_SET) {
            if (r->v[F_PORTS]==1) mask=(1u<<F_PORTS)|(1u<<F_ACTION);
            else if (r->v[F_PORTS]==2) mask=(1u<<F_PORTS)|(1u<<F_IP);
            else return -EINVAL;
        }
        break;
    case ADM_ADDR:
        device=1;
        if (r->verb==ADM_ADD || r->verb==ADM_REPLACE || r->verb==ADM_DEL) mask=(1u<<F_IP)|(1u<<F_PREFIX);
        break;
    case ADM_ROUTE:
        if (r->verb==ADM_GET) mask=(1u<<F_IP)|(1u<<F_PREFIX)|(1u<<F_SRC)|(1u<<F_SRC_PREFIX);
        else {
            mask=1u<<F_TABLE;
            if (r->verb!=ADM_SHOW && r->verb!=ADM_FLUSH) mask|=(1u<<F_IP)|(1u<<F_PREFIX);
            if (r->verb==ADM_ADD || r->verb==ADM_REPLACE) {mask|=(1u<<F_GATEWAY)|(1u<<F_ACTION);device=1;}
        }
        break;
    case ADM_RULE:
        if (r->verb==ADM_ADD) {mask=(1u<<F_PREF)|(1u<<F_SRC)|(1u<<F_SRC_PREFIX)|(1u<<F_DST)|(1u<<F_DST_PREFIX)|(1u<<F_ACTION)|(1u<<F_TABLE);device=1;}
        else if (r->verb==ADM_DEL) mask=1u<<F_PREF;
        break;
    case ADM_ACL:
        if (r->verb==ADM_ADD) {mask=(1u<<(F_ACTION+1))-1;device=1;}
        else if (r->verb==ADM_DEL) mask=1u<<F_PREF;
        else if (r->verb==ADM_DEFAULT || r->verb==ADM_APPLY) mask=1u<<F_ACTION;
        break;
    case ADM_NEIGH:
        device=1;
        if (r->verb!=ADM_SHOW && r->verb!=ADM_FLUSH) mask=1u<<F_IP;
        if (r->verb==ADM_ADD || r->verb==ADM_REPLACE) mask|=(1u<<F_SPORT_MIN)|(1u<<F_SPORT_MAX);
        break;
    case ADM_MONITOR:
        mask=1u<<F_PROTO;
        if (r->v[F_PROTO] && (r->v[F_PROTO]<ADM_LINK || r->v[F_PROTO]>ADM_ACL)) return -EINVAL;
        break;
    default: break;
    }
    for (unsigned i=0;i<16;i++) if (!(mask&(1u<<i)) && r->v[i]) return -EINVAL;
    if (!device && *r->dev) return -EINVAL;
    for (unsigned i=0;i<r->count;i++) if (r->acls[i].rule.iif!=NET_IIF_NONE) return -EINVAL;
    return 0;
}
_Static_assert(sizeof(struct net_acl) == 52, "ACL wire fields must be explicit 32-bit values");
