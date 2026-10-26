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
    return 0;
}
_Static_assert(sizeof(struct net_acl) == 52, "ACL wire fields must be explicit 32-bit values");
