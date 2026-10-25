#include <arpa/inet.h>
#include <assert.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include "runtime.h"

static struct net_config c;
static uint32_t ip(const char *s) { struct in_addr a; assert(inet_pton(AF_INET, s, &a) == 1); return a.s_addr; }
int main(void)
{
    assert(net_prefix_valid(ip("10.0.0.0"), 8));
    assert(!net_prefix_valid(ip("10.0.0.1"), 8));
    assert(!net_prefix_valid(0, 33));
    c.addresses[c.address_count++] = (struct net_address){ip("10.0.0.1"), 24, 0};
    c.addresses[c.address_count++] = (struct net_address){ip("10.0.0.2"), 24, 0};
    assert(!net_connected_rebuild(&c) && c.route_count == 1);
    assert(!net_config_validate(&c, 1));
    c.routes[c.route_count++] = (struct net_route){.gateway = ip("192.0.2.1"), .table = 100};
    assert(net_config_validate(&c, 1) == -ENETUNREACH);
    c.routes[1].gateway = ip("10.0.0.254");
    assert(!net_config_validate(&c, 1));
    c.acls[c.acl_count++] = (struct net_acl){ .pref = 10, .iif = NET_IIF_NONE, .proto = 17,
        .dport_min = 5000, .dport_max = 6000, .ports = 2, .drop = 1 };
    c.acls[c.acl_count++] = (struct net_acl){ .pref = 20, .iif = NET_IIF_NONE };
    assert(!net_config_validate(&c, 1));
    struct acl_key k = {.proto = 17, .dport = 5500, .ports_valid = 1};
    struct acl_counters counters = {0};
    assert(!net_acl_accept(&c, &counters, &k, 100));
    assert(counters.dropped == 1 && counters.rules[0].bytes == 100);
    k.proto = 1;
    assert(net_acl_accept(&c, &counters, &k, 20));
    k.proto = 17; k.dport = 6001;
    assert(net_acl_classify(&c, &k) == 1);
    k.dport = 5000; k.ports_valid = 0;
    assert(net_acl_classify(&c, &k) == 1);
    c.acls[0].proto = 0;
    assert(net_config_validate(&c, 1) == -EINVAL);
    c.acls[0].proto = 17;
    c.acls[1].pref = 10;
    assert(net_config_validate(&c, 1) == -EINVAL);
    c.acls[1].pref = 20;
    struct net_config next = c;
    next.acls[0].drop = 0;
    net_acl_counters_migrate(&c, &next, &counters);
    assert(!counters.rules[0].packets && counters.rules[1].packets == 1);
    c.acl_count = 0; c.default_drop = 1;
    assert(!net_acl_accept(&c, &counters, &k, 20) && counters.defaults == 1);
    return 0;
}
