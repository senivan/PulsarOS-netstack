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
    c.routes[1].gateway = ip("10.0.0.255");
    assert(net_config_validate(&c, 1) == -ENETUNREACH || net_config_validate(&c, 1) == -EINVAL);
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
    struct acl_key burst[3]={k,k,k}; int results[3];
    burst[0].ports_valid=1; burst[1].proto=1; burst[2].dport=65535;
    net_acl_classify_batch(&c,burst,3,results);
    assert(results[0]==0 && results[1]==1 && results[2]==1);
    c.acls[0].src=ip("10.0.0.0"); c.acls[0].src_prefix=8;
    c.acls[0].dst=ip("192.168.0.0"); c.acls[0].dst_prefix=16;
    k.ports_valid=1; k.src=ip("10.2.3.4"); k.dst=ip("192.168.2.3");
    assert(net_acl_classify(&c,&k)==0);
    k.src=ip("11.2.3.4"); assert(net_acl_classify(&c,&k)==1);
    c.acls[0].proto=6; k.src=ip("10.2.3.4"); k.proto=6;
    assert(net_acl_classify(&c,&k)==0);
    c.acls[0].src=c.acls[0].dst=c.acls[0].src_prefix=c.acls[0].dst_prefix=0;
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
    static struct app_runtime rt;
    rt.port_count = 1;
    rt.ports[0] = (struct port_state){.id = 0, .configured = 1, .started = 1, .mtu = 1500};
    c.default_drop = 0;
    c.rule_count = 2;
    c.rules[0] = (struct net_rule){.pref = 100, .iif = NET_IIF_NONE, .src = ip("10.0.0.0"), .src_prefix = 24, .table = 101};
    c.rules[1] = (struct net_rule){.pref = 200, .iif = NET_IIF_NONE, .table = 100};
    rt.network = &c;
    struct route_result result;
    assert(ipv4_route_query(&rt, ip("8.8.8.8"), ip("10.0.0.2"), NET_IIF_NONE, &result) == DROP_NONE);
    assert(result.table == 100 && result.rule_pref == 200 && result.source_ip_be == ip("10.0.0.2"));
    c.routes[c.route_count++] = (struct net_route){.ip = ip("8.8.8.0"), .prefix = 24, .table = 100, .type = NET_PROHIBIT};
    assert(ipv4_route_query(&rt, ip("8.8.8.8"), 0, NET_IIF_NONE, &result) == DROP_ROUTE_PROHIBIT);
    assert(result.type == NET_PROHIBIT);
    assert(ipv4_route_errno(DROP_ROUTE_PROHIBIT)==EACCES && ipv4_route_errno(DROP_ROUTE_BLACKHOLE)==EINVAL);
    c.rules[1].iif = 0;
    assert(ipv4_route_query(&rt, ip("8.8.8.8"), 0, NET_IIF_NONE, &result) == DROP_NO_ROUTE);
    assert(ipv4_route_query(&rt, ip("8.8.8.8"), 0, 0, &result) == DROP_ROUTE_PROHIBIT);
    c.rule_count = 0;
    c.routes[c.route_count++] = (struct net_route){.ip = ip("172.16.0.0"), .prefix = 16, .table = NET_TABLE_MAIN};
    assert(ipv4_route_query(&rt, ip("172.16.0.0"), 0, NET_IIF_NONE, &result) == DROP_INVALID_DESTINATION);
    assert(ipv4_route_query(&rt, ip("10.0.0.2"), 0, NET_IIF_NONE, &result) == DROP_NONE && result.local);
    assert(net_source(&rt, 0, ip("10.0.0.3")) == ip("10.0.0.1"));
    rt.ports[0].admin_down = 1;
    assert(ipv4_route_query(&rt, ip("10.0.0.3"), 0, NET_IIF_NONE, &result) == DROP_NO_ROUTE);
    return 0;
}
