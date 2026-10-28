#define _GNU_SOURCE
#include <arpa/inet.h>
#include <assert.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include "admin_service.h"

static struct admin_view view;
static struct net_config next;
static struct admin_request request;
static int parse(const char *text)
{
    char line[512], error[128]; assert(strlen(text)<sizeof(line)); strcpy(line,text);
    char *argv[64]; int argc=0;
    for(char *s=strtok(line," ");s;s=strtok(NULL," ")) {assert(argc<64);argv[argc++]=s;}
    return admin_parse(argc,argv,&request,error,sizeof(error));
}
static void apply(const char *text)
{
    assert(!parse(text));
    assert(!admin_mutate(&view,&request,&next));
    assert(next.generation==view.config.generation+1);
    view.config=next;
}
int main(void)
{
    view.port_count=2;
    view.links[0].port=(struct port_state){.id=0,.started=1,.configured=1,.mtu=1500};
    view.links[1].port=(struct port_state){.id=1,.started=1,.configured=1,.mtu=1500};
    strcpy(view.links[0].port.name,"eth0");strcpy(view.links[1].port.name,"eth1");
    view.config.generation=1;
    apply("addr add 10.0.0.1/24 dev eth0");
    apply("addr add 10.0.0.2/24 dev eth0");
    assert(view.config.address_count==2 && view.config.route_count==1);
    assert(!parse("addr add 10.0.0.1/24 dev eth0")); assert(admin_mutate(&view,&request,&next)==-EEXIST);
    assert(!parse("addr add 192.0.2.1/24 dev nonexistent")); assert(admin_mutate(&view,&request,&next)==-ENODEV);
    assert(parse("addr add 10.0.0.1/33 dev eth0"));
    assert(!parse("addr add 10.0.0.1/24 dev eth0"));request.v[F_IP]=inet_addr("192.0.2.1");request.v[F_PREFIX]=33;assert(admin_mutate(&view,&request,&next)==-EINVAL);
    assert(parse("route add 10.0.0.1/24 dev eth0"));
    apply("route add default via 10.0.0.254 dev eth0 table 100");
    assert(!parse("route add default via 192.0.2.1 dev eth0"));assert(admin_mutate(&view,&request,&next)==-ENETUNREACH);
    apply("rule add pref 200 lookup 200");
    apply("rule add pref 100 from 10.0.0.0/24 lookup 100");
    assert(view.config.rules[0].pref==100);
    assert(!parse("rule add pref 100 lookup 100"));assert(admin_mutate(&view,&request,&next)==-EEXIST);
    assert(!parse("rule del pref 0"));assert(admin_mutate(&view,&request,&next)==-ENOENT);
    apply("acl add pref 100 proto udp dport 5000-6000 action drop");
    apply("acl add pref 50 src 192.0.2.0/24 action accept");
    assert(view.config.acls[0].pref==50);
    assert(parse("acl add pref 1 proto icmp dport 22 action drop"));
    assert(parse("acl add pref 1 proto udp dport 6000-5000 action drop"));
    assert(parse("route show metric 2"));assert(parse("link show mtu 1400"));assert(parse("acl show proto udp"));
    assert(parse("route flush"));assert(parse("monitor add"));
    assert(parse("acl add pref 1 action drop action accept"));
    assert(!parse("acl add pref 1 proto tcp sport 10-20 dport 22 iif eth1 action drop"));
    uint8_t wire[ADMIN_REQUEST_MAX]; size_t length=admin_request_encode(wire,&request);
    struct admin_request decoded;
    assert(!admin_request_decode(wire,length,&decoded));assert(!memcmp(&request,&decoded,sizeof(request)));
    assert(admin_request_decode(wire,length-1,&decoded));
    request.count=NET_ACL_MAX+1;assert(!admin_request_encode(wire,&request));
    struct admin_header h={.id=5,.length=7,.result=-EINVAL,.generation=UINT64_C(0x123456789abcdef0)}, d;
    admin_header_encode(wire,&h); assert(!admin_header_decode(wire,&d));
    assert(h.id==d.id&&h.length==d.length&&h.result==d.result&&h.generation==d.generation);
    wire[0]=0;assert(admin_header_decode(wire,&d)==-EPROTO);
    apply("acl del pref 50"); apply("acl default drop"); assert(view.config.default_drop==1);
    apply("rule flush"); assert(!view.config.rule_count);
    apply("route flush table 100"); assert(view.config.route_count==1);
    apply("addr del 10.0.0.2/24 dev eth0"); assert(view.config.route_count==1);
    apply("addr flush dev eth0"); assert(!view.config.route_count);
    static struct app_runtime rt;
    rt.port_count=1;rt.ports[0]=view.links[0].port;
    rt.network=&view.config;
    struct rte_ether_addr mac={{2,0,0,0,0,1}}, other={{2,0,0,0,0,2}}, found;
    uint32_t ip=inet_addr("192.0.2.1");
    assert(!neighbour_set(&rt,0,ip,&mac,0));assert(neighbour_set(&rt,0,ip,&mac,0)==-EEXIST);
    assert(!neighbour_update(&rt,0,ip,&other));assert(!neighbour_lookup(&rt.neighbours,0,ip,&found));assert(!memcmp(&found,&mac,sizeof(mac)));
    assert(!neighbour_set(&rt,0,ip,&other,1));assert(!neighbour_delete(&rt,0,ip));assert(neighbour_lookup(&rt.neighbours,0,ip,&found)==-ENOENT);
    assert(neighbour_delete(&rt,0,ip)==-ENOENT);
    return 0;
}
