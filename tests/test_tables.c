#include <arpa/inet.h>
#include <assert.h>
#include <errno.h>
#include <limits.h>
#include <string.h>
#include "admin_service.h"

static struct app_runtime rt;
static struct net_config config;
static uint32_t random_state = 12345;
static uint32_t random_next(void) { random_state=random_state*1664525u+1013904223u; return random_state; }

static void routes(void)
{
    rt.port_count=2;
    for (unsigned i=0;i<2;i++) {
        rt.ports[i]=(struct port_state){.id=i,.configured=1,.started=1,.mtu=1500};
        config.addresses[config.address_count++]=(struct net_address){htonl(0x0a000001u+i),24,i};
    }
    assert(!net_connected_rebuild(&config));
    for (unsigned i=0;i<200;i++) config.routes[config.route_count++]=(struct net_route){
        .ip=htonl(0xc6120000u+(i<<8)),.prefix=24,.table=100+i%8,.dev=i%2,.type=i%17==0 ? i%3+1 : 0};
    config.routes[config.route_count++]=(struct net_route){.ip=htonl(0xc6120000u),.prefix=16,.table=100,.dev=1};
    config.rule_count=2;
    config.rules[0]=(struct net_rule){.pref=50,.table=999,.iif=NET_IIF_NONE};
    config.rules[1]=(struct net_rule){.pref=100,.table=100,.iif=NET_IIF_NONE};
    assert(!net_config_prepare(&config,2));
    rt.network=&config;
    for (unsigned i=0;i<2048;i++) {
        config.rules[1].table=100+i%8;
        config.rules[1].iif=i%3 ? NET_IIF_NONE : 0;
        rt.ports[0].admin_down=!!(i&4);rt.ports[1].admin_down=!!(i&8);
        uint32_t dst=htonl(0xc6120000u+((i%220)<<8)+(i%253)+1);
        struct route_result linear={0}, indexed={0};
        config.routes_indexed=0;
        enum drop_reason a=ipv4_route_query(&rt,dst,htonl(0x0a000064u),i%2,&linear);
        config.routes_indexed=1;
        enum drop_reason b=ipv4_route_query(&rt,dst,htonl(0x0a000064u),i%2,&indexed);
        assert(a==b && !memcmp(&linear,&indexed,sizeof(linear)));
    }
    config.rule_count=0;
    rt.ports[0].admin_down=rt.ports[1].admin_down=0;
    struct route_result r;
    assert(ipv4_route_query(&rt,htonl(0x0a000064u),0,NET_IIF_NONE,&r)==DROP_NONE && r.netif_id==0);
    rt.ports[0].admin_down=1;
    assert(ipv4_route_query(&rt,htonl(0x0a000064u),0,NET_IIF_NONE,&r)==DROP_NONE && r.netif_id==1);
    assert(netif_is_local_ip(&rt,config.addresses[1].ip));
    rt.ports[1].configured=0;
    assert(!netif_is_local_ip(&rt,config.addresses[1].ip));
    assert(!netif_is_local_ip(&rt,htonl(0xcb007101u)));
    rt.network=NULL;
}
static void handles(void)
{
    assert(!socket_subsystem_init(&rt));
    rt.sockets.capacity=1;
    int previous=0;
    for (unsigned i=0;i<1024;i++) {
        int fd=core_socket(&rt,PS_AF_INET,PS_SOCK_DGRAM,0);
        assert(fd>0 && socket_lookup(&rt,fd));
        assert(!socket_lookup(&rt,previous));
        assert(core_close(&rt,previous)==-EBADF);
        assert(!core_close(&rt,fd));
        previous=fd;
    }
    rt.sockets.generations[0]=(INT_MAX-1u)/PS_SOCKET_MAX;
    int last=core_socket(&rt,PS_AF_INET,PS_SOCK_DGRAM,0);
    assert(last>0 && socket_lookup(&rt,last));
    assert(!core_close(&rt,last));
    assert(core_socket(&rt,PS_AF_INET,PS_SOCK_DGRAM,0)==1);
    assert(!socket_lookup(&rt,last));
    assert(!socket_lookup(&rt,INT_MIN) && !socket_lookup(&rt,0) && !socket_lookup(&rt,2));
    socket_subsystem_fini(&rt);
}
static void neighbours(void)
{
    unsigned present[2][128]={{0}}, count=0;
    struct rte_ether_addr expected[2][128];
    memset(&rt.neighbours,0,sizeof(rt.neighbours));
    rt.port_count=2;
    for (unsigned i=0;i<2;i++) rt.ports[i]=(struct port_state){.id=i,.configured=1,.started=1,.mtu=1500};
    strcpy(rt.ports[0].name,"eth0");strcpy(rt.ports[1].name,"eth1");
    for (unsigned n=0;n<10000;n++) {
        unsigned dev=(random_next()>>16)%2, key=(random_next()>>16)%128;
        uint32_t ip=htonl(0xc0000201u+key);
        if ((random_next()>>16)%3) {
            struct rte_ether_addr mac={{2,0,0,0,(uint8_t)(n>>8),(uint8_t)n}};
            int rc=neighbour_learn(&rt.neighbours,dev,ip,&mac);
            if (!present[dev][key] && count==NEIGHBOUR_CAPACITY) assert(rc==-ENOSPC);
            else {assert(!rc);if (!present[dev][key]) count++;present[dev][key]=1;expected[dev][key]=mac;}
        } else {
            int rc=neighbour_delete(&rt,dev,ip);
            if (!present[dev][key]) assert(rc==-ENOENT);
            else {assert(!rc);present[dev][key]=0;count--;}
        }
        for (unsigned d=0;d<2;d++) for (unsigned k=0;k<128;k++) {
            struct rte_ether_addr mac;
            int rc=neighbour_lookup(&rt.neighbours,d,htonl(0xc0000201u+k),&mac);
            if (present[d][k]) assert(!rc && !memcmp(&mac,&expected[d][k],sizeof(mac)));
            else assert(rc==-ENOENT);
        }
    }
    struct admin_request flush={.group=ADM_NEIGH,.verb=ADM_FLUSH};strcpy(flush.dev,"eth0");
    assert(!admin_worker_operation(&rt,&flush));
    for (unsigned d=0;d<2;d++) for (unsigned k=0;k<128;k++) {
        struct rte_ether_addr mac;
        int rc=neighbour_lookup(&rt.neighbours,d,htonl(0xc0000201u+k),&mac);
        assert((!d || !present[d][k]) ? rc==-ENOENT : rc==0);
    }
}
int main(void) { routes(); handles(); neighbours(); return 0; }
