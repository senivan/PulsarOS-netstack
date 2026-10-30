#define _POSIX_C_SOURCE 200809L
#include <arpa/inet.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "admin_service.h"

static struct app_runtime rt;
static struct admin_view view;
static struct net_config next;
static volatile uint64_t sink;

static uint64_t now(void)
{
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);
    return (uint64_t)t.tv_sec*1000000000u + (uint64_t)t.tv_nsec;
}
static void result(const char *name, unsigned count, unsigned rounds, uint64_t start, uint64_t sum)
{
    uint64_t elapsed = now()-start;
    sink += sum;
    printf("%s,%u,%.2f\n", name, count, (double)elapsed/rounds);
}
static void apply(const struct admin_request *request)
{
    int rc = admin_mutate(&view, request, &next);
    if (rc) { fprintf(stderr, "benchmark setup: %d\n", rc); exit(1); }
    view.config = next;
}
static void routing(void)
{
    view.port_count = rt.port_count = NETIF_MAX;
    view.config.generation = 1;
    for (unsigned i=0; i<NETIF_MAX; i++) {
        rt.ports[i] = (struct port_state){.id=i, .configured=1, .started=1, .mtu=1500};
        snprintf(rt.ports[i].name, sizeof(rt.ports[i].name), "eth%u", i);
        view.links[i].port = rt.ports[i];
    }
    for (unsigned i=0; i<NET_ADDR_MAX; i++) {
        struct admin_request r = {.group=ADM_ADDR, .verb=ADM_ADD};
        r.v[F_IP]=htonl(0x0a000001u+(i<<8)); r.v[F_PREFIX]=24;
        snprintf(r.dev, sizeof(r.dev), "eth%u", i%NETIF_MAX);
        apply(&r);
    }
    for (unsigned i=0; i<NET_ROUTE_MAX-NET_ADDR_MAX; i++) {
        struct admin_request r = {.group=ADM_ROUTE, .verb=ADM_ADD};
        r.v[F_IP]=htonl(0xc6120000u+(i<<8)); r.v[F_PREFIX]=24; r.v[F_TABLE]=100+i%16;
        snprintf(r.dev, sizeof(r.dev), "eth%u", i%NETIF_MAX);
        apply(&r);
    }
    rt.network = &view.config;
    uint64_t sum=0, start=now();
    for (unsigned i=0; i<200000; i++) sum += netif_is_local_ip(&rt, htonl(0xcb007101u));
    result("local_address_miss", NET_ADDR_MAX, 200000, start, sum);
    for (unsigned policies=0; policies<=32; policies+=32) {
        struct admin_request r = {.group=ADM_RULE, .verb=ADM_ADD};
        for (unsigned i=0; i<policies; i++) {
            r.v[F_PREF]=i+1; r.v[F_TABLE]=1000+i;
            apply(&r);
        }
        r.v[F_PREF]=100; r.v[F_TABLE]=115; apply(&r);
        struct route_result route;
        sum=0; start=now();
        for (unsigned i=0; i<20000; i++) {
            enum drop_reason reason=ipv4_route_query(&rt, htonl(0xc612bf01u), htonl(0x0a000001u), NET_IIF_NONE, &route);
            if (reason!=DROP_NONE || route.table!=115) exit(1);
            sum += route.netif_id;
        }
        result(policies ? "route_32_fallthrough" : "route_table_hit", NET_ROUTE_MAX, 20000, start, sum);
        r.verb=ADM_FLUSH; apply(&r);
    }
    rt.network = NULL;
}
static void main_table(void)
{
    memset(&view.config, 0, sizeof(view.config));
    view.config.generation=1;
    view.port_count=rt.port_count=1;
    struct admin_request r={.group=ADM_ADDR,.verb=ADM_ADD};
    strcpy(r.dev,"eth0");r.v[F_IP]=htonl(0x0a000001u);r.v[F_PREFIX]=24;apply(&r);
    r=(struct admin_request){.group=ADM_ROUTE,.verb=ADM_ADD};
    strcpy(r.dev,"eth0");r.v[F_TABLE]=NET_TABLE_MAIN;apply(&r);
    rt.network=&view.config;
    for (unsigned phase=0;phase<2;phase++) {
        if (phase) for (unsigned i=0;i<254;i++) {
            r.v[F_IP]=htonl(0xc6120000u+(i<<8));r.v[F_PREFIX]=24;apply(&r);
        }
        struct route_result route;
        uint64_t sum=0,start=now();
        for (unsigned i=0;i<20000;i++) {
            if (ipv4_route_query(&rt,htonl(0xc612fd01u),htonl(0x0a000001u),NET_IIF_NONE,&route)!=DROP_NONE || route.table!=NET_TABLE_MAIN) exit(1);
            sum+=route.mtu;
        }
        result("route_main_hit",view.config.route_count,20000,start,sum);
    }
    rt.network=NULL;
}
static void sockets(void)
{
    const unsigned counts[]={1,64,256};
    for (unsigned n=0; n<sizeof(counts)/sizeof(counts[0]); n++) {
        if (socket_subsystem_init(&rt)) exit(1);
        ps_fd_t fds[PS_SOCKET_MAX];
        for (unsigned i=0; i<counts[n]; i++) {
            fds[i]=core_socket(&rt, PS_AF_INET, PS_SOCK_DGRAM, 0);
            if (fds[i]<0) exit(1);
        }
        uint64_t sum=0, start=now();
        for (unsigned i=0; i<200000; i++) sum += socket_lookup(&rt, fds[(i*73)%counts[n]]) != NULL;
        result("socket_fd_hit", counts[n], 200000, start, sum);
        sum=0; start=now();
        for (unsigned i=0; i<200000; i++) sum += socket_lookup(&rt, INT_MAX) != NULL;
        result("socket_fd_miss", counts[n], 200000, start, sum);
        socket_subsystem_fini(&rt);
    }
}
static void neighbours(void)
{
    const unsigned counts[]={16,32,48,64};
    const struct rte_ether_addr mac={{2,0,0,0,0,1}};
    struct rte_ether_addr found;
    for (unsigned n=0; n<sizeof(counts)/sizeof(counts[0]); n++) {
        memset(&rt.neighbours, 0, sizeof(rt.neighbours));
        for (unsigned i=0; i<counts[n]; i++)
            if (neighbour_learn(&rt.neighbours, 0, htonl(0xc0000201u+i), &mac)) exit(1);
        uint64_t sum=0, start=now();
        for (unsigned i=0; i<200000; i++) sum += !neighbour_lookup(&rt.neighbours, 0, htonl(0xc0000201u+(i*13)%counts[n]), &found);
        result("neighbour_hit", counts[n], 200000, start, sum);
        sum=0; start=now();
        for (unsigned i=0; i<200000; i++) sum += !neighbour_lookup(&rt.neighbours, 0, htonl(0xc6336401u+i%256), &found);
        result("neighbour_miss", counts[n], 200000, start, sum);
        if (counts[n]==NEIGHBOUR_CAPACITY) continue;
        sum=0; start=now();
        for (unsigned i=0; i<20000; i++) {
            uint32_t ip=htonl(0xc6336401u+i%256);
            if (neighbour_learn(&rt.neighbours, 0, ip, &mac) || neighbour_delete(&rt, 0, ip)) exit(1);
            sum++;
        }
        result("neighbour_insert_delete_pair", counts[n], 20000, start, sum);
    }
}
int main(void)
{
    puts("case,entries,ns_per_operation");
    routing(); main_table(); sockets(); neighbours();
    return sink==0;
}
