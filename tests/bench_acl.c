#define _POSIX_C_SOURCE 200809L
#include <arpa/inet.h>
#include <stdint.h>
#include <stdio.h>
#include <time.h>
#include "net_config.h"

static uint64_t nanoseconds(void)
{
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);
    return (uint64_t)t.tv_sec*1000000000u + (uint64_t)t.tv_nsec;
}
int main(void)
{
    static struct net_config config;
    struct acl_key keys[64];
    int results[64];
    const unsigned counts[]={0,8,32,128}, rounds=20000;
    volatile int total=0;
    for (unsigned i=0;i<64;i++) keys[i]=(struct acl_key){.src=htonl(0xc0000201u+i), .iif=0, .proto=17, .ports_valid=1, .dport=9000};
    for (unsigned i=0;i<NET_ACL_MAX;i++) config.acls[i]=(struct net_acl){.pref=i, .src=htonl(0x0a000001u+i), .src_prefix=32, .iif=NET_IIF_NONE, .drop=1};
    puts("rules,keys,ns_per_key_full_miss");
    for (unsigned i=0;i<sizeof(counts)/sizeof(counts[0]);i++) {
        config.acl_count=counts[i];
        uint64_t start=nanoseconds();
        for (unsigned round=0;round<rounds;round++) {
            net_acl_classify_batch(&config,keys,64,results);
            total+=results[round%64];
        }
        printf("%u,%u,%.2f\n",counts[i],rounds*64,(double)(nanoseconds()-start)/(rounds*64));
    }
    return total==-((int)rounds*4) ? 0 : 1;
}
