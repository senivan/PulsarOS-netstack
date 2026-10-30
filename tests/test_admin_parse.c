#define _POSIX_C_SOURCE 200809L
#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "admin.h"

static int parse(const char *line, struct admin_request *r)
{
    char text[512], error[256]; assert(strlen(line)<sizeof(text));strcpy(text,line);
    char *argv[64]; int count=0;
    for(char *p=strtok(text," ");p;p=strtok(NULL," ")) {assert(count<64);argv[count++]=p;}
    return admin_parse(count,argv,r,error,sizeof(error));
}
int main(void)
{
    struct admin_request r;
    assert(!parse("route get 8.8.8.8 from 10.0.0.2",&r));
    assert(!parse("route show table all",&r)&&!r.v[F_TABLE]);
    assert(!parse("rule add pref 100 iif eth1 lookup 100",&r));
    assert(!parse("rule add pref 100 action prohibit",&r));
    assert(!parse("acl add pref 4294967295 proto tcp sport any dport 80-443 action drop",&r));
    const char *invalid[]={"route add 10.0.0.1/8 dev eth0", "addr add 1.2.3.4/999 dev eth0", "addr add invalid/24 dev eth0",
        "rule add pref 4294967296 lookup 100", "rule flush pref 100", "acl add pref -1 action drop", "acl show proto udp",
        "route get 8.8.8.8 table 100", "route show metric 5", "neigh add 10.0.0.1 lladdr 00:00:00:00:00:01 dev eth0 nud reachable",
        "link set dev eth0 up mtu 1400", "link show dev ../bad", "acl add pref 1 dport 53 action drop", "status add"};
    for(unsigned i=0;i<sizeof(invalid)/sizeof(invalid[0]);i++) assert(parse(invalid[i],&r));
    char path[]="/tmp/pulsaros-acl-test-XXXXXX";int fd=mkstemp(path);assert(fd>=0);
    FILE *f=fdopen(fd,"w");assert(f);fputs("# test\n\ndefault drop\n100 proto udp dport 5000-6000 accept\n200 src 192.0.2.0/24 drop\n",f);assert(!fclose(f));
    char command[256];snprintf(command,sizeof(command),"acl apply %s",path);
    assert(!parse(command,&r)&&r.count==2&&r.v[F_ACTION]==1);
    uint8_t encoded[ADMIN_REQUEST_MAX];size_t n=admin_request_encode(encoded,&r);
    struct admin_request decoded;assert(!admin_request_decode(encoded,n,&decoded));assert(!memcmp(&r,&decoded,sizeof(r)));
    f=fopen(path,"w");assert(f);fputs("100 action accept\n100 action drop\n",f);assert(!fclose(f));assert(parse(command,&r)==-EEXIST);
    f=fopen(path,"w");assert(f);fputs("default accept\ninvalid\n",f);assert(!fclose(f));assert(parse(command,&r));
    assert(!unlink(path));
    return 0;
}
