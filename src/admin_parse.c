#include <arpa/inet.h>
#include <ctype.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "admin.h"

static int number(const char *s, uint32_t *out)
{
    if (!*s) return -EINVAL;
    for (const char *p=s;*p;p++) if (!isdigit((unsigned char)*p)) return -EINVAL;
    char *end; errno=0; unsigned long n=strtoul(s,&end,10);
    if(errno || *end || n>UINT32_MAX) return -EINVAL;
    *out=(uint32_t)n; return 0;
}
static int ip_prefix(const char *s, uint32_t *ip, uint32_t *prefix, int host)
{
    if(!strcmp(s,"all") || !strcmp(s,"default")) { if(host) return -EINVAL; *ip=*prefix=0; return 0; }
    char text[64]; if(strlen(s)>=sizeof(text)) return -EINVAL; strcpy(text,s);
    char *slash=strchr(text,'/'); *prefix=32;
    if(slash) { *slash++=0; if(host || number(slash,prefix) || *prefix>32) return -EINVAL; }
    return inet_pton(AF_INET,text,ip)==1 ? 0 : -EINVAL;
}
static int table(const char *s, uint32_t *out)
{
    if(!strcmp(s,"main")) *out=NET_TABLE_MAIN;
    else if(!strcmp(s,"local")) *out=NET_TABLE_LOCAL;
    else if(!strcmp(s,"default")) *out=NET_TABLE_DEFAULT;
    else if(!strcmp(s,"all")) *out=0;
    else if(number(s,out) || !*out) return -EINVAL;
    return 0;
}
static int action(const char *s, uint32_t *out)
{
    if(!strcmp(s,"unicast")) *out=NET_UNICAST;
    else if(!strcmp(s,"blackhole")) *out=NET_BLACKHOLE;
    else if(!strcmp(s,"unreachable")) *out=NET_UNREACHABLE;
    else if(!strcmp(s,"prohibit")) *out=NET_PROHIBIT;
    else return -EINVAL;
    return 0;
}
static int drop(const char *s, uint32_t *out)
{
    if(!strcmp(s,"accept")) *out=0;
    else if(!strcmp(s,"drop")) *out=1;
    else return -EINVAL;
    return 0;
}
static int devname(const char *s, char out[64])
{
    if(!*s || strlen(s)>=64) return -EINVAL;
    for(const unsigned char *p=(const unsigned char *)s;*p;p++)
        if(!isalnum(*p) && *p!='_' && *p!='-' && *p!='.' && *p!=':') return -EINVAL;
    strcpy(out,s); return 0;
}
static int ports(const char *s, uint32_t *lo, uint32_t *hi)
{
    if(!strcmp(s,"any")) { *lo=0; *hi=65535; return 0; }
    char text[32]; if(strlen(s)>=sizeof(text)) return -EINVAL; strcpy(text,s);
    char *dash=strchr(text,'-'); if(dash) *dash++=0;
    if(number(text,lo)) return -EINVAL;
    *hi=*lo;
    if(dash && number(dash,hi)) return -EINVAL;
    return *lo>*hi || *hi>65535 ? -EINVAL : 0;
}
static int group(const char *s)
{
    static const char *names[]={"","status","stats","link","addr","route","rule","neigh","acl","app","socket","monitor"};
    for(unsigned i=1;i<=ADM_MONITOR;i++) if(!strcmp(s,names[i])) return (int)i;
    if(!strcmp(s,"address")||!strcmp(s,"a")) return ADM_ADDR;
    if(!strcmp(s,"r")) return ADM_ROUTE;
    if(!strcmp(s,"l")) return ADM_LINK;
    if(!strcmp(s,"neighbor")||!strcmp(s,"neighbour")||!strcmp(s,"n")) return ADM_NEIGH;
    return 0;
}
static int verb(const char *s)
{
    static const char *names[]={"","show","add","replace","del","flush","get","set","apply","default"};
    for(unsigned i=1;i<=ADM_DEFAULT;i++) if(!strcmp(s,names[i])) return (int)i;
    if(!strcmp(s,"list")||!strcmp(s,"ls")) return ADM_SHOW;
    if(!strcmp(s,"delete")) return ADM_DEL;
    return 0;
}
static int apply_file(const char *, struct admin_request *, char *, size_t);
int admin_parse(int argc, char **argv, struct admin_request *r, char *error, size_t size)
{
    memset(r,0,sizeof(*r));
    if(!argc || !(r->group=(uint32_t)group(argv[0]))) goto invalid;
    r->verb=ADM_SHOW; r->v[F_TABLE]=NET_TABLE_MAIN;
    int i=1;
    if(i<argc && verb(argv[i])) r->verb=(uint32_t)verb(argv[i++]);
    if(r->group==ADM_ACL && i<argc && !strcmp(argv[i],"stats")) { i++; r->flags|=ADMIN_STATS; }
    if(r->group==ADM_MONITOR) {
        if(r->verb!=ADM_SHOW) goto invalid;
        if(i<argc) { int g=group(argv[i++]); if(g<ADM_LINK || g>ADM_ACL) goto invalid; r->v[F_PROTO]=(uint32_t)g; }
        if(i!=argc) goto invalid;
        return 0;
    }
    if(r->group==ADM_ACL && r->verb==ADM_APPLY) {
        if(i+1!=argc) goto invalid;
        return apply_file(argv[i],r,error,size);
    }
    uint32_t seen=0;
    int have_prefix=0, have_pref=0, have_action=0, have_lookup=0, have_mac=0, have_nud=0;
    if(r->group==ADM_ROUTE && r->verb!=ADM_SHOW && r->verb!=ADM_FLUSH) {
        if(i<argc && !action(argv[i],&r->v[F_ACTION])) { have_action=1; i++; }
        if(i>=argc || ip_prefix(argv[i++],&r->v[F_IP],&r->v[F_PREFIX],r->verb==ADM_GET)) goto invalid;
        have_prefix=1;
    } else if(r->group==ADM_ADDR && r->verb!=ADM_SHOW && r->verb!=ADM_FLUSH) {
        if(i>=argc || !strchr(argv[i],'/') || ip_prefix(argv[i++],&r->v[F_IP],&r->v[F_PREFIX],0)) goto invalid;
        have_prefix=1;
    } else if(r->group==ADM_NEIGH && r->verb!=ADM_SHOW && r->verb!=ADM_FLUSH) {
        uint32_t unused;
        if(i>=argc || ip_prefix(argv[i++],&r->v[F_IP],&unused,1)) goto invalid;
    } else if(r->group==ADM_ACL && r->verb==ADM_DEFAULT && i<argc) {
        if(i+1!=argc || drop(argv[i++],&r->v[F_ACTION])) goto invalid;
        have_action=1;
    }
    for(;i<argc;i++) {
        const char *key=argv[i];
        if(r->group==ADM_STATS && !strcmp(key,"--nodes")) {r->flags|=ADMIN_NODES;continue;}
        if(r->group==ADM_LINK && r->verb==ADM_SET && (!strcmp(key,"up")||!strcmp(key,"down"))) {
            if(r->v[F_PORTS]) goto invalid;
            r->v[F_PORTS]=1; r->v[F_ACTION]=!strcmp(key,"up"); continue;
        }
        if(r->group==ADM_ACL && r->verb==ADM_ADD && !drop(key,&r->v[F_ACTION])) {if(have_action) goto invalid;have_action=1;continue;}
        if(i+1>=argc) goto invalid;
        const char *value=argv[++i];
        unsigned bit;
        if(!strcmp(key,"dev")) {
            bit=0; if(r->group!=ADM_LINK && r->group!=ADM_ADDR && r->group!=ADM_ROUTE && r->group!=ADM_NEIGH) goto invalid;
            if(devname(value,r->dev)) goto invalid;
        } else if(!strcmp(key,"iif")) {
            bit=0; if(r->group!=ADM_RULE && r->group!=ADM_ACL) goto invalid;
            if(strcmp(value,"any") && devname(value,r->dev)) goto invalid;
        } else if(!strcmp(key,"pref") || !strcmp(key,"priority")) {
            bit=1; if(r->group!=ADM_RULE && r->group!=ADM_ACL) goto invalid;
            if(number(value,&r->v[F_PREF])) goto invalid;
            have_pref=1;
        } else if(!strcmp(key,"src")||!strcmp(key,"from")) {
            bit=2; if((r->group!=ADM_RULE && r->group!=ADM_ACL && !(r->group==ADM_ROUTE&&r->verb==ADM_GET)) ||
                ip_prefix(value,&r->v[F_SRC],&r->v[F_SRC_PREFIX],r->group==ADM_ROUTE)) goto invalid;
        } else if(!strcmp(key,"dst")||!strcmp(key,"to")) {
            bit=3; if((r->group!=ADM_RULE && r->group!=ADM_ACL) || ip_prefix(value,&r->v[F_DST],&r->v[F_DST_PREFIX],0)) goto invalid;
        } else if(!strcmp(key,"proto")) {
            bit=4; if(r->group!=ADM_ACL) goto invalid;
            if(!strcmp(value,"tcp")) r->v[F_PROTO]=6;
            else if(!strcmp(value,"udp")) r->v[F_PROTO]=17;
            else if(!strcmp(value,"icmp")) r->v[F_PROTO]=1;
            else if(!strcmp(value,"any")) r->v[F_PROTO]=0;
            else if(number(value,&r->v[F_PROTO])||r->v[F_PROTO]>255) goto invalid;
        } else if(!strcmp(key,"sport")||!strcmp(key,"dport")) {
            bit=!strcmp(key,"sport")?5:6; if(r->group!=ADM_ACL) goto invalid;
            unsigned field=bit==5?F_SPORT_MIN:F_DPORT_MIN;
            if(ports(value,&r->v[field],&r->v[field+1])) goto invalid;
            r->v[F_PORTS]|=bit==5?1:2;
        } else if(!strcmp(key,"action")) {
            bit=7; if(have_action) goto invalid;
            if(r->group==ADM_ACL) {if(drop(value,&r->v[F_ACTION])) goto invalid;}
            else if(r->group==ADM_RULE) {if(action(value,&r->v[F_ACTION])||!r->v[F_ACTION]) goto invalid;}
            else goto invalid;
            have_action=1;
        } else if(!strcmp(key,"table")||!strcmp(key,"lookup")) {
            bit=8; if((r->group!=ADM_ROUTE && r->group!=ADM_RULE) || table(value,&r->v[F_TABLE])) goto invalid;
            have_lookup=1;
        } else if(!strcmp(key,"via")) {
            bit=9; uint32_t unused;
            if(r->group!=ADM_ROUTE || ip_prefix(value,&r->v[F_GATEWAY],&unused,1)) goto invalid;
        } else if(!strcmp(key,"mtu")) {
            bit=10; if(r->group!=ADM_LINK||r->verb!=ADM_SET||r->v[F_PORTS]||number(value,&r->v[F_IP])) goto invalid;
            r->v[F_PORTS]=2;
        } else if(!strcmp(key,"lladdr")) {
            bit=11; if(r->group!=ADM_NEIGH) goto invalid;
            unsigned bytes[6]; char tail;
            if(strlen(value)!=17 || sscanf(value,"%2x:%2x:%2x:%2x:%2x:%2x%c",bytes,bytes+1,bytes+2,bytes+3,bytes+4,bytes+5,&tail)!=6) goto invalid;
            for(unsigned n=0;n<6;n++) if(bytes[n]>255) goto invalid;
            r->v[F_SPORT_MIN]=bytes[0]<<8|bytes[1]; r->v[F_SPORT_MAX]=bytes[2]<<24|bytes[3]<<16|bytes[4]<<8|bytes[5];have_mac=1;
        } else if(!strcmp(key,"nud")) {
            bit=12; if(r->group!=ADM_NEIGH||strcmp(value,"permanent")) goto invalid;have_nud=1;
        } else goto invalid;
        if(seen&(1u<<bit)) goto invalid;
        seen|=1u<<bit;
    }
    if((r->group==ADM_STATUS||r->group==ADM_STATS||r->group==ADM_APP||r->group==ADM_SOCKET) && r->verb!=ADM_SHOW) goto invalid;
    if(r->group==ADM_ADDR && r->verb!=ADM_SHOW && !*r->dev) goto invalid;
    if(r->group==ADM_LINK && r->verb!=ADM_SHOW && (r->verb!=ADM_SET||!*r->dev||!r->v[F_PORTS])) goto invalid;
    if(r->group==ADM_NEIGH && r->verb!=ADM_SHOW && (!*r->dev || ((r->verb==ADM_ADD||r->verb==ADM_REPLACE)&&(!have_mac||!have_nud)))) goto invalid;
    if(r->group==ADM_ROUTE && r->verb!=ADM_SHOW && (!r->v[F_TABLE] || r->v[F_TABLE]==NET_TABLE_LOCAL)) goto invalid;
    if(r->group==ADM_ROUTE && (r->verb==ADM_ADD||r->verb==ADM_REPLACE) && !r->v[F_ACTION] && !*r->dev) goto invalid;
    if(r->group==ADM_RULE && ((r->verb==ADM_ADD && (!have_pref||(!have_lookup&&!have_action)||(have_lookup&&have_action))) || (r->verb==ADM_DEL&&!have_pref))) goto invalid;
    if(r->group==ADM_ACL && ((r->verb==ADM_ADD&&(!have_pref||!have_action)) || (r->verb==ADM_DEL&&!have_pref))) goto invalid;
    if(r->group==ADM_ACL && r->verb==ADM_DEFAULT && !have_action) {r->verb=ADM_SHOW;return 0;}
    if(r->group==ADM_ACL && r->v[F_PORTS] && r->v[F_PROTO]!=6 && r->v[F_PROTO]!=17) goto invalid;
    if((r->group==ADM_ROUTE && have_prefix && r->verb!=ADM_GET && (r->v[F_IP]&~net_mask(r->v[F_PREFIX]))) ||
        ((r->group==ADM_RULE||r->group==ADM_ACL) && ((r->v[F_SRC]&~net_mask(r->v[F_SRC_PREFIX]))||(r->v[F_DST]&~net_mask(r->v[F_DST_PREFIX]))))) goto invalid;
    uint32_t allowed=0;
    switch(r->group) {
    case ADM_LINK: allowed=r->verb==ADM_SET ? (1u|1u<<10) : 1u; break;
    case ADM_ADDR: allowed=1u; break;
    case ADM_ROUTE:
        allowed=r->verb==ADM_GET ? 1u<<2 : (r->verb==ADM_ADD||r->verb==ADM_REPLACE ? (1u|1u<<8|1u<<9) : 1u<<8);
        if(r->verb==ADM_FLUSH&&!have_lookup) goto invalid;
        break;
    case ADM_RULE:
        allowed=r->verb==ADM_ADD ? (1u|1u<<1|1u<<2|1u<<3|1u<<7|1u<<8) : (r->verb==ADM_DEL ? 1u<<1 : 0); break;
    case ADM_NEIGH: allowed=(r->verb==ADM_ADD||r->verb==ADM_REPLACE) ? (1u|1u<<11|1u<<12) : 1u; break;
    case ADM_ACL: allowed=r->verb==ADM_ADD ? 255u : (r->verb==ADM_DEL ? 1u<<1 : 0); break;
    default: break;
    }
    if(seen&~allowed) goto invalid;
    uint8_t wire[ADMIN_REQUEST_MAX]; struct admin_request decoded;
    if(admin_request_decode(wire,admin_request_encode(wire,r),&decoded)) goto invalid;
    return 0;
invalid:
    snprintf(error,size,"invalid or unsupported arguments"); return -EINVAL;
}
static int apply_file(const char *path, struct admin_request *r, char *error, size_t size)
{
    FILE *f=fopen(path,"r"); if(!f) {snprintf(error,size,"%s: %s",path,strerror(errno));return -errno;}
    char line[2048]; unsigned lineno=0; int rc=0, have_default=0;
    while(fgets(line,sizeof(line),f)) {
        lineno++;
        if(!strchr(line,'\n') && !feof(f)) {rc=-EINVAL;break;}
        char *comment=strchr(line,'#'); if(comment) *comment=0;
        char *tokens[70]; unsigned count=0; char *s=strtok(line," \t\r\n");
        while(s && count<70) {tokens[count++]=s;s=strtok(NULL," \t\r\n");}
        if(s) {rc=-EINVAL;break;} if(!count) continue;
        if(!strcmp(tokens[0],"default")) {
            if(have_default || count!=2 || drop(tokens[1],&r->v[F_ACTION])) {rc=-EINVAL;break;}
            have_default=1;continue;
        }
        if(r->count==NET_ACL_MAX) {rc=-ENOSPC;break;}
        char *args[74]={"acl","add","pref"}; for(unsigned i=0;i<count;i++) args[i+3]=tokens[i];
        struct admin_request entry;
        rc=admin_parse((int)count+3,args,&entry,error,size); if(rc) break;
        struct admin_acl *a=&r->acls[r->count++]; uint32_t *v=entry.v;
        a->rule=(struct net_acl){v[F_PREF],v[F_SRC],v[F_SRC_PREFIX],v[F_DST],v[F_DST_PREFIX],NET_IIF_NONE,v[F_PROTO],
            v[F_SPORT_MIN],v[F_SPORT_MAX],v[F_DPORT_MIN],v[F_DPORT_MAX],v[F_PORTS],v[F_ACTION]};
        strcpy(a->dev,entry.dev);
        for(unsigned i=0;i+1<r->count;i++) if(r->acls[i].rule.pref==a->rule.pref) rc=-EEXIST;
        if(rc) break;
    }
    if(ferror(f)) rc=-EIO;
    fclose(f);
    if(rc) snprintf(error,size,"%s:%u: invalid ACL ruleset (%s)",path,lineno,strerror(-rc));
    return rc;
}
void admin_usage(void)
{
    puts("usage: pulsar [-4] [-j] [-br] [-s] [--socket PATH] COMMAND\n"
         "  status | stats [--nodes] | app show | socket show\n"
         "  link show [dev DEV] | link set dev DEV up|down|mtu N\n"
         "  addr show [dev DEV] | addr add|replace|del IP/PREFIX dev DEV | addr flush dev DEV\n"
         "  route show [table TABLE|all] | route get IP [from IP]\n"
         "  route add|replace [unicast|blackhole|unreachable|prohibit] PREFIX [via IP] [dev DEV] [table TABLE]\n"
         "  route del PREFIX [table TABLE] | route flush table TABLE\n"
         "  rule show | rule add pref N [from PREFIX] [to PREFIX] [iif DEV] lookup TABLE\n"
         "  rule add pref N [from PREFIX] [to PREFIX] [iif DEV] action blackhole|unreachable|prohibit\n"
         "  rule del pref N | rule flush\n"
         "  neigh show [dev DEV] | neigh add|replace IP lladdr MAC dev DEV nud permanent\n"
         "  neigh del IP dev DEV | neigh flush dev DEV\n"
         "  acl show|stats | acl add pref N [src PREFIX] [dst PREFIX] [proto tcp|udp|icmp|N]\n"
         "      [sport N[-N]] [dport N[-N]] [iif DEV] action accept|drop\n"
         "  acl del pref N | acl flush | acl default [accept|drop] | acl apply FILE\n"
         "  monitor [link|addr|route|rule|neigh|acl] | help | version");
}
