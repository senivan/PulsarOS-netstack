#include <arpa/inet.h>
#include <errno.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include "admin_service.h"
#include "daemon.h"

struct output { char *text; size_t size, used; int error, json, first; };
static void append(struct output *o, const char *format, ...)
{
    if (o->error) return;
    va_list args; va_start(args, format);
    int n = vsnprintf(o->text+o->used, o->size-o->used, format, args);
    va_end(args);
    if (n < 0 || (size_t)n >= o->size-o->used) { o->error = -ENOBUFS; return; }
    o->used += (size_t)n;
}
static const char *address(uint32_t ip, char b[16]) { return inet_ntop(AF_INET, &ip, b, 16) ? b : "?"; }
static void row(struct output *o) { if (o->json) { append(o, "%s{", o->first ? "" : ","); o->first=0; } }
static void end(struct output *o) { append(o, o->json ? "}" : "\n"); }
static void number(struct output *o, const char *name, uint64_t n, int last)
{
    append(o, o->json ? "\"%s\":%llu%s" : "%s=%llu%s", name, (unsigned long long)n, last ? "" : (o->json ? "," : " "));
}
static void string(struct output *o, const char *name, const char *s, int last)
{
    append(o, o->json ? "\"%s\":\"" : "%s=", name);
    for (const unsigned char *p=(const unsigned char *)s; *p; p++) {
        if (o->json && (*p < 32 || *p == '"' || *p == '\\')) append(o, "\\u%04x", *p);
        else append(o, "%c", *p);
    }
    append(o, o->json ? "\"%s" : "%s", last ? "" : (o->json ? "," : " "));
}
static const char *type(uint32_t action)
{
    static const char *names[]={"unicast", "blackhole", "unreachable", "prohibit"};
    return action <= NET_PROHIBIT ? names[action] : "invalid";
}
static const char *device(const struct admin_view *v, unsigned dev) { return dev<v->port_count ? v->links[dev].port.name : "*"; }
static void prefix(struct output *o, const char *name, uint32_t ip, uint32_t length, int last)
{
    char b[16], text[24]; snprintf(text, sizeof(text), "%s/%u", address(ip,b), length); string(o,name,text,last);
}
static void rule(struct output *o, const struct admin_view *v, const struct net_rule *r)
{
    row(o); number(o,"pref",r->pref,0); prefix(o,"from",r->src,r->src_prefix,0); prefix(o,"to",r->dst,r->dst_prefix,0);
    string(o,"iif",device(v,r->iif),0); string(o,"action",type(r->type),0); number(o,"table",r->table,1); end(o);
}
int admin_format(const struct admin_view *v, const struct admin_request *r, const struct daemon_service *apps, char *text, size_t size)
{
    struct output o={.text=text,.size=size,.json=!!(r->flags&ADMIN_JSON),.first=1};
    int filter = *r->dev ? admin_device(v,r->dev) : -1;
    if (*r->dev && filter<0) return filter;
    if (o.json) append(&o,"{\"schema\":1,\"generation\":%llu,\"items\":[",(unsigned long long)v->config.generation);
    char b[16], d[16], mac[24];
    if (r->group == ADM_STATUS) {
        unsigned clients=0, tables=3;
        for (unsigned i=0;i<apps->max_clients;i++) clients += !!atomic_load_explicit(&apps->identities[i].owner,memory_order_acquire);
        for (unsigned i=0;i<v->config.route_count;i++) {
            uint32_t t=v->config.routes[i].table;
            if (t==NET_TABLE_MAIN || t==NET_TABLE_DEFAULT) continue;
            unsigned j; for(j=0;j<i;j++) if(v->config.routes[j].table==t) break;
            if(j==i) tables++;
        }
        row(&o); string(&o,"state","running",0); number(&o,"uptime_seconds",v->uptime,0); number(&o,"workers",1,0);
        number(&o,"ports",v->port_count,0); number(&o,"applications",clients,0); number(&o,"sockets",v->socket_count,0);
        number(&o,"acl_rules",v->config.acl_count,0); number(&o,"routing_tables",tables,0); number(&o,"forwarding",v->forwarding,1); end(&o);
    } else if (r->group == ADM_LINK) {
        for(unsigned i=0;i<v->port_count;i++) {
            if(filter>=0 && i!=(unsigned)filter) continue;
            const struct admin_link *l=&v->links[i]; const struct port_state *p=&l->port;
            snprintf(mac,sizeof(mac),"%02x:%02x:%02x:%02x:%02x:%02x",p->mac.addr_bytes[0],p->mac.addr_bytes[1],p->mac.addr_bytes[2],p->mac.addr_bytes[3],p->mac.addr_bytes[4],p->mac.addr_bytes[5]);
            row(&o); number(&o,"id",p->id,0); string(&o,"name",p->name,0); string(&o,"admin",p->admin_down?"DOWN":"UP",0);
            number(&o,"carrier",l->carrier,0); number(&o,"mtu",p->mtu,!(r->flags&ADMIN_STATS) && (r->flags&ADMIN_BRIEF));
            if(!(r->flags&ADMIN_BRIEF)) { number(&o,"dpdk_port",p->port_id,0); string(&o,"mac",mac,0); string(&o,"driver",l->driver,!(r->flags&ADMIN_STATS)); }
            if(r->flags&ADMIN_STATS) {
                number(&o,"rx_packets",p->rx_packets,0); number(&o,"rx_bytes",p->rx_bytes,0); number(&o,"tx_packets",p->tx_packets,0); number(&o,"tx_bytes",p->tx_bytes,0);
                number(&o,"tx_drops",p->tx_drops,0); number(&o,"rx_errors",l->hardware.ierrors,0); number(&o,"rx_missed",l->hardware.imissed,0); number(&o,"tx_errors",l->hardware.oerrors,1);
            }
            end(&o);
        }
    } else if(r->group==ADM_ADDR) {
        for(unsigned i=0;i<v->config.address_count;i++) { const struct net_address *a=&v->config.addresses[i];
            if(filter>=0 && a->dev!=(unsigned)filter) continue;
            row(&o); string(&o,"dev",device(v,a->dev),0); prefix(&o,"address",a->ip,a->prefix,1); end(&o);
        }
    } else if(r->group==ADM_ROUTE && r->verb==ADM_GET) {
        if(v->route_reason!=DROP_NONE && v->route_reason!=DROP_ROUTE_BLACKHOLE && v->route_reason!=DROP_ROUTE_UNREACHABLE && v->route_reason!=DROP_ROUTE_PROHIBIT) return -ENETUNREACH;
        const struct route_result *p=&v->route;
        row(&o); string(&o,"destination",address(r->v[F_IP],b),0); string(&o,"source",address(p->source_ip_be,d),0);
        string(&o,"dev",p->type?"*":device(v,p->netif_id),0); string(&o,"next_hop",address(p->next_hop_be,b),0);
        number(&o,"table",p->table,0); number(&o,"rule_pref",p->rule_pref,0); string(&o,"type",p->local?"local":type(p->type),1); end(&o);
    } else if(r->group==ADM_ROUTE) {
        if(r->v[F_TABLE]==0 || r->v[F_TABLE]==NET_TABLE_LOCAL)
            for(unsigned i=0;i<v->config.address_count;i++) { const struct net_address *a=&v->config.addresses[i];
                row(&o); prefix(&o,"destination",a->ip,32,0); string(&o,"dev",device(v,a->dev),0); number(&o,"table",NET_TABLE_LOCAL,0); string(&o,"type","local",1); end(&o);
            }
        for(unsigned i=0;i<v->config.route_count;i++) { const struct net_route *p=&v->config.routes[i];
            if(r->v[F_TABLE] && p->table!=r->v[F_TABLE]) continue;
            row(&o); prefix(&o,"destination",p->ip,p->prefix,0); string(&o,"gateway",address(p->gateway,b),0);
            string(&o,"dev",p->type?"*":device(v,p->dev),0); number(&o,"table",p->table,0); number(&o,"connected",p->connected,0); string(&o,"type",type(p->type),1); end(&o);
        }
    } else if(r->group==ADM_RULE) {
        struct net_rule builtin={.iif=NET_IIF_NONE,.table=NET_TABLE_LOCAL}; rule(&o,v,&builtin);
        for(unsigned i=0;i<v->config.rule_count;i++) rule(&o,v,&v->config.rules[i]);
        builtin.pref=32766; builtin.table=NET_TABLE_MAIN; rule(&o,v,&builtin);
        builtin.pref=32767; builtin.table=NET_TABLE_DEFAULT; rule(&o,v,&builtin);
    } else if(r->group==ADM_ACL) {
        for(unsigned i=0;i<v->config.acl_count;i++) { const struct net_acl *a=&v->config.acls[i];
            row(&o); number(&o,"id",a->pref,0); number(&o,"pref",a->pref,0); prefix(&o,"src",a->src,a->src_prefix,0); prefix(&o,"dst",a->dst,a->dst_prefix,0);
            string(&o,"iif",device(v,a->iif),0); number(&o,"protocol",a->proto,0); number(&o,"ports",a->ports,0);
            number(&o,"sport_min",a->sport_min,0); number(&o,"sport_max",a->sport_max,0); number(&o,"dport_min",a->dport_min,0); number(&o,"dport_max",a->dport_max,0);
            string(&o,"action",a->drop?"drop":"accept",0); number(&o,"packets",v->acl.rules[i].packets,0); number(&o,"bytes",v->acl.rules[i].bytes,1); end(&o);
        }
        row(&o); string(&o,"default",v->config.default_drop?"drop":"accept",0); number(&o,"accepted",v->acl.accepted,0); number(&o,"dropped",v->acl.dropped,0); number(&o,"default_matches",v->acl.defaults,1); end(&o);
    } else if(r->group==ADM_NEIGH) {
        for(unsigned i=0;i<NEIGHBOUR_CAPACITY;i++) { const struct neighbour_entry *n=&v->neighbours.entries[i];
            if(!n->in_use || (filter>=0 && n->netif_id!=(unsigned)filter)) continue;
            snprintf(mac,sizeof(mac),"%02x:%02x:%02x:%02x:%02x:%02x",n->mac.addr_bytes[0],n->mac.addr_bytes[1],n->mac.addr_bytes[2],n->mac.addr_bytes[3],n->mac.addr_bytes[4],n->mac.addr_bytes[5]);
            row(&o); string(&o,"address",address(n->ip_be,b),0); string(&o,"dev",device(v,n->netif_id),0); string(&o,"lladdr",mac,0); string(&o,"state",n->permanent?"PERMANENT":"DYNAMIC",1); end(&o);
        }
    } else if(r->group==ADM_SOCKET) {
        static const char *states[]={"CLOSED","LISTEN","SYN_SENT","SYN_RECEIVED","ESTABLISHED","FIN_WAIT_1","FIN_WAIT_2","CLOSE_WAIT","LAST_ACK","TIME_WAIT"};
        for(unsigned i=0;i<v->socket_count;i++) { const struct admin_socket *s=&v->sockets[i];
            row(&o); number(&o,"id",s->fd,0); number(&o,"owner",s->owner,0); string(&o,"protocol",s->type==PS_SOCK_DGRAM?"udp":"tcp",0);
            string(&o,"local",address(s->local.ip_be,b),0); number(&o,"local_port",s->local.port,0); string(&o,"remote",address(s->remote.ip_be,d),0); number(&o,"remote_port",s->remote.port,0);
            string(&o,"state",s->type==PS_SOCK_DGRAM?"BOUND":(s->state<sizeof(states)/sizeof(states[0])?states[s->state]:"UNKNOWN"),0);
            number(&o,"open",s->open,0); number(&o,"rx_queue",s->rx,0); number(&o,"tx_queue",s->tx,1); end(&o);
        }
    } else if(r->group==ADM_APP) {
        for(unsigned i=0;i<apps->max_clients;i++) { uint64_t owner=atomic_load_explicit(&apps->identities[i].owner,memory_order_acquire); if(!owner) continue;
            unsigned count=0; for(unsigned j=0;j<v->socket_count;j++) count+=v->sockets[j].owner==owner;
            row(&o); number(&o,"id",owner,0); number(&o,"pid",atomic_load(&apps->identities[i].pid),0); number(&o,"uid",atomic_load(&apps->identities[i].uid),0);
            number(&o,"sockets",count,0); string(&o,"state","connected",1); end(&o);
        }
    } else if(r->group==ADM_STATS) {
        for(unsigned i=0;i<NODE_MAX;i++) { const struct node_stats *n=&v->nodes[i];
            row(&o); number(&o,"node",i,0); number(&o,"packets",n->packets,0); number(&o,"bytes",n->bytes,0); number(&o,"drops",n->drops,0); number(&o,"errors",n->errors,1); end(&o);
        }
        for(unsigned i=1;i<DROP_REASON_MAX;i++) if(v->drops[i]) {row(&o); number(&o,"drop_reason",i,0); number(&o,"count",v->drops[i],1); end(&o);}
    } else return -EOPNOTSUPP;
    if(o.json) append(&o,"]}\n");
    return o.error ? o.error : (int)o.used;
}
