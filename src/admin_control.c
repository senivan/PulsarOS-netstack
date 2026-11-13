#include <errno.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <time.h>
#include <unistd.h>
#include "admin_service.h"
#include "daemon.h"

static uint64_t milliseconds(void)
{
    struct timespec ts; clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec*1000 + ts.tv_nsec/1000000;
}
static void disconnect(struct admin_connection *c)
{
    if(c->fd>=0) close(c->fd);
    c->fd=-1;
    c->subscribed=0;
    if(!c->pending) { c->have=0; c->length=0; }
}
static void response(struct admin_connection *c, int result, uint64_t generation, size_t length)
{
    struct admin_header h={.id=c->header.id,.length=(uint32_t)length,.result=result,.generation=generation};
    admin_header_encode(c->output,&h);
    c->length=ADMIN_HEADER+length; c->sent=0;
    c->have=0; c->target=ADMIN_HEADER;
}
static void events(struct admin_service *s, struct admin_connection *c)
{
    const struct admin_events *e=&s->job.view.events;
    if(c->sequence==e->sequence || c->length) return;
    uint64_t lost=e->sequence-c->sequence>ADMIN_EVENT_MAX ? e->sequence-c->sequence-ADMIN_EVENT_MAX : 0;
    if(lost) c->sequence+=lost;
    size_t used=0;
    while(c->sequence<e->sequence) {
        const struct admin_event *v=&e->entries[c->sequence%ADMIN_EVENT_MAX];
        c->sequence++;
        if(c->request.v[F_PROTO] && c->request.v[F_PROTO]!=v->group && v->group!=ADM_STATUS) continue;
        static const char *kinds[]={"", "generation", "stats", "link", "addr", "route", "rule", "neigh", "acl", "app", "socket", "monitor"};
        char ip[16]; inet_ntop(AF_INET,&v->ip,ip,sizeof(ip));
        int n=snprintf((char *)c->output+ADMIN_HEADER+used,ADMIN_RESPONSE_MAX-used,
            "{\"schema\":1,\"sequence\":%llu,\"generation\":%llu,\"group\":%u,\"id\":%u,\"action\":%u,\"kind\":\"%s\",\"address\":\"%s\",\"prefix\":%u,\"dev\":%u,\"table\":%u,\"lost\":%llu}\n",
            (unsigned long long)v->sequence,(unsigned long long)v->generation,v->group,v->id,v->action,kinds[v->group],ip,v->prefix,v->dev,v->table,(unsigned long long)lost);
        if(n<0 || (size_t)n>=ADMIN_RESPONSE_MAX-used) break;
        used+=(size_t)n; lost=0;
    }
    if(lost && !used) {
        int n=snprintf((char *)c->output+ADMIN_HEADER,ADMIN_RESPONSE_MAX,
            "{\"schema\":1,\"kind\":\"overflow\",\"sequence\":%llu,\"generation\":%llu,\"lost\":%llu}\n",
            (unsigned long long)c->sequence,(unsigned long long)s->job.view.config.generation,(unsigned long long)lost);
        if(n>0) used=(size_t)n;
    }
    if(used) response(c,0,s->job.view.config.generation,used);
}
static int software(const struct admin_request *r)
{
    return (r->group==ADM_ADDR || r->group==ADM_ROUTE || r->group==ADM_RULE || r->group==ADM_ACL) &&
        r->verb!=ADM_SHOW && r->verb!=ADM_GET;
}
static void complete(struct admin_service *s)
{
    if (atomic_load_explicit(&s->state, memory_order_acquire) != ADMIN_MAILBOX_REPLY) return;
    struct admin_job *j = &s->job;
    struct admin_connection *c = s->current >= 0 ? &s->clients[s->current] : NULL;

    /* Build the candidate from the captured view before requesting activation. */
    if (c && s->phase == 0 && software(&c->request)) {
        struct net_config *next = malloc(sizeof(*next));
        j->result = next ? admin_mutate(&j->view, &c->request, next) : -ENOMEM;
        if (!j->result) {
            j->next = next;
            j->retired = NULL;
            j->type = ADMIN_ACTIVATE;
            s->phase = 1;
            atomic_store_explicit(&s->state, ADMIN_MAILBOX_WORKER, memory_order_release);
            return;
        }
        free(next);
    }

    /* Failed activation leaves the candidate unused; success retires the old view. */
    if (s->phase == 1) {
        if (j->result) free(j->next);
        else free(j->retired);
        j->next = NULL;
        j->retired = NULL;
    }

    if (c) {
        c->pending = 0;
        if (c->fd >= 0) {
            int n = 0;
            if (!j->result && c->request.group == ADM_MONITOR) {
                if (c->request.verb != ADM_SHOW || c->request.v[F_PROTO] > ADM_MONITOR) {
                    j->result = -EINVAL;
                } else {
                    c->subscribed = 1;
                    c->sequence = j->view.events.sequence;
                }
            } else if (!j->result && c->request.verb != ADM_SHOW && c->request.verb != ADM_GET) {
                n = snprintf((char *)c->output + ADMIN_HEADER, ADMIN_RESPONSE_MAX,
                    c->request.flags & ADMIN_JSON ?
                        "{\"schema\":1,\"generation\":%llu,\"applied\":true}\n" : "applied generation %llu\n",
                    (unsigned long long)j->view.config.generation);
            } else if (!j->result) {
                n = admin_format(&j->view, &c->request, s->applications,
                                 (char *)c->output + ADMIN_HEADER, ADMIN_RESPONSE_MAX);
            }
            if (n < 0) {
                j->result = n;
                n = 0;
            }
            response(c, j->result, j->view.config.generation, (size_t)n);
        } else {
            c->have = 0;
            c->length = 0;
        }
    }
    for (unsigned i = 0; i < ADMIN_CLIENT_MAX; i++) {
        if (s->clients[i].fd >= 0 && s->clients[i].subscribed) events(s, &s->clients[i]);
    }
    s->current = -1;
    atomic_store_explicit(&s->state, ADMIN_MAILBOX_CONTROL, memory_order_release);
}
static void accept_clients(struct admin_service *s)
{
    for(unsigned n=0;n<ADMIN_CLIENT_MAX;n++) {
        int fd=accept4(s->listener,NULL,NULL,SOCK_NONBLOCK|SOCK_CLOEXEC);
        if(fd<0) return;
        struct ucred cred; socklen_t len=sizeof(cred);
        if(getsockopt(fd,SOL_SOCKET,SO_PEERCRED,&cred,&len) || (cred.uid!=0 && cred.uid!=geteuid())) { close(fd); continue; }
        struct admin_connection *c=NULL;
        for(unsigned i=0;i<ADMIN_CLIENT_MAX;i++) if(s->clients[i].fd<0 && !s->clients[i].pending) { c=&s->clients[i]; break; }
        if(!c) {close(fd);continue;}
        memset(c,0,sizeof(*c)); c->fd=fd; c->target=ADMIN_HEADER;
    }
}
static void read_client(struct admin_connection *c)
{
    ssize_t n=recv(c->fd,c->input+c->have,c->target-c->have,0);
    if(n<=0) { if(!n || (errno!=EAGAIN && errno!=EINTR)) disconnect(c); return; }
    c->have+=(size_t)n;
    if(c->have==ADMIN_HEADER && c->target==ADMIN_HEADER) {
        if(admin_header_decode(c->input,&c->header) || c->header.length>ADMIN_REQUEST_MAX ||
            c->header.length<ADMIN_REQUEST_BASE || c->header.result || c->header.generation || c->header.id==c->last_id) {disconnect(c);return;}
        c->target+=c->header.length;
    }
    if(c->have==c->target) {
        c->last_id=c->header.id;
        int rc=admin_request_decode(c->input+ADMIN_HEADER,c->header.length,&c->request);
        if(rc) response(c,rc,0,0);
    }
}
static void write_client(struct admin_connection *c)
{
    ssize_t n=send(c->fd,c->output+c->sent,c->length-c->sent,MSG_NOSIGNAL);
    if(n<=0) {if(!n || (errno!=EAGAIN && errno!=EINTR)) disconnect(c);return;}
    c->sent+=(size_t)n;
    if(c->sent==c->length) c->sent=c->length=0;
}
static void schedule(struct admin_service *s)
{
    if(atomic_load_explicit(&s->state,memory_order_acquire)!=ADMIN_MAILBOX_CONTROL) return;
    for(unsigned n=1;n<=ADMIN_CLIENT_MAX;n++) {
        unsigned i=(s->cursor+n)%ADMIN_CLIENT_MAX;
        struct admin_connection *c=&s->clients[i];
        if(c->fd<0 || c->subscribed || c->pending || c->length || c->have!=c->target) continue;
        s->cursor=i; s->current=(int)i; s->phase=0;
        s->job.request=c->request; s->job.type=ADMIN_READ;
        if((c->request.group==ADM_LINK || c->request.group==ADM_NEIGH) && c->request.verb!=ADM_SHOW) s->job.type=ADMIN_HARDWARE;
        c->pending=1;
        atomic_store_explicit(&s->state,ADMIN_MAILBOX_WORKER,memory_order_release);
        return;
    }
    if(milliseconds()-s->last_scan<100) return;
    for(unsigned i=0;i<ADMIN_CLIENT_MAX;i++) if(s->clients[i].subscribed) {
        s->last_scan=milliseconds(); s->current=-1; s->phase=0;
        s->job.request=(struct admin_request){.group=ADM_MONITOR,.verb=ADM_SHOW}; s->job.type=ADMIN_READ;
        atomic_store_explicit(&s->state,ADMIN_MAILBOX_WORKER,memory_order_release); return;
    }
}
static void *run(void *arg)
{
    struct admin_service *s=arg;
    pthread_setaffinity_np(pthread_self(),sizeof(s->applications->control_cpus),&s->applications->control_cpus);
    while(!atomic_load_explicit(&s->stopping,memory_order_acquire) ||
          atomic_load_explicit(&s->state,memory_order_acquire)!=ADMIN_MAILBOX_CONTROL) {
        complete(s);
        if(atomic_load(&s->stopping)) { for(unsigned i=0;i<ADMIN_CLIENT_MAX;i++) disconnect(&s->clients[i]); continue; }
        schedule(s);
        struct pollfd fds[ADMIN_CLIENT_MAX+1]; fds[0]=(struct pollfd){s->listener,POLLIN,0};
        for(unsigned i=0;i<ADMIN_CLIENT_MAX;i++) {struct admin_connection *c=&s->clients[i];
            fds[i+1]=(struct pollfd){c->fd,c->length?POLLOUT:(!c->pending&&!c->subscribed&&c->have<c->target?POLLIN:0),0};}
        int rc=poll(fds,ADMIN_CLIENT_MAX+1,10);
        if(rc<0) {if(errno==EINTR) continue; atomic_store(&s->failed,1); atomic_store(&s->stopping,1); continue;}
        if(fds[0].revents&POLLIN) accept_clients(s);
        for(unsigned i=0;i<ADMIN_CLIENT_MAX;i++) {struct admin_connection *c=&s->clients[i]; short e=fds[i+1].revents;
            if(e&(POLLHUP|POLLERR|POLLNVAL)) disconnect(c);
            if(c->fd>=0 && (e&POLLOUT)) write_client(c);
            if(c->fd>=0 && (e&POLLIN)) read_client(c);
        }
    }
    for(unsigned i=0;i<ADMIN_CLIENT_MAX;i++) disconnect(&s->clients[i]);
    atomic_store_explicit(&s->done,1,memory_order_release);
    return NULL;
}
int admin_prepare(struct admin_service *s, const char *path, struct daemon_service *apps)
{
    memset(s,0,sizeof(*s)); s->listener=s->lock_fd=s->current=-1; s->applications=apps;
    atomic_init(&s->state,ADMIN_MAILBOX_CONTROL);atomic_init(&s->stopping,0);atomic_init(&s->done,0);atomic_init(&s->failed,0);
    for(unsigned i=0;i<ADMIN_CLIENT_MAX;i++) s->clients[i].fd=-1;
    if(!*path || strlen(path)>=sizeof(s->path)) return -EINVAL;
    strcpy(s->path,path);
    char lockpath[114]; snprintf(lockpath,sizeof(lockpath),"%s.lock",path);
    s->lock_fd=open(lockpath,O_CREAT|O_RDWR|O_CLOEXEC|O_NOFOLLOW,0600);
    if(s->lock_fd<0) return -errno;
    struct stat st;
    if(fstat(s->lock_fd,&st)) return -errno;
    if(!S_ISREG(st.st_mode)||st.st_uid!=geteuid()||st.st_nlink!=1) return -EACCES;
    if(flock(s->lock_fd,LOCK_EX|LOCK_NB)) return -errno;
    struct sockaddr_un a={.sun_family=AF_UNIX}; strcpy(a.sun_path,path);
    if(!lstat(path,&st)) {
        if(!S_ISSOCK(st.st_mode)||st.st_uid!=geteuid()) return -EEXIST;
        int probe=socket(AF_UNIX,SOCK_STREAM|SOCK_NONBLOCK|SOCK_CLOEXEC,0);
        if(probe<0) return -errno;
        int rc=connect(probe,(struct sockaddr *)&a,sizeof(a)), error=errno; close(probe);
        if(!rc || (error!=ECONNREFUSED && error!=ENOENT)) return -EADDRINUSE;
        if(unlink(path) && errno!=ENOENT) return -errno;
    } else if(errno!=ENOENT) return -errno;
    s->listener=socket(AF_UNIX,SOCK_STREAM|SOCK_NONBLOCK|SOCK_CLOEXEC,0);
    if(s->listener<0) return -errno;
    mode_t mask=umask(0077); int rc=bind(s->listener,(struct sockaddr *)&a,sizeof(a)), error=errno; umask(mask);
    if(rc) return -error;
    if(lstat(path,&st)) return -errno;
    s->device=st.st_dev; s->inode=st.st_ino;
    return listen(s->listener,ADMIN_CLIENT_MAX) ? -errno : 0;
}
int admin_start(struct admin_service *s) {int rc=pthread_create(&s->thread,NULL,run,s); return rc?-rc:0;}
void admin_release(struct admin_service *s)
{
    if(s->listener>=0) close(s->listener);
    struct stat st;
    if(s->inode && !lstat(s->path,&st) && st.st_dev==s->device && st.st_ino==s->inode) unlink(s->path);
    if(s->lock_fd>=0) close(s->lock_fd);
}
