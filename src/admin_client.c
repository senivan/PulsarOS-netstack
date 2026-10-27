#define _POSIX_C_SOURCE 200809L
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <time.h>
#include <unistd.h>
#include "admin.h"

static int64_t now(void) { struct timespec t; clock_gettime(CLOCK_MONOTONIC,&t);return (int64_t)t.tv_sec*1000+t.tv_nsec/1000000; }
static int ready(int fd, short events, int64_t deadline)
{
    for(;;) {
        int64_t remaining=deadline-now(); if(remaining<=0) return -ETIMEDOUT;
        struct pollfd p={.fd=fd,.events=events};
        int n=poll(&p,1,(int)remaining);
        if(n<0) {if(errno==EINTR) continue;return -errno;}
        if(!n) return -ETIMEDOUT;
        if(p.revents&events) return 0;
        if(p.revents&(POLLERR|POLLHUP|POLLNVAL)) return -ECONNRESET;
    }
}
static int transfer(int fd, void *data, size_t length, int write, int64_t deadline)
{
    size_t done=0;
    while(done<length) {
        int rc=ready(fd,write?POLLOUT:POLLIN,deadline); if(rc) return rc;
        ssize_t n=write ? send(fd,(char *)data+done,length-done,MSG_NOSIGNAL) : recv(fd,(char *)data+done,length-done,0);
        if(n<0) {if(errno==EINTR||errno==EAGAIN) continue;return -errno;}
        if(!n) return -ECONNRESET;
        done+=(size_t)n;
    }
    return 0;
}
int admin_open(const char *path)
{
    struct sockaddr_un a={.sun_family=AF_UNIX};
    if(!*path || strlen(path)>=sizeof(a.sun_path)) return -EINVAL;
    strcpy(a.sun_path,path);
    int fd=socket(AF_UNIX,SOCK_STREAM,0); if(fd<0) return -errno;
    if(fcntl(fd,F_SETFL,O_NONBLOCK)<0 || fcntl(fd,F_SETFD,FD_CLOEXEC)<0) {int error=errno;close(fd);return -error;}
    int rc=connect(fd,(struct sockaddr *)&a,sizeof(a));
    if(rc && errno!=EINPROGRESS) {rc=-errno;close(fd);return rc;}
    if(rc) {
        rc=ready(fd,POLLOUT,now()+5000);
        if(!rc) {int error; socklen_t size=sizeof(error);if(getsockopt(fd,SOL_SOCKET,SO_ERROR,&error,&size)) rc=-errno;else rc=-error;}
        if(rc) {close(fd);return rc;}
    }
    return fd;
}
int admin_receive(int fd, uint32_t id, char *text, size_t size, uint64_t *generation)
{
    uint8_t wire[ADMIN_HEADER]; struct admin_header h;
    int64_t deadline=now()+5000;
    int rc=transfer(fd,wire,sizeof(wire),0,deadline);
    if(!rc) rc=admin_header_decode(wire,&h);
    if(rc) return rc;
    if(h.id!=id || h.length>=size || h.result>0) return -EPROTO;
    rc=transfer(fd,text,h.length,0,deadline); if(rc) return rc;
    text[h.length]=0; if(generation) *generation=h.generation;
    return h.result ? h.result : (int)h.length;
}
int admin_call(int fd, const struct admin_request *r, char *text, size_t size, uint64_t *generation)
{
    uint8_t wire[ADMIN_HEADER+ADMIN_REQUEST_MAX];
    size_t length=admin_request_encode(wire+ADMIN_HEADER,r); if(!length) return -EINVAL;
    struct admin_header h={.id=1,.length=(uint32_t)length}; admin_header_encode(wire,&h);
    int rc=transfer(fd,wire,ADMIN_HEADER+length,1,now()+5000);
    return rc ? rc : admin_receive(fd,1,text,size,generation);
}
int admin_exchange(const char *path, const struct admin_request *r, char *text, size_t size, uint64_t *generation)
{
    int fd=admin_open(path); if(fd<0) return fd;
    int rc=admin_call(fd,r,text,size,generation);close(fd);return rc;
}
