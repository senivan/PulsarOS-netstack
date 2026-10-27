#include <errno.h>
#include <poll.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include "admin.h"

int main(int argc, char **argv)
{
    const char *path=ADMIN_DEFAULT_SOCKET;
    uint32_t flags=0;
    int i=1;
    for(;i<argc && argv[i][0]=='-';i++) {
        if(!strcmp(argv[i],"-4")) continue;
        if(!strcmp(argv[i],"-6")) {fprintf(stderr,"pulsar: IPv6: %s\n",strerror(EAFNOSUPPORT));return 2;}
        if(!strcmp(argv[i],"-j")) flags|=ADMIN_JSON;
        else if(!strcmp(argv[i],"-br")) flags|=ADMIN_BRIEF;
        else if(!strcmp(argv[i],"-s")) flags|=ADMIN_STATS;
        else if(!strcmp(argv[i],"--socket") && i+1<argc) path=argv[++i];
        else if(!strcmp(argv[i],"--help")) {admin_usage();return 0;}
        else {fprintf(stderr,"pulsar: unsupported option %s\n",argv[i]);return 2;}
    }
    if(i==argc || (i+1==argc && !strcmp(argv[i],"help"))) {admin_usage();return 0;}
    if(i+1==argc && !strcmp(argv[i],"version")) {puts("pulsar 1 (management protocol 1)");return 0;}
    struct admin_request request;
    char error[256], text[ADMIN_RESPONSE_MAX+1];
    int rc=admin_parse(argc-i,argv+i,&request,error,sizeof(error));
    if(rc) {fprintf(stderr,"pulsar: %s\n",error);return 2;}
    request.flags|=flags;
    int fd=admin_open(path);
    if(fd<0) {fprintf(stderr,"pulsar: %s: %s\n",path,strerror(-fd));return 1;}
    rc=admin_call(fd,&request,text,sizeof(text),NULL);
    if(rc>=0 && request.group!=ADM_MONITOR) fputs(text,stdout);
    while(rc>=0 && request.group==ADM_MONITOR) {
        struct pollfd p={.fd=fd,.events=POLLIN};
        int n=poll(&p,1,-1);
        if(n<0) {if(errno==EINTR) continue;rc=-errno;break;}
        if(p.revents&POLLIN) {rc=admin_receive(fd,1,text,sizeof(text),NULL);if(rc>=0) {fputs(text,stdout);fflush(stdout);}}
        else if(p.revents&(POLLERR|POLLHUP|POLLNVAL)) {rc=-ECONNRESET;break;}
    }
    close(fd);
    if(rc<0) {fprintf(stderr,"pulsar: %s\n",strerror(-rc));return 1;}
    return 0;
}
