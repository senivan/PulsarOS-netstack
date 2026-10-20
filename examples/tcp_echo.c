#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include "config.h"
#include "runtime.h"
#include "ps_socket.h"

static struct app_runtime rt;
static struct {
    ps_fd_t fd;
    size_t length, offset;
    uint8_t data[2048];
} clients[PS_SOCKET_MAX];

static void request_stop(int signo)
{
    (void)signo;
    rt.stop = 1;
}

int main(int argc, char **argv)
{
    if (argc != 2) { fprintf(stderr, "usage: %s <config.conf>\n", argv[0]); return 2; }
    struct app_config conf;
    char error[256];
    if (app_config_load(argv[1], &conf, error, sizeof(error))) { fprintf(stderr, "%s\n", error); return 1; }
    if (app_init(argv[0], &conf, &rt)) return 1;
    ps_fd_t listener = ps_socket(PS_AF_INET, PS_SOCK_STREAM, 0);
    if (listener < 0 || ps_bind(listener, &(struct ps_sockaddr){ .port = 9000 }) || ps_listen(listener, 8)) {
        app_fini(&rt);
        return 1;
    }
    signal(SIGINT, request_stop);
    signal(SIGTERM, request_stop);
    puts("tcp_echo: listening on TCP port 9000; entering host input loop");
    fflush(stdout);
    while (!rt.stop) {
        app_step(&rt);
        for (unsigned i = 0; i < PS_SOCKET_MAX; i++) {
            if (clients[i].fd) continue;
            ps_fd_t fd = ps_accept(listener, NULL);
            if (fd < 0) break;
            clients[i].fd = fd;
            clients[i].length = clients[i].offset = 0;
        }
        for (unsigned i = 0; i < PS_SOCKET_MAX; i++) {
            ps_fd_t fd = clients[i].fd;
            if (!fd) continue;
            if (clients[i].offset == clients[i].length) {
                ssize_t n = ps_recv(fd, clients[i].data, sizeof(clients[i].data));
                if (n == -EAGAIN) continue;
                if (n <= 0) { ps_close(fd); clients[i].fd = 0; continue; }
                clients[i].length = (size_t)n;
                clients[i].offset = 0;
            }
            ssize_t n = ps_send(fd, clients[i].data + clients[i].offset,
                                 clients[i].length - clients[i].offset);
            if (n == -EAGAIN) continue;
            if (n < 0) { ps_close(fd); clients[i].fd = 0; continue; }
            clients[i].offset += (size_t)n;
        }
    }
    for (unsigned i = 0; i < PS_SOCKET_MAX; i++) if (clients[i].fd) ps_close(clients[i].fd);
    ps_close(listener);
    app_dump_stats(&rt);
    app_fini(&rt);
    return 0;
}
