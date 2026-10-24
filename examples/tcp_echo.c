#define _POSIX_C_SOURCE 200809L
#include "client_common.h"

#define ECHO_CONNECTIONS 64
static struct { ps_fd_t fd; size_t length, offset; uint8_t data[2048]; } clients[ECHO_CONNECTIONS];

int main(int argc, char **argv)
{
    const char *path;
    uint16_t port;
    if (client_options(argc, argv, &path, &port)) {
        fprintf(stderr, "usage: %s [--socket PATH] [--port PORT]\n", argv[0]);
        return 2;
    }
    int error = ps_init(path);
    if (error) return client_error("daemon connection", error);
    ps_fd_t listener = ps_socket(PS_AF_INET, PS_SOCK_STREAM, 0);
    if (listener < 0) { ps_fini(); return client_error("socket", listener); }
    error = ps_bind(listener, &(struct ps_sockaddr){ .port = port });
    if (!error) error = ps_listen(listener, 8);
    if (error) { ps_fini(); return client_error("bind/listen", error); }
    printf("tcp_echo: listening on TCP port %u\n", port);
    fflush(stdout);
    int rc = 0;
    while (!client_stopping && !rc) {
        int progress = 0;
        for (unsigned i = 0; i < ECHO_CONNECTIONS; i++) {
            if (clients[i].fd) continue;
            ps_fd_t fd = ps_accept(listener, NULL);
            if (fd == -EAGAIN) break;
            if (fd < 0) { rc = client_error("accept", fd); break; }
            clients[i].fd = fd;
            clients[i].length = clients[i].offset = 0;
            progress = 1;
        }
        for (unsigned i = 0; i < ECHO_CONNECTIONS && !rc; i++) {
            ps_fd_t fd = clients[i].fd;
            if (!fd) continue;
            if (clients[i].offset == clients[i].length) {
                ssize_t n = ps_recv(fd, clients[i].data, sizeof(clients[i].data));
                if (n == -EAGAIN) continue;
                if (n <= 0) {
                    int closed = ps_close(fd);
                    if (closed < 0) rc = client_error("close", closed);
                    clients[i].fd = 0;
                    progress = 1;
                    continue;
                }
                clients[i].length = (size_t)n;
                clients[i].offset = 0;
            }
            ssize_t n = ps_send(fd, clients[i].data + clients[i].offset, clients[i].length - clients[i].offset);
            if (n == -EAGAIN) continue;
            if (n < 0) {
                int closed = ps_close(fd);
                if (closed < 0) rc = client_error("close", closed);
                clients[i].fd = 0;
                progress = 1;
                continue;
            }
            clients[i].offset += (size_t)n;
            progress = 1;
        }
        if (!progress) client_wait();
    }
    for (unsigned i = 0; i < ECHO_CONNECTIONS; i++) if (clients[i].fd) ps_close(clients[i].fd);
    ps_close(listener);
    ps_fini();
    return rc;
}
