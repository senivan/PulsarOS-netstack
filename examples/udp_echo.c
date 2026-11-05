#define _POSIX_C_SOURCE 200809L
#include "client_common.h"

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
    ps_fd_t fd = ps_socket(PS_AF_INET, PS_SOCK_DGRAM, 0);
    if (fd < 0) { ps_fini(); return client_error("socket", fd); }
    error = ps_bind(fd, &(struct ps_sockaddr){ .port = port });
    if (error) { ps_fini(); return client_error("bind", error); }
    printf("udp_echo: bound UDP port %u\n", port);
    fflush(stdout);
    int rc = 0;
    while (!client_stopping) {
        uint8_t payload[PS_DGRAM_BATCH_MAX][PS_DGRAM_MAX_PAYLOAD];
        struct ps_mmsg messages[PS_DGRAM_BATCH_MAX];
        for (unsigned i = 0; i < PS_DGRAM_BATCH_MAX; i++)
            messages[i] = (struct ps_mmsg){ .data = payload[i], .len = sizeof(payload[i]) };
        int received = ps_recvmmsg(fd, messages, PS_DGRAM_BATCH_MAX);
        if (received == -EAGAIN) { client_wait(); continue; }
        if (received < 0) { rc = client_error("receive", received); break; }
        unsigned sent = 0;
        while (sent < (unsigned)received && !client_stopping) {
            int n = ps_sendmmsg(fd, messages + sent, (unsigned)received - sent);
            if (n == -EAGAIN) { client_wait(); continue; }
            if (n < 0) { rc = client_error("send", n); break; }
            sent += (unsigned)n;
        }
        if (rc) break;
    }
    ps_close(fd);
    ps_fini();
    return rc;
}
