#define _POSIX_C_SOURCE 200809L
#include <arpa/inet.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "ps_socket.h"

int main(int argc, char **argv)
{
    if (argc != 3 && argc != 4) return 2;
    size_t target = 5000;
    if (argc == 4) {
        char *end;
        unsigned long value = strtoul(argv[3], &end, 10);
        if (!*argv[3] || *end || !value || value > 100 * 1024 * 1024) return 2;
        target = value;
    }
    struct ps_sockaddr peer = { .port = 9001 };
    if (inet_pton(AF_INET, argv[2], &peer.ip_be) != 1) return 2;
    if (ps_init(argv[1])) return 1;
    ps_fd_t fd = ps_socket(PS_AF_INET, PS_SOCK_STREAM, 0);
    int rc = 1;
    if (fd < 0 || ps_connect(fd, &peer) != -EINPROGRESS) goto done;
    uint8_t payload[65536], received[65536];
    for (unsigned i = 0; i < sizeof(payload); i++) payload[i] = (uint8_t)i;
    size_t sent = 0, read = 0;
    struct timespec start, now, delay = { .tv_nsec = 1000000 };
    clock_gettime(CLOCK_MONOTONIC, &start);
    while (1) {
        nanosleep(&delay, NULL);
        clock_gettime(CLOCK_MONOTONIC, &now);
        if (now.tv_sec - start.tv_sec >= (target > 5000 ? 180 : 15)) break;
        if (sent < target) {
            size_t offset = sent % sizeof(payload);
            size_t length = sizeof(payload) - offset;
            if (length > target - sent) length = target - sent;
            ssize_t n = ps_send(fd, payload + offset, length);
            if (n >= 0) sent += (size_t)n;
            else if (n != -EAGAIN && n != -ENOTCONN) goto done;
        }
        ssize_t n = ps_recv(fd, received, sizeof(received));
        if (n > 0) {
            if ((size_t)n > target - read) goto done;
            for (ssize_t i = 0; i < n; i++)
                if (received[i] != (uint8_t)(read + (size_t)i)) goto done;
            read += (size_t)n;
        }
        else if (n != -EAGAIN && n != -ENOTCONN) goto done;
        if (read != target) continue;
        ps_close(fd);
        fd = -1;
        rc = 0;
        break;
    }
done:
    if (fd >= 0) ps_close(fd);
    ps_fini();
    return rc;
}
