#define _POSIX_C_SOURCE 200809L
#include <arpa/inet.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include "ps_socket.h"

int main(int argc, char **argv)
{
    if (argc != 3) return 2;
    struct ps_sockaddr dst = { .port = 9001 };
    if (inet_pton(AF_INET, argv[2], &dst.ip_be) != 1) return 2;
    if (ps_init(argv[1])) return 1;
    const char payload[] = "active-arp";
    int rc = 1;
    ps_fd_t udp_fd = ps_socket(PS_AF_INET, PS_SOCK_DGRAM, 0);
    if (udp_fd < 0 || ps_bind(udp_fd, &(struct ps_sockaddr){ .port = 9000 }) ||
        ps_sendto(udp_fd, payload, sizeof(payload) - 1, &dst) != sizeof(payload) - 1) goto done;
    struct timespec start, now, delay = { .tv_nsec = 1000000 };
    clock_gettime(CLOCK_MONOTONIC, &start);
    while (1) {
        nanosleep(&delay, NULL);
        clock_gettime(CLOCK_MONOTONIC, &now);
        if (now.tv_sec - start.tv_sec >= 5) break;
        char response[32];
        struct ps_sockaddr peer;
        ssize_t n = ps_recvfrom(udp_fd, response, sizeof(response), &peer);
        if (n == -EAGAIN) continue;
        if (n == sizeof(payload) - 1 && !memcmp(payload, response, (size_t)n) &&
            peer.ip_be == dst.ip_be && peer.port == dst.port) rc = 0;
        break;
    }
done:
    ps_close(udp_fd);
    ps_fini();
    return rc;
}
