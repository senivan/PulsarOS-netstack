#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <inttypes.h>
#include <netinet/tcp.h>
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <unistd.h>
#include "wire.h"
#include "latency.h"

static void stop(int sig)
{
    (void)sig;
    bench_stop = 1;
}
static int connect_socket(const struct sockaddr_in *a, int tcp, struct latency *handshake)
{
    int fd = socket(AF_INET, (tcp ? SOCK_STREAM : SOCK_DGRAM) | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
    if (fd < 0)
        return -1;
    int one = 1;
    if (tcp)
        setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));
    uint64_t start = clock_ns();
    int rc = connect(fd, (const struct sockaddr *)a, sizeof(*a));
    if (rc && errno == EINPROGRESS) {
        struct pollfd p = {fd, POLLOUT, 0};
        rc = poll(&p, 1, 1500);
        int error = 0;
        socklen_t n = sizeof(error);
        if (rc <= 0 || getsockopt(fd, SOL_SOCKET, SO_ERROR, &error, &n) || error) {
            close(fd);
            return -1;
        }
        rc = 0;
    }
    if (rc) {
        close(fd);
        return -1;
    }
    if (tcp)
        latency_add(handshake, clock_ns() - start);
    return fd;
}
static int exchange(int fd, int tcp, uint8_t *out, uint8_t *in, size_t length, uint64_t deadline,
                    uint64_t *submitted)
{
    size_t sent = 0, received = 0;
    while ((sent < length || received < length) && clock_ns() < deadline && !bench_stop) {
        struct pollfd p = {fd, (short)(POLLIN | (sent < length ? POLLOUT : 0)), 0};
        poll(&p, 1, 10);
        if (sent < length && (p.revents & POLLOUT)) {
            ssize_t n = send(fd, out + sent, length - sent, MSG_NOSIGNAL);
            if (n > 0) {
                sent += (size_t)n;
                *submitted += (uint64_t)n;
            } else if (n < 0 && errno != EAGAIN && errno != EINTR)
                return -1;
        }
        if (p.revents & POLLIN) {
            ssize_t n = recv(fd, in + received, length - received, 0);
            if (n <= 0) {
                if (n < 0 && (errno == EAGAIN || errno == EINTR))
                    continue;
                return -1;
            }
            received += (size_t)n;
            if (!tcp && received != length)
                return -2;
        }
    }
    if (received != length)
        return -1;
    return memcmp(out, in, length) ? -2 : 0;
}
static void graceful(int fd)
{
    shutdown(fd, SHUT_WR);
    uint8_t data[8192];
    uint64_t end = clock_ns() + 2000000000u;
    while (clock_ns() < end) {
        struct pollfd p = {fd, POLLIN, 0};
        poll(&p, 1, 10);
        ssize_t n = recv(fd, data, sizeof(data), 0);
        if (!n)
            break;
        if (n < 0 && errno != EAGAIN && errno != EINTR)
            break;
    }
    close(fd);
}
int main(int argc, char **argv)
{
    const char *address = NULL, *output = NULL, *mode = "rr";
    int tcp = 0, port = 9000, connections = 1, bytes = 64;
    uint32_t run = 1;
    double duration = 10;
    static const struct option opts[] = {{"address", 1, 0, 'a'},     {"output", 1, 0, 'o'},
                                         {"kind", 1, 0, 'k'},        {"mode", 1, 0, 'm'},
                                         {"port", 1, 0, 'p'},        {"duration", 1, 0, 'd'},
                                         {"connections", 1, 0, 'c'}, {"bytes", 1, 0, 'b'},
                                         {"run", 1, 0, 'r'},         {0, 0, 0, 0}};
    int c;
    while ((c = getopt_long(argc, argv, "", opts, NULL)) != -1) {
        switch (c) {
        case 'a':
            address = optarg;
            break;
        case 'o':
            output = optarg;
            break;
        case 'k':
            if (strcmp(optarg, "udp") && strcmp(optarg, "tcp"))
                return 2;
            tcp = !strcmp(optarg, "tcp");
            break;
        case 'm':
            mode = optarg;
            break;
        case 'p':
            port = atoi(optarg);
            break;
        case 'd':
            duration = atof(optarg);
            break;
        case 'c':
            connections = atoi(optarg);
            break;
        case 'b':
            bytes = atoi(optarg);
            break;
        case 'r':
            run = (uint32_t)strtoul(optarg, NULL, 10);
            break;
        default:
            return 2;
        }
    }
    if (optind != argc || !address || !output || connections < 1 || connections > 32 ||
        bytes < 16 || bytes > 65536 || duration <= 0 || duration > 3600 || port < 1 ||
        port > 65535 || (!tcp && bytes > 1472) ||
        (strcmp(mode, "rr") && strcmp(mode, "bulk") && strcmp(mode, "connect") &&
         strcmp(mode, "short")) ||
        (!tcp && strcmp(mode, "rr")))
        return 2;
    signal(SIGTERM, stop);
    signal(SIGINT, stop);
    struct sockaddr_in target = {.sin_family = AF_INET, .sin_port = htons((uint16_t)port)};
    if (inet_pton(AF_INET, address, &target.sin_addr) != 1)
        return 2;
    uint8_t *sent = malloc((size_t)bytes), *received = malloc((size_t)bytes);
    if (!sent || !received)
        return 1;
    struct latency latency = {0}, handshake = {0};
    uint64_t packets = 0, delivered = 0, submitted = 0, failures = 0, invalid = 0,
             start = clock_ns(), end = start + (uint64_t)(duration * 1e9), last = start;
    struct rusage before, after;
    getrusage(RUSAGE_SELF, &before);
    if (!strcmp(mode, "connect") || !strcmp(mode, "short")) {
        while (clock_ns() < end && !bench_stop) {
            int fd = connect_socket(&target, tcp, &handshake);
            if (fd < 0) {
                failures++;
                continue;
            }
            if (!strcmp(mode, "short")) {
                payload_fill(sent, (size_t)bytes, run, packets, 42);
                uint64_t began = clock_ns();
                int status = exchange(fd, 1, sent, received, (size_t)bytes,
                                      clock_ns() + 2000000000u, &submitted);
                if (status) {
                    if (status == -2)
                        invalid++;
                    failures++;
                } else {
                    latency_add(&latency, clock_ns() - began);
                    delivered += (uint64_t)bytes;
                    packets++;
                }
            } else
                packets++;
            graceful(fd);
            last = clock_ns();
        }
    } else if (!strcmp(mode, "rr")) {
        int fd = connect_socket(&target, tcp, &handshake);
        if (fd < 0) {
            failures++;
            goto done;
        }
        while (clock_ns() < end && !bench_stop) {
            payload_fill(sent, (size_t)bytes, run, packets + failures, 42);
            uint64_t began = clock_ns();
            int status = exchange(fd, tcp, sent, received, (size_t)bytes, clock_ns() + 500000000u,
                                  &submitted);
            if (status) {
                if (status == -2)
                    invalid++;
                failures++;
                if (tcp)
                    break;
            } else {
                latency_add(&latency, clock_ns() - began);
                delivered += (uint64_t)bytes;
                packets++;
            }
            last = clock_ns();
        }
        if (tcp)
            graceful(fd);
        else
            close(fd);
    } else {
        struct connection {
            int fd;
            uint64_t sent, received;
        } peers[32];
        struct pollfd fds[32];
        for (int i = 0; i < connections; i++) {
            peers[i] = (struct connection){.fd = connect_socket(&target, 1, &handshake)};
            if (peers[i].fd < 0) {
                failures++;
                connections = i;
                break;
            }
        }
        while (clock_ns() < end && !bench_stop) {
            for (int i = 0; i < connections; i++)
                fds[i] = (struct pollfd){
                    peers[i].fd,
                    (short)(POLLIN | (peers[i].sent - peers[i].received < 8192 ? POLLOUT : 0)), 0};
            poll(fds, (nfds_t)connections, 10);
            for (int i = 0; i < connections; i++) {
                struct connection *p = &peers[i];
                if (fds[i].revents & POLLOUT) {
                    size_t n = (size_t)(8192 - (p->sent - p->received));
                    if (n > (size_t)bytes)
                        n = (size_t)bytes;
                    for (size_t j = 0; j < n; j++)
                        sent[j] = (uint8_t)((p->sent + j) * 17 + 42);
                    ssize_t wrote = send(p->fd, sent, n, MSG_NOSIGNAL);
                    if (wrote > 0) {
                        p->sent += (uint64_t)wrote;
                        submitted += (uint64_t)wrote;
                    } else if (wrote < 0 && errno != EAGAIN) {
                        failures++;
                        end = 0;
                    }
                }
                if (fds[i].revents & POLLIN) {
                    ssize_t n = recv(p->fd, received, (size_t)bytes, 0);
                    if (n > 0) {
                        for (ssize_t j = 0; j < n; j++)
                            if (received[j] != (uint8_t)((p->received + (uint64_t)j) * 17 + 42))
                                invalid++;
                        p->received += (uint64_t)n;
                        delivered += (uint64_t)n;
                        packets++;
                        last = clock_ns();
                    } else if (!n || (n < 0 && errno != EAGAIN)) {
                        failures++;
                        end = 0;
                    }
                }
            }
        }
        for (int i = 0; i < connections; i++)
            graceful(peers[i].fd);
    }
done:
    getrusage(RUSAGE_SELF, &after);
    uint64_t finish = clock_ns(), measurement_end = last > end ? last : end;
    if (measurement_end < start)
        measurement_end = finish;
    FILE *f = fopen(output, "w");
    if (!f)
        return 1;
    fprintf(f,
            "{\"schema\":1,\"requests\":%" PRIu64 ",\"delivered_bytes\":%" PRIu64
            ",\"submitted_bytes\":%" PRIu64 ",\"failures\":%" PRIu64 ",\"invalid\":%" PRIu64
            ",\"start_ns\":%" PRIu64 ",\"end_ns\":%" PRIu64 ",\"process_end_ns\":%" PRIu64
            ",\"handshakes\":%" PRIu64 ",\"user_seconds\":%.9f,\"system_seconds\":%.9f,",
            packets, delivered, submitted, failures, invalid, start, measurement_end, finish,
            handshake.total,
            (after.ru_utime.tv_sec - before.ru_utime.tv_sec) +
                (after.ru_utime.tv_usec - before.ru_utime.tv_usec) / 1e6,
            (after.ru_stime.tv_sec - before.ru_stime.tv_sec) +
                (after.ru_stime.tv_usec - before.ru_stime.tv_usec) / 1e6);
    latency_write(f, &latency);
    fputs(",\"handshake\":{", f);
    latency_write(f, &handshake);
    fputs("}}\n", f);
    fclose(f);
    free(sent);
    free(received);
    free(latency.values);
    free(handshake.values);
    return invalid ? 1 : 0;
}
