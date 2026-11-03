#define _POSIX_C_SOURCE 200809L
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <inttypes.h>
#include <netinet/tcp.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>
#include "wire.h"
#ifdef PULSAROS_CLIENT
#include "ps_socket.h"
typedef struct ps_sockaddr endpoint;
static int start(const char *path) { return ps_init(path); }
static int open_socket(int tcp)
{
    return ps_socket(PS_AF_INET, tcp ? PS_SOCK_STREAM : PS_SOCK_DGRAM, 0);
}
static int bind_socket(int fd, int port)
{
    return ps_bind(fd, &(endpoint){.port = (uint16_t)port});
}
#define close_socket ps_close
#define receive ps_recv
#define transmit ps_send
#define receive_from ps_recvfrom
#define transmit_to ps_sendto
#define listen_socket ps_listen
#define accept_socket ps_accept
#define finish ps_fini
#else
typedef struct sockaddr_in endpoint;
static int start(const char *path)
{
    (void)path;
    return 0;
}
static int open_socket(int tcp)
{
    int fd = socket(AF_INET, tcp ? SOCK_STREAM : SOCK_DGRAM, 0);
    if (fd < 0)
        return -errno;
    fcntl(fd, F_SETFL, O_NONBLOCK);
    if (tcp) {
        int one = 1;
        setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));
    }
    return fd;
}
static int bind_socket(int fd, int port)
{
    endpoint a = {.sin_family = AF_INET, .sin_port = htons((uint16_t)port)};
    int one = 1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
    return bind(fd, (struct sockaddr *)&a, sizeof(a)) ? -errno : 0;
}
static int close_socket(int fd) { return close(fd); }
static ssize_t receive(int fd, void *b, size_t n)
{
    ssize_t r = recv(fd, b, n, 0);
    return r < 0 ? -errno : r;
}
static ssize_t transmit(int fd, const void *b, size_t n)
{
    ssize_t r = send(fd, b, n, MSG_NOSIGNAL);
    return r < 0 ? -errno : r;
}
static ssize_t receive_from(int fd, void *b, size_t n, endpoint *a)
{
    socklen_t z = sizeof(*a);
    ssize_t r = recvfrom(fd, b, n, 0, (struct sockaddr *)a, &z);
    return r < 0 ? -errno : r;
}
static ssize_t transmit_to(int fd, const void *b, size_t n, endpoint *a)
{
    ssize_t r = sendto(fd, b, n, MSG_NOSIGNAL, (struct sockaddr *)a, sizeof(*a));
    return r < 0 ? -errno : r;
}
static int listen_socket(int fd, int backlog) { return listen(fd, backlog) ? -errno : 0; }
static int accept_socket(int fd, endpoint *a)
{
    socklen_t n = sizeof(*a);
    int r = accept(fd, (struct sockaddr *)a, &n);
    if (r < 0)
        return -errno;
    fcntl(r, F_SETFL, O_NONBLOCK);
    int one = 1;
    setsockopt(r, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));
    return r;
}
static void finish(void) {}
#endif
static volatile sig_atomic_t stopping, snapshot;
static void handler(int sig)
{
    if (sig == SIGUSR1)
        snapshot = 1;
    else
        stopping = 1;
}
static struct {
    int fd;
    size_t have, sent;
    uint8_t data[8192];
} clients[64];
static uint64_t packets, bytes, invalid, calls, accepted, unique, duplicates;
static uint64_t run_packets, run_unique, run_bytes, run_first, run_last;
static uint32_t seen_run;
static void save(const char *path)
{
    char tmp[600];
    snprintf(tmp, sizeof(tmp), "%s.tmp", path);
    FILE *f = fopen(tmp, "w");
    if (!f) {
        perror("server metrics");
        exit(1);
    }
    fprintf(f,
            "{\"schema\":1,\"packets\":%" PRIu64 ",\"bytes\":%" PRIu64 ",\"invalid\":%" PRIu64
            ",\"unique\":%" PRIu64 ",\"duplicates\":%" PRIu64 ",\"calls\":%" PRIu64
            ",\"accepted\":%" PRIu64 ",\"current_run\":%u,\"run_packets\":%" PRIu64
            ",\"run_unique\":%" PRIu64 ",\"run_bytes\":%" PRIu64 ",\"run_first_ns\":%" PRIu64
            ",\"run_last_ns\":%" PRIu64 ",\"time_ns\":%" PRIu64 "}\n",
            packets, bytes, invalid, unique, duplicates, calls, accepted, seen_run, run_packets,
            run_unique, run_bytes, run_first, run_last, clock_ns());
    if (fclose(f) || rename(tmp, path)) {
        perror("server metrics commit");
        exit(1);
    }
}
int main(int argc, char **argv)
{
    const char *path = NULL, *output = NULL;
    int tcp = 0, sink = 0, port = 9000;
    static const struct option opts[] = {{"socket", 1, 0, 's'}, {"output", 1, 0, 'o'},
                                         {"kind", 1, 0, 'k'},   {"mode", 1, 0, 'm'},
                                         {"port", 1, 0, 'p'},   {0, 0, 0, 0}};
    int c;
    while ((c = getopt_long(argc, argv, "", opts, NULL)) != -1) {
        switch (c) {
        case 's':
            path = optarg;
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
            if (strcmp(optarg, "echo") && strcmp(optarg, "sink"))
                return 2;
            sink = !strcmp(optarg, "sink");
            break;
        case 'p': {
            uint64_t number = 0;
            if (unsigned_parse(optarg, 65535, &number))
                return 2;
            port = (int)number;
        } break;
        default:
            return 2;
        }
    }
    if (optind != argc || !output || port < 1 || port > 65535)
        return 2;
    struct sigaction action = {.sa_handler = handler, .sa_flags = SA_RESTART};
    sigemptyset(&action.sa_mask);
    sigaction(SIGINT, &action, NULL);
    sigaction(SIGTERM, &action, NULL);
    sigaction(SIGUSR1, &action, NULL);
    if (start(path)) {
        fprintf(stderr, "server init failed\n");
        return 1;
    }
    int fd = open_socket(tcp);
    if (fd < 0 || bind_socket(fd, port) || (tcp && listen_socket(fd, 32))) {
        fprintf(stderr, "server bind/listen failed\n");
        return 1;
    }
    for (unsigned i = 0; i < 64; i++)
        clients[i].fd = -1;
    save(output);
    puts("READY");
    fflush(stdout);
    uint8_t *seen = calloc(8000000, 1);
    if (!seen)
        return 1;
    while (!stopping) {
        int progress = 0;
        if (!tcp) {
            uint8_t data[1472];
            endpoint peer;
            calls++;
            ssize_t n = receive_from(fd, data, sizeof(data), &peer);
            if (n >= 0) {
                progress = 1;
                packets++;
                bytes += (uint64_t)n;
                uint64_t seq = 0;
                if (n < 16 || !payload_valid(data, (size_t)n, read32(data + 4), 42, &seq) ||
                    seq >= 64000000)
                    invalid++;
                else {
                    uint32_t current = read32(data + 4);
                    if (current != seen_run) {
                        memset(seen, 0, 8000000);
                        seen_run = current;
                        run_packets = run_unique = run_bytes = run_first = run_last = 0;
                    }
                    run_packets++;
                    run_last = clock_ns();
                    if (!run_first)
                        run_first = run_last;
                    if (seen[seq / 8] & (1u << (seq % 8)))
                        duplicates++;
                    else {
                        seen[seq / 8] |= (uint8_t)(1u << (seq % 8));
                        unique++;
                        run_unique++;
                        run_bytes += (uint64_t)n;
                    }
                }
                if (!sink) {
                    calls++;
                    ssize_t sent = transmit_to(fd, data, (size_t)n, &peer);
                    if (sent != n && sent != -EAGAIN)
                        invalid++;
                }
            } else if (n != -EAGAIN) {
                fprintf(stderr, "server recv: %zd\n", n);
                break;
            }
        } else {
            for (unsigned i = 0; i < 64; i++)
                if (clients[i].fd < 0) {
                    endpoint peer;
                    calls++;
                    int child = accept_socket(fd, &peer);
                    if (child >= 0) {
                        clients[i].fd = child;
                        accepted++;
                        progress = 1;
                    } else if (child != -EAGAIN) {
                        fprintf(stderr, "accept: %d\n", child);
                        stopping = 1;
                    }
                    break;
                }
            for (unsigned i = 0; i < 64; i++) {
                if (clients[i].fd < 0)
                    continue;
                if (clients[i].have) {
                    calls++;
                    ssize_t n = transmit(clients[i].fd, clients[i].data + clients[i].sent,
                                         clients[i].have - clients[i].sent);
                    if (n > 0) {
                        clients[i].sent += (size_t)n;
                        progress = 1;
                        if (clients[i].sent == clients[i].have)
                            clients[i].have = clients[i].sent = 0;
                    } else if (n != -EAGAIN) {
                        close_socket(clients[i].fd);
                        clients[i].fd = -1;
                        clients[i].have = clients[i].sent = 0;
                    }
                    continue;
                }
                calls++;
                ssize_t n = receive(clients[i].fd, clients[i].data, sizeof(clients[i].data));
                if (n > 0) {
                    packets++;
                    bytes += (uint64_t)n;
                    progress = 1;
                    if (!sink)
                        clients[i].have = (size_t)n;
                } else if (n != -EAGAIN) {
                    close_socket(clients[i].fd);
                    clients[i].fd = -1;
                    clients[i].have = clients[i].sent = 0;
                }
            }
        }
        if (snapshot) {
            snapshot = 0;
            save(output);
        }
        if (!progress) {
            struct timespec delay = {.tv_nsec = 1000000};
            nanosleep(&delay, NULL);
        }
    }
    for (unsigned i = 0; i < 64; i++)
        if (clients[i].fd >= 0)
            close_socket(clients[i].fd);
    close_socket(fd);
    finish();
    save(output);
    free(seen);
    return invalid ? 1 : 0;
}
