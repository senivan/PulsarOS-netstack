#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <getopt.h>
#include <inttypes.h>
#include <limits.h>
#include <net/if.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>
#include <linux/if_packet.h>
#include <linux/if_ether.h>
#include "wire.h"

volatile sig_atomic_t bench_stop;
static void stop(int sig)
{
    (void)sig;
    bench_stop = 1;
}
uint64_t clock_ns(void)
{
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);
    return (uint64_t)t.tv_sec * 1000000000u + (uint64_t)t.tv_nsec;
}
uint16_t read16(const void *p)
{
    uint16_t n;
    memcpy(&n, p, 2);
    return ntohs(n);
}
uint32_t read32(const void *p)
{
    uint32_t n;
    memcpy(&n, p, 4);
    return ntohl(n);
}
uint64_t read64(const void *p)
{
    return (uint64_t)read32(p) << 32 | read32((const uint8_t *)p + 4);
}
void write16(void *p, uint16_t n)
{
    n = htons(n);
    memcpy(p, &n, 2);
}
void write32(void *p, uint32_t n)
{
    n = htonl(n);
    memcpy(p, &n, 4);
}
void write64(void *p, uint64_t n)
{
    write32(p, n >> 32);
    write32((uint8_t *)p + 4, (uint32_t)n);
}
static uint32_t sum(const uint8_t *p, size_t n)
{
    uint32_t s = 0;
    while (n > 1) {
        s += (uint32_t)p[0] << 8 | p[1];
        p += 2;
        n -= 2;
    }
    if (n)
        s += (uint32_t)*p << 8;
    return s;
}
static uint16_t fold(uint32_t s)
{
    while (s >> 16)
        s = (s & 65535) + (s >> 16);
    return (uint16_t)~s;
}
uint16_t packet_checksum(const void *p, size_t n) { return fold(sum(p, n)); }
uint16_t udp_checksum(const uint8_t *ip, const uint8_t *udp, size_t n)
{
    return fold(sum(ip + 12, 8) + 17 + (uint32_t)n + sum(udp, n));
}
uint32_t destination(const struct options *o, uint64_t seq)
{
    uint64_t index = seq;
    if (o->pattern == 1) {
        index ^= o->seed;
        index ^= index >> 33;
        index *= UINT64_C(0xff51afd7ed558ccd);
        index ^= index >> 33;
    }
    if (o->pattern == 2)
        index = o->destinations - 1;
    return htonl(ntohl(o->destination_ip) + (uint32_t)(index % o->destinations) * o->stride);
}
void packet_build(uint8_t *b, const struct options *o, uint64_t seq)
{
    memset(b, 0, o->frame_size);
    memcpy(b, o->destination_mac, 6);
    memcpy(b + 6, o->source_mac, 6);
    write16(b + 12, 0x0800);
    uint8_t *ip = b + 14, *udp = b + 34, *payload = b + 42;
    ip[0] = 0x45;
    write16(ip + 2, o->frame_size - 14);
    write16(ip + 4, (uint16_t)seq);
    write16(ip + 6, 0x4000);
    ip[8] = (uint8_t)o->ttl;
    ip[9] = 17;
    memcpy(ip + 12, &o->source_ip, 4);
    uint32_t dst = destination(o, seq);
    memcpy(ip + 16, &dst, 4);
    write16(ip + 10, packet_checksum(ip, 20));
    unsigned flow = (unsigned)(seq % o->flows);
    write16(udp, o->source_port + flow);
    write16(udp + 2, o->destination_port + flow);
    write16(udp + 4, o->frame_size - 34);
    write32(payload, BENCH_MAGIC);
    write32(payload + 4, o->run);
    write64(payload + 8, seq);
    for (unsigned i = BENCH_TAG_SIZE; i < o->frame_size - 42; i++)
        payload[i] = (uint8_t)(seq + i * 17 + o->seed);
    uint16_t checksum = udp_checksum(ip, udp, o->frame_size - 34);
    write16(udp + 6, checksum ? checksum : 65535);
}
int packet_validate(const uint8_t *b, size_t n, const struct options *o, uint64_t *seq)
{
    if (n < 14 || read16(b + 12) != 0x0800)
        return 0;
    if (n < 34)
        return -1;
    const uint8_t *ip = b + 14, *udp = b + 34, *payload = b + 42;
    if (ip[9] != 17)
        return n >= 58 && read32(payload) == BENCH_MAGIC ? -1 : 0;
    if (n < 58 || read32(payload) != BENCH_MAGIC)
        return -1;
    if (read32(payload + 4) != o->run)
        return 2;
    *seq = read64(payload + 8);
    uint32_t dst = destination(o, *seq);
    if (n != o->frame_size || ip[0] != 0x45 || read16(ip + 2) != n - 14 ||
        read16(ip + 6) != 0x4000 || ip[8] != o->ttl || packet_checksum(ip, 20) ||
        memcmp(ip + 12, &o->source_ip, 4) || memcmp(ip + 16, &dst, 4) ||
        read16(ip + 4) != (uint16_t)*seq || read16(udp + 4) != n - 34 || !read16(udp + 6) ||
        udp_checksum(ip, udp, n - 34) || read16(udp) != o->source_port + *seq % o->flows ||
        read16(udp + 2) != o->destination_port + *seq % o->flows ||
        memcmp(b, o->destination_mac, 6) || memcmp(b + 6, o->source_mac, 6))
        return -1;
    for (unsigned i = BENCH_TAG_SIZE; i < n - 42; i++)
        if (payload[i] != (uint8_t)(*seq + i * 17 + o->seed))
            return -1;
    return 1;
}
int unsigned_parse(const char *s, uint64_t max, uint64_t *v)
{
    if (!*s)
        return -1;
    for (const char *p = s; *p; p++)
        if (*p < '0' || *p > '9')
            return -1;
    char *end;
    errno = 0;
    unsigned long long n = strtoull(s, &end, 10);
    if (errno || *end || n > max)
        return -1;
    *v = n;
    return 0;
}
int duration_parse(const char *s, double *value)
{
    char *end;
    errno = 0;
    double result = strtod(s, &end);
    if (errno || end == s || *end || !(result > 0) || result > 3600)
        return -1;
    *value = result;
    return 0;
}
static int mac(const char *s, uint8_t *out)
{
    unsigned v[6];
    char tail;
    if (strlen(s) != 17 ||
        sscanf(s, "%2x:%2x:%2x:%2x:%2x:%2x%c", v, v + 1, v + 2, v + 3, v + 4, v + 5, &tail) != 6)
        return -1;
    for (unsigned i = 0; i < 6; i++) {
        if (v[i] > 255)
            return -1;
        out[i] = (uint8_t)v[i];
    }
    return 0;
}
int options_parse(int argc, char **argv, struct options *o)
{
    *o = (struct options){.frame_size = 128,
                          .source_port = 20000,
                          .destination_port = 9000,
                          .ttl = 63,
                          .run = 1,
                          .seed = 42,
                          .flows = 1,
                          .destinations = 1,
                          .stride = 256,
                          .duration = 10,
                          .sequence_limit = 64000000};
    static const struct option opts[] = {{"interface", 1, 0, 'i'},
                                         {"output", 1, 0, 'o'},
                                         {"src", 1, 0, 's'},
                                         {"dst", 1, 0, 'd'},
                                         {"src-mac", 1, 0, 'm'},
                                         {"dst-mac", 1, 0, 'M'},
                                         {"size", 1, 0, 'z'},
                                         {"rate", 1, 0, 'r'},
                                         {"duration", 1, 0, 't'},
                                         {"flows", 1, 0, 'f'},
                                         {"destinations", 1, 0, 'n'},
                                         {"stride", 1, 0, 'S'},
                                         {"pattern", 1, 0, 'p'},
                                         {"run", 1, 0, 'R'},
                                         {"seed", 1, 0, 'e'},
                                         {"sport", 1, 0, 'a'},
                                         {"dport", 1, 0, 'b'},
                                         {"ttl", 1, 0, 'T'},
                                         {"sequence-limit", 1, 0, 'l'},
                                         {"arp", 0, 0, 'A'},
                                         {"echo", 0, 0, 'E'},
                                         {"probe-run", 1, 0, 'P'},
                                         {"drop-mod", 1, 0, 'D'},
                                         {"drop-rem", 1, 0, 'F'},
                                         {"pcap", 1, 0, 'c'},
                                         {0, 0, 0, 0}};
    int c;
    while ((c = getopt_long(argc, argv, "", opts, NULL)) != -1) {
        uint64_t value = 0;
        if (strchr("zrfnSReabTlPDF", c) && unsigned_parse(optarg, UINT32_MAX, &value))
            return -1;
        switch (c) {
        case 'i':
            if (strlen(optarg) >= sizeof(o->interface))
                return -1;
            strcpy(o->interface, optarg);
            break;
        case 'o':
            if (strlen(optarg) >= sizeof(o->output))
                return -1;
            strcpy(o->output, optarg);
            break;
        case 'c':
            if (strlen(optarg) >= sizeof(o->pcap))
                return -1;
            strcpy(o->pcap, optarg);
            break;
        case 's':
            if (inet_pton(AF_INET, optarg, &o->source_ip) != 1)
                return -1;
            break;
        case 'd':
            if (inet_pton(AF_INET, optarg, &o->destination_ip) != 1)
                return -1;
            break;
        case 'm':
            if (mac(optarg, o->source_mac))
                return -1;
            break;
        case 'M':
            if (mac(optarg, o->destination_mac))
                return -1;
            break;
        case 'z':
            o->frame_size = (uint32_t)value;
            break;
        case 'r':
            o->rate = value;
            break;
        case 'f':
            o->flows = (uint32_t)value;
            break;
        case 'n':
            o->destinations = (uint32_t)value;
            break;
        case 'S':
            o->stride = (uint32_t)value;
            break;
        case 'R':
            o->run = (uint32_t)value;
            break;
        case 'e':
            o->seed = (uint32_t)value;
            break;
        case 'a':
            o->source_port = (uint32_t)value;
            break;
        case 'b':
            o->destination_port = (uint32_t)value;
            break;
        case 'T':
            o->ttl = (uint32_t)value;
            break;
        case 'l':
            o->sequence_limit = value;
            break;
        case 'P':
            o->probe_run = (uint32_t)value;
            break;
        case 'D':
            o->drop_mod = (uint32_t)value;
            break;
        case 'F':
            o->drop_rem = (uint32_t)value;
            break;
        case 'A':
            o->arp = 1;
            break;
        case 'E':
            o->echo = 1;
            break;
        case 'p':
            if (!strcmp(optarg, "random"))
                o->pattern = 1;
            else if (!strcmp(optarg, "last"))
                o->pattern = 2;
            else if (strcmp(optarg, "sequential"))
                return -1;
            break;
        case 't':
            if (duration_parse(optarg, &o->duration))
                return -1;
            break;
        default:
            return -1;
        }
    }
    if (optind != argc || !*o->interface || !*o->output || o->frame_size < 60 ||
        o->frame_size > 1514 || !o->flows || o->flows > 4096 || !o->destinations ||
        o->destinations > 4096 || o->source_port + o->flows > 65536 ||
        o->destination_port + o->flows > 65536 || !o->sequence_limit ||
        o->sequence_limit > 256000000 || o->ttl > 255 || !o->run ||
        (o->drop_mod && o->drop_rem >= o->drop_mod))
        return -1;
    struct sigaction action = {.sa_handler = stop};
    sigemptyset(&action.sa_mask);
    sigaction(SIGINT, &action, NULL);
    sigaction(SIGTERM, &action, NULL);
    return 0;
}
int packet_socket(struct options *o)
{
    int fd = socket(AF_PACKET, SOCK_RAW | SOCK_NONBLOCK | SOCK_CLOEXEC, htons(ETH_P_ALL));
    if (fd < 0)
        return -1;
    unsigned index = if_nametoindex(o->interface);
    struct sockaddr_ll a = {
        .sll_family = AF_PACKET, .sll_protocol = htons(ETH_P_ALL), .sll_ifindex = (int)index};
    if (!index || bind(fd, (struct sockaddr *)&a, sizeof(a))) {
        close(fd);
        return -1;
    }
    int one = 1, buffer = 16 * 1024 * 1024;
    if (setsockopt(fd, SOL_PACKET, PACKET_IGNORE_OUTGOING, &one, sizeof(one)) &&
        errno != ENOPROTOOPT) {
        close(fd);
        return -1;
    }
    if (setsockopt(fd, SOL_SOCKET, SO_RCVBUFFORCE, &buffer, sizeof(buffer)))
        setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &buffer, sizeof(buffer));
    setsockopt(fd, SOL_SOCKET, SO_SNDBUF, &buffer, sizeof(buffer));
    struct packet_mreq m = {.mr_ifindex = (int)index, .mr_type = PACKET_MR_PROMISC};
    if (setsockopt(fd, SOL_PACKET, PACKET_ADD_MEMBERSHIP, &m, sizeof(m))) {
        close(fd);
        return -1;
    }
    return fd;
}
void metrics_write(const struct options *o, const struct metrics *m)
{
    FILE *f = fopen(o->output, "w");
    if (!f) {
        perror("metrics");
        exit(1);
    }
    fprintf(f,
            "{\"schema\":1,\"packets\":%" PRIu64 ",\"bytes\":%" PRIu64 ",\"unique\":%" PRIu64
            ",\"duplicates\":%" PRIu64 ",\"invalid\":%" PRIu64 ",\"unexpected\":%" PRIu64
            ",\"reordered\":%" PRIu64 ",\"out_of_range\":%" PRIu64 ",\"start_ns\":%" PRIu64
            ",\"end_ns\":%" PRIu64 ",\"first_ns\":%" PRIu64 ",\"last_ns\":%" PRIu64
            ",\"retries\":%" PRIu64 ",\"kernel_packets\":%" PRIu64 ",\"kernel_drops\":%" PRIu64
            ",\"arp\":%" PRIu64 ",\"probes\":%" PRIu64
            ",\"sequence_bits\":64,\"highest_sequence\":%" PRIu64
            ",\"missing_below_highest\":%" PRIu64 ",\"arp_requests\":%" PRIu64
            ",\"ipv4_id_wraps\":%" PRIu64 ",\"user_seconds\":%.9f,\"system_seconds\":%.9f}\n",
            m->packets, m->bytes, m->unique, m->duplicates, m->invalid, m->unexpected, m->reordered,
            m->out_of_range, m->start_ns, m->end_ns, m->first_ns, m->last_ns, m->retries,
            m->kernel_packets, m->kernel_drops, m->arp, m->probes, m->highest_sequence,
            m->missing_below_highest, m->arp_requests, m->highest_sequence / 65536, m->user_seconds,
            m->system_seconds);
    if (fclose(f)) {
        perror("metrics close");
        exit(1);
    }
}
void sleep_until(uint64_t target)
{
    while (!bench_stop) {
        uint64_t n = clock_ns();
        if (n >= target)
            return;
        if (target - n > 100000) {
            struct timespec t = {.tv_sec = (time_t)(target / 1000000000),
                                 .tv_nsec = (long)(target % 1000000000)};
            clock_nanosleep(CLOCK_MONOTONIC, TIMER_ABSTIME, &t, NULL);
        }
    }
}
void payload_fill(uint8_t *p, size_t length, uint32_t run, uint64_t sequence, uint32_t seed)
{
    write32(p, BENCH_MAGIC);
    write32(p + 4, run);
    write64(p + 8, sequence);
    for (size_t i = 16; i < length; i++)
        p[i] = (uint8_t)(sequence + i * 17 + seed);
}
int payload_valid(const uint8_t *p, size_t length, uint32_t run, uint32_t seed, uint64_t *sequence)
{
    if (length < 16 || read32(p) != BENCH_MAGIC || read32(p + 4) != run)
        return 0;
    *sequence = read64(p + 8);
    for (size_t i = 16; i < length; i++)
        if (p[i] != (uint8_t)(*sequence + i * 17 + seed))
            return 0;
    return 1;
}
