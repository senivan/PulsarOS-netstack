#define _GNU_SOURCE
#include <errno.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>
#include <linux/if_packet.h>
#include "wire.h"

static volatile sig_atomic_t snapshot;
static void capture(int sig)
{
    (void)sig;
    snapshot = 1;
}
static double seconds(struct timeval t) { return t.tv_sec + t.tv_usec / 1e6; }
static void arp_reply(int fd, const uint8_t *p, size_t length, const struct options *o,
                      struct metrics *m)
{
    if (length < 42 || read16(p + 12) != 0x0806 || read16(p + 14) != 1 ||
        read16(p + 16) != 0x0800 || p[18] != 6 || p[19] != 4 || read16(p + 20) != 1)
        return;
    m->arp_requests++;
    if (!o->arp)
        return;
    uint8_t reply[60] = {0};
    memcpy(reply, p, 42);
    memcpy(reply, p + 22, 6);
    memcpy(reply + 6, o->destination_mac, 6);
    write16(reply + 20, 2);
    memcpy(reply + 22, o->destination_mac, 6);
    memcpy(reply + 28, p + 38, 4);
    memcpy(reply + 32, p + 22, 6);
    memcpy(reply + 38, p + 28, 4);
    if (send(fd, reply, sizeof(reply), MSG_DONTWAIT) == sizeof(reply))
        m->arp++;
}
static void echo(int fd, uint8_t *p, size_t length)
{
    uint8_t copy[6];
    memcpy(copy, p, 6);
    memcpy(p, p + 6, 6);
    memcpy(p + 6, copy, 6);
    uint8_t *ip = p + 14, *udp = p + 34;
    memcpy(copy, ip + 12, 4);
    memcpy(ip + 12, ip + 16, 4);
    memcpy(ip + 16, copy, 4);
    uint16_t port = read16(udp);
    write16(udp, read16(udp + 2));
    write16(udp + 2, port);
    ip[8] = 64;
    write16(ip + 10, 0);
    write16(ip + 10, packet_checksum(ip, 20));
    write16(udp + 6, 0);
    uint16_t sum = udp_checksum(ip, udp, length - 34);
    write16(udp + 6, sum ? sum : 65535);
    send(fd, p, length, MSG_DONTWAIT);
}
static void pcap_packet(FILE *f, const void *data, uint32_t length)
{
    struct timespec t;
    clock_gettime(CLOCK_REALTIME, &t);
    uint32_t header[4] = {(uint32_t)t.tv_sec, (uint32_t)(t.tv_nsec / 1000), length, length};
    if (fwrite(header, sizeof(header), 1, f) != 1 || fwrite(data, length, 1, f) != 1) {
        perror("pcap write");
        exit(1);
    }
}
int main(int argc, char **argv)
{
    struct options o;
    if (options_parse(argc, argv, &o)) {
        fprintf(stderr, "invalid receiver options\n");
        return 2;
    }
    int fd = packet_socket(&o);
    if (fd < 0) {
        perror("receiver socket");
        return 1;
    }
    uint8_t *seen = calloc((o.sequence_limit + 7) / 8, 1);
    if (!seen)
        return 1;
    FILE *pcap = NULL;
    if (*o.pcap) {
        pcap = fopen(o.pcap, "wb");
        if (!pcap) {
            perror("pcap");
            return 1;
        }
        uint32_t header[6] = {0xa1b2c3d4, 0x00040002, 0, 0, 65535, 1};
        if (fwrite(header, sizeof(header), 1, pcap) != 1)
            return 1;
    }
    uint8_t buffers[BENCH_BATCH][2048];
    struct mmsghdr messages[BENCH_BATCH] = {0};
    struct iovec vectors[BENCH_BATCH];
    for (unsigned i = 0; i < BENCH_BATCH; i++) {
        vectors[i] = (struct iovec){buffers[i], sizeof(buffers[i])};
        messages[i].msg_hdr.msg_iov = &vectors[i];
        messages[i].msg_hdr.msg_iovlen = 1;
    }
    struct sigaction action = {.sa_handler = capture};
    sigemptyset(&action.sa_mask);
    sigaction(SIGUSR1, &action, NULL);
    struct metrics m = {0};
    struct rusage before, after;
    getrusage(RUSAGE_SELF, &before);
    m.start_ns = clock_ns();
    uint64_t high = 0;
    puts("READY");
    fflush(stdout);
    while (!bench_stop) {
        int n = recvmmsg(fd, messages, BENCH_BATCH, MSG_DONTWAIT, NULL);
        if (n < 0) {
            if (errno != EAGAIN && errno != EINTR) {
                perror("recvmmsg");
                return 1;
            }
            struct pollfd p = {fd, POLLIN, 0};
            poll(&p, 1, 20);
            n = 0;
        }
        uint64_t received_at = clock_ns();
        for (int i = 0; i < n; i++) {
            uint8_t *p = buffers[i];
            size_t length = messages[i].msg_len;
            uint64_t seq = 0;
            arp_reply(fd, p, length, &o, &m);
            if (o.probe_run && length >= 58 && read32(p + 42) == BENCH_MAGIC &&
                read32(p + 46) == o.probe_run) {
                struct options probe = o;
                probe.run = o.probe_run;
                probe.flows = probe.destinations = 1;
                probe.pattern = 0;
                if (packet_validate(p, length, &probe, &seq) == 1) {
                    if (o.echo)
                        echo(fd, p, length);
                    m.probes++;
                } else
                    m.invalid++;
                continue;
            }
            int valid = packet_validate(p, length, &o, &seq);
            if (valid == 0)
                continue;
            if (valid == 2) {
                m.unexpected++;
                continue;
            }
            if (valid < 0) {
                m.invalid++;
                continue;
            }
            m.packets++;
            m.bytes += length;
            if (seq >= o.sequence_limit) {
                m.out_of_range++;
                continue;
            }
            if (o.drop_mod && seq % o.drop_mod == o.drop_rem) {
                m.invalid++;
                continue;
            }
            if (seen[seq / 8] & (1u << (seq % 8))) {
                m.duplicates++;
                continue;
            }
            seen[seq / 8] |= (uint8_t)(1u << (seq % 8));
            m.unique++;
            if (seq < high)
                m.reordered++;
            if (seq > high)
                high = seq;
            m.highest_sequence = high;
            if (!m.first_ns)
                m.first_ns = received_at;
            m.last_ns = received_at;
            if (pcap && m.unique <= 16)
                pcap_packet(pcap, p, (uint32_t)length);
        }
        if (snapshot) {
            snapshot = 0;
            m.end_ns = clock_ns();
            metrics_write(&o, &m);
        }
    }
    m.missing_below_highest = m.unique ? high + 1 - m.unique : 0;
    if (m.unique && o.drop_mod) {
        uint64_t eligible = high >= o.drop_rem ? (high - o.drop_rem) / o.drop_mod + 1 : 0;
        m.missing_below_highest -= eligible;
    }
    m.end_ns = clock_ns();
    getrusage(RUSAGE_SELF, &after);
    m.user_seconds = seconds(after.ru_utime) - seconds(before.ru_utime);
    m.system_seconds = seconds(after.ru_stime) - seconds(before.ru_stime);
    struct tpacket_stats stats;
    socklen_t size = sizeof(stats);
    if (!getsockopt(fd, SOL_PACKET, PACKET_STATISTICS, &stats, &size)) {
        m.kernel_packets = stats.tp_packets;
        m.kernel_drops = stats.tp_drops;
    }
    metrics_write(&o, &m);
    if (pcap)
        fclose(pcap);
    free(seen);
    close(fd);
    return 0;
}
