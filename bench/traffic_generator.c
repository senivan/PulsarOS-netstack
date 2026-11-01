#define _GNU_SOURCE
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <unistd.h>
#include "wire.h"

static double seconds(struct timeval t) { return t.tv_sec + t.tv_usec / 1e6; }
int main(int argc, char **argv)
{
    struct options o;
    if (options_parse(argc, argv, &o)) {
        fprintf(stderr, "invalid generator options\n");
        return 2;
    }
    int fd = packet_socket(&o);
    if (fd < 0) {
        perror("packet socket");
        return 1;
    }
    uint8_t data[BENCH_BATCH][BENCH_FRAME_MAX];
    struct mmsghdr messages[BENCH_BATCH] = {0};
    struct iovec vectors[BENCH_BATCH];
    for (unsigned i = 0; i < BENCH_BATCH; i++) {
        vectors[i] = (struct iovec){data[i], o.frame_size};
        messages[i].msg_hdr.msg_iov = &vectors[i];
        messages[i].msg_hdr.msg_iovlen = 1;
    }
    struct metrics m = {0};
    struct rusage before, after;
    getrusage(RUSAGE_SELF, &before);
    m.start_ns = clock_ns();
    uint64_t deadline = m.start_ns + (uint64_t)(o.duration * 1e9);
    while (!bench_stop && clock_ns() < deadline && m.packets < o.sequence_limit) {
        unsigned batch = o.rate ? (unsigned)(o.rate / 10000) : BENCH_BATCH;
        if (!batch)
            batch = 1;
        if (batch > BENCH_BATCH)
            batch = BENCH_BATCH;
        if (batch > o.sequence_limit - m.packets)
            batch = (unsigned)(o.sequence_limit - m.packets);
        for (unsigned i = 0; i < batch; i++)
            packet_build(data[i], &o, m.packets + i);
        int n = sendmmsg(fd, messages, batch, MSG_DONTWAIT);
        if (n < 0) {
            if (errno == EAGAIN || errno == ENOBUFS || errno == EINTR) {
                m.retries++;
                continue;
            }
            perror("sendmmsg");
            close(fd);
            return 1;
        }
        m.packets += (unsigned)n;
        m.bytes += (uint64_t)n * o.frame_size;
        if (o.rate)
            sleep_until(m.start_ns + (uint64_t)((double)m.packets * 1e9 / o.rate));
    }
    m.highest_sequence = m.packets ? m.packets - 1 : 0;
    m.end_ns = clock_ns();
    getrusage(RUSAGE_SELF, &after);
    m.user_seconds = seconds(after.ru_utime) - seconds(before.ru_utime);
    m.system_seconds = seconds(after.ru_stime) - seconds(before.ru_stime);
    metrics_write(&o, &m);
    close(fd);
    if (m.packets == o.sequence_limit) {
        fprintf(stderr, "sequence tracking limit exhausted; sample invalid\n");
        return 3;
    }
    return 0;
}
