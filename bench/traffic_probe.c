#define _GNU_SOURCE
#include <errno.h>
#include <poll.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>
#include "wire.h"
#include "latency.h"

int main(int argc, char **argv)
{
    struct options o;
    if (options_parse(argc, argv, &o))
        return 2;
    int fd = packet_socket(&o);
    if (fd < 0) {
        perror("probe socket");
        return 1;
    }
    struct options reply = o;
    reply.source_ip = o.destination_ip;
    reply.destination_ip = o.source_ip;
    memcpy(reply.source_mac, o.destination_mac, 6);
    memcpy(reply.destination_mac, o.source_mac, 6);
    reply.source_port = o.destination_port;
    reply.destination_port = o.source_port;
    reply.ttl = 63;
    struct latency latency = {0};
    uint64_t sent = 0, received = 0, invalid = 0, start = clock_ns(),
             end = start + (uint64_t)(o.duration * 1e9);
    uint8_t frame[BENCH_FRAME_MAX], input[2048];
    while (!bench_stop && clock_ns() < end) {
        packet_build(frame, &o, sent);
        uint64_t began = clock_ns();
        ssize_t n = send(fd, frame, o.frame_size, MSG_DONTWAIT);
        if (n != (ssize_t)o.frame_size) {
            if (errno == EAGAIN)
                continue;
            perror("probe send");
            return 1;
        }
        uint64_t expected = sent++;
        int found = 0;
        while (clock_ns() - began < 250000000u && !bench_stop) {
            struct pollfd p = {fd, POLLIN, 0};
            poll(&p, 1, 2);
            n = recv(fd, input, sizeof(input), MSG_DONTWAIT);
            if (n < 0)
                continue;
            uint64_t seq = 0;
            int rc = packet_validate(input, (size_t)n, &reply, &seq);
            if (rc < 0)
                invalid++;
            if (rc == 1 && seq == expected) {
                latency_add(&latency, clock_ns() - began);
                received++;
                found = 1;
                break;
            }
        }
        (void)found;
        if (o.rate)
            sleep_until(start + (uint64_t)((double)sent * 1e9 / o.rate));
    }
    FILE *f = fopen(o.output, "w");
    if (!f)
        return 1;
    fprintf(f,
            "{\"schema\":1,\"sent\":%llu,\"received\":%llu,\"invalid\":%llu,\"start_ns\":%llu,"
            "\"end_ns\":%llu,",
            (unsigned long long)sent, (unsigned long long)received, (unsigned long long)invalid,
            (unsigned long long)start, (unsigned long long)clock_ns());
    latency_write(f, &latency);
    fputs("}\n", f);
    fclose(f);
    free(latency.values);
    close(fd);
    return invalid ? 1 : 0;
}
