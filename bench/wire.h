#pragma once
#include <stddef.h>
#include <stdint.h>
#include <signal.h>

#define BENCH_MAGIC 0x50534231u
#define BENCH_BATCH 64
#define BENCH_FRAME_MAX 1514
#define BENCH_TAG_SIZE 16
struct options {
    char interface[32], output[512], pcap[512];
    uint8_t source_mac[6], destination_mac[6];
    uint32_t source_ip, destination_ip, run, seed, flows, destinations, stride, pattern;
    uint32_t frame_size, source_port, destination_port, ttl, probe_run, drop_mod, drop_rem;
    uint64_t rate, sequence_limit;
    double duration;
    int arp, echo;
};
struct metrics {
    uint64_t packets, bytes, unique, duplicates, invalid, unexpected, reordered, out_of_range;
    uint64_t highest_sequence, missing_below_highest, arp_requests;
    uint64_t first_ns, last_ns, start_ns, end_ns, retries, kernel_packets, kernel_drops, arp,
        probes;
    double user_seconds, system_seconds;
};
extern volatile sig_atomic_t bench_stop;
uint64_t clock_ns(void);
uint16_t read16(const void *);
uint32_t read32(const void *);
uint64_t read64(const void *);
void write16(void *, uint16_t);
void write32(void *, uint32_t);
void write64(void *, uint64_t);
uint16_t packet_checksum(const void *, size_t);
uint16_t udp_checksum(const uint8_t *, const uint8_t *, size_t);
uint32_t destination(const struct options *, uint64_t);
void packet_build(uint8_t *, const struct options *, uint64_t);
int packet_validate(const uint8_t *, size_t, const struct options *, uint64_t *);
int options_parse(int, char **, struct options *);
int packet_socket(struct options *);
void metrics_write(const struct options *, const struct metrics *);
void sleep_until(uint64_t);
void payload_fill(uint8_t *, size_t, uint32_t run, uint64_t sequence, uint32_t seed);
int payload_valid(const uint8_t *, size_t, uint32_t run, uint32_t seed, uint64_t *sequence);

int unsigned_parse(const char *, uint64_t, uint64_t *);
int duration_parse(const char *, double *);

static inline uint8_t stream_byte(uint64_t offset)
{
    uint64_t word = (offset >> 3) + UINT64_C(0x9e3779b97f4a7c15);
    word = (word ^ (word >> 30)) * UINT64_C(0xbf58476d1ce4e5b9);
    word = (word ^ (word >> 27)) * UINT64_C(0x94d049bb133111eb);
    word ^= word >> 31;
    return (uint8_t)(word >> ((offset & 7) * 8));
}
