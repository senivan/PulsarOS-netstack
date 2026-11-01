#include <arpa/inet.h>
#include <assert.h>
#include <stdint.h>
#include <string.h>
#include "wire.h"

int main(void)
{
    struct options o = {.frame_size = 128,
                        .source_port = 20000,
                        .destination_port = 9000,
                        .ttl = 64,
                        .run = 123,
                        .seed = 42,
                        .flows = 64,
                        .destinations = 32,
                        .stride = 256};
    assert(inet_pton(AF_INET, "192.0.2.1", &o.source_ip) == 1);
    assert(inet_pton(AF_INET, "198.18.0.1", &o.destination_ip) == 1);
    uint8_t bytes[BENCH_FRAME_MAX + 1], copy[BENCH_FRAME_MAX];
    for (unsigned pattern = 0; pattern < 3; pattern++) {
        o.pattern = pattern;
        for (unsigned size = 60; size <= 1514; size++) {
            o.frame_size = size;
            const uint64_t sequences[] = {0, 1, 65535, 65536, UINT64_C(0x100000001)};
            for (unsigned i = 0; i < sizeof(sequences) / sizeof(sequences[0]); i++) {
                uint64_t seq = sequences[i], decoded = 0;
                packet_build(bytes + 1, &o, seq);
                assert(packet_validate(bytes + 1, size, &o, &decoded) == 1 && decoded == seq);
                assert(packet_checksum(bytes + 15, 20) == 0);
                assert(udp_checksum(bytes + 15, bytes + 35, size - 34) == 0);
                memcpy(copy, bytes + 1, size);
                copy[size - 1] ^= 1;
                assert(packet_validate(copy, size, &o, &decoded) == -1);
                assert(packet_validate(bytes + 1, size - 1, &o, &decoded) == -1);
                bytes[1 + 46] ^= 1;
                assert(packet_validate(bytes + 1, size, &o, &decoded) == 2);
            }
        }
    }
    uint8_t p[65];
    uint64_t seq = 0;
    payload_fill(p, sizeof(p), 123, 65536, 42);
    assert(payload_valid(p, sizeof(p), 123, 42, &seq) && seq == 65536);
    p[64] ^= 1;
    assert(!payload_valid(p, sizeof(p), 123, 42, &seq));
    assert(!payload_valid(p, 15, 123, 42, &seq));
    return 0;
}
