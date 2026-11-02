#pragma once
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#define LATENCY_CAPACITY 1000000
struct latency {
    uint64_t *values, count, total, random;
};
static inline void latency_add(struct latency *s, uint64_t value)
{
    if (!s->values) {
        s->values = malloc(LATENCY_CAPACITY * sizeof(uint64_t));
        if (!s->values)
            exit(1);
        s->random = 42;
    }
    s->total++;
    if (s->count < LATENCY_CAPACITY)
        s->values[s->count++] = value;
    else {
        s->random = s->random * UINT64_C(6364136223846793005) + 1;
        uint64_t i = s->random % s->total;
        if (i < LATENCY_CAPACITY)
            s->values[i] = value;
    }
}
static inline int latency_compare(const void *a, const void *b)
{
    uint64_t x = *(const uint64_t *)a, y = *(const uint64_t *)b;
    return (x > y) - (x < y);
}
static inline void latency_write(FILE *f, struct latency *s)
{
    fprintf(f, "\"latency_samples\":%llu", (unsigned long long)s->count);
    if (!s->count) {
        fputs(
            ",\"p50_us\":null,\"p90_us\":null,\"p99_us\":null,\"p999_us\":null,\"maximum_us\":null",
            f);
        return;
    }
    qsort(s->values, s->count, sizeof(uint64_t), latency_compare);
    fprintf(f, ",\"p50_us\":%.3f,\"p90_us\":%.3f,\"p99_us\":%.3f,",
            s->values[(s->count - 1) * 50 / 100] / 1e3, s->values[(s->count - 1) * 90 / 100] / 1e3,
            s->values[(s->count - 1) * 99 / 100] / 1e3);
    if (s->count >= 10000)
        fprintf(f, "\"p999_us\":%.3f,", s->values[(s->count - 1) * 999 / 1000] / 1e3);
    else
        fputs("\"p999_us\":null,", f);
    fprintf(f, "\"maximum_us\":%.3f", s->values[s->count - 1] / 1e3);
}
