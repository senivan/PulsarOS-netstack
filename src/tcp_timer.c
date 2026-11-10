#include <errno.h>
#include <string.h>
#include <rte_cycles.h>
#include <rte_tcp.h>
#include "runtime.h"

void tcp_timer_progress(struct app_runtime *rt, uint64_t now)
{
    if (now < rt->tcp_timer_next) return;
    rt->tcp_timer_next = now + RTE_MAX(UINT64_C(1), rte_get_timer_hz() / 1000);
    tcp_tick(rt, now);
}

void tcp_tick(struct app_runtime *rt, uint64_t now)
{
    for (unsigned i = 0; i < rt->sockets.capacity; i++) {
        struct ps_socket_entry *s = &rt->sockets.entries[i];
        if (!s->allocated || s->type != PS_SOCK_STREAM) continue;
        struct tcp_connection *c = &s->transport.tcp;
        if (c->expires && now >= c->expires) {
            if (c->state != TCP_TIME_WAIT) rt->tcp_stats.timeouts++;
            tcp_fail(rt, s, c->state == TCP_TIME_WAIT ? 0 : ETIMEDOUT);
            continue;
        }
        tcp_kick(rt, s, now);
        if (!s->allocated || c->state == TCP_CLOSED) continue;
        if (c->persist_deadline && now >= c->persist_deadline) {
            tcp_emit(rt, &s->local, &s->remote, c->snd_una - 1, c->rcv_nxt,
                     RTE_TCP_ACK_FLAG, TCP_BUFFER_SIZE - c->rx_len, NULL, 0);
            c->persist_rto = RTE_MIN(c->persist_rto * 2, 60 * rte_get_timer_hz());
            c->persist_deadline = now + c->persist_rto;
        }
        if (!c->peer_window && c->persist_deadline) continue;
        if (!c->deadline || now < c->deadline) continue;
        if (c->retries == TCP_MAX_RETRIES) {
            rt->tcp_stats.timeouts++;
            tcp_fail(rt, s, ETIMEDOUT);
            continue;
        }
        if (c->flight_flags) {
            c->sample_blocked = 1;
            c->sample_valid = 0; /* Karn: retransmissions invalidate the sample. */
            c->ssthresh = RTE_MAX(c->flight_len / 2, 2 * c->mss);
            c->cwnd = c->mss;
            c->ca_bytes = 0;
            c->dupacks = c->recovery = 0;
            tcp_emit_flight(rt, s);
            rt->tcp_stats.retransmissions++;
        } else { c->deadline = 0; continue; }
        c->retries++;
        c->rto = RTE_MIN(c->rto * 2, 60 * rte_get_timer_hz());
        c->deadline = now + c->rto;
    }
}
