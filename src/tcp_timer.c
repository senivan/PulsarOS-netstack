#include <errno.h>
#include <string.h>
#include <rte_cycles.h>
#include <rte_tcp.h>
#include "runtime.h"

void tcp_tick(struct app_runtime *rt, uint64_t now)
{
    for (unsigned i = 0; i < PS_SOCKET_MAX; i++) {
        struct ps_socket_entry *s = &rt->sockets.entries[i];
        if (!s->allocated || s->type != PS_SOCK_STREAM) continue;
        struct tcp_connection *c = &s->transport.tcp;
        if (c->expires && now >= c->expires) {
            if (c->state != TCP_TIME_WAIT) rt->tcp_stats.timeouts++;
            tcp_fail(rt, s, c->state == TCP_TIME_WAIT ? 0 : ETIMEDOUT);
            continue;
        }
        if (!c->deadline || now < c->deadline) continue;
        if (c->retries == TCP_MAX_RETRIES) {
            rt->tcp_stats.timeouts++;
            tcp_fail(rt, s, ETIMEDOUT);
            continue;
        }
        if (c->flight_flags) {
            /* Conservative single-flight RTO: start at one second and back off.
             * Retransmit copied bytes at SND.UNA, never retain graph mbufs. */
            tcp_emit_flight(rt, s);
            rt->tcp_stats.retransmissions++;
        } else if ((c->tx_len || c->closing) && !c->peer_window) {
            tcp_emit(rt, &s->local, &s->remote, c->snd_nxt - 1, c->rcv_nxt,
                      RTE_TCP_ACK_FLAG, TCP_BUFFER_SIZE - c->rx_len, NULL, 0);
        } else { c->deadline = 0; continue; }
        c->retries++;
        c->rto = RTE_MIN(c->rto * 2, 60 * rte_get_timer_hz());
        c->deadline = now + c->rto;
    }
}
