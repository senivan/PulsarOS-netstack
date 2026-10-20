#pragma once

#include "ps_socket.h"
#include "packet.h"

#define TCP_BUFFER_SIZE 8192
#define TCP_MAX_RETRIES 5
#define TCP_TIME_WAIT_SECONDS 120
#define TCP_FIN_WAIT_SECONDS 120

enum tcp_state {
    TCP_CLOSED, TCP_LISTEN, TCP_SYN_SENT, TCP_SYN_RECEIVED, TCP_ESTABLISHED,
    TCP_FIN_WAIT_1, TCP_FIN_WAIT_2, TCP_CLOSE_WAIT, TCP_LAST_ACK, TCP_TIME_WAIT
};

/* Single flight, copied byte buffers. Out-of-order data is ACKed and discarded.
 * No simultaneous open, scaling, SACK, timestamps, urgent data or IP fragmentation. */
struct tcp_connection {
    enum tcp_state state;
    ps_fd_t parent;
    uint16_t backlog, mss, peer_window;
    uint32_t snd_una, snd_nxt, rcv_nxt, snd_wl1, snd_wl2;
    uint16_t rx_len, tx_len, flight_len;
    uint8_t flight_flags, retries, closing, peer_fin;
    uint64_t deadline, rto, expires;
    uint8_t rx[TCP_BUFFER_SIZE], tx[TCP_BUFFER_SIZE];
};

struct tcp_stats {
    uint64_t syns, established, closed, resets, retransmissions, timeouts;
    uint64_t duplicate_acks, out_of_order, sent, output_failed;
};

struct app_runtime;
struct ps_socket_entry;
struct rte_tcp_hdr;

int tcp_connect(struct app_runtime *, struct ps_socket_entry *, const struct ps_sockaddr *);
int tcp_listen(struct ps_socket_entry *, int backlog);
ps_fd_t tcp_accept(struct app_runtime *, struct ps_socket_entry *, struct ps_sockaddr *);
void tcp_close(struct app_runtime *, struct ps_socket_entry *, uint64_t now);
ssize_t tcp_send(struct app_runtime *, struct ps_socket_entry *, const void *, size_t);
ssize_t tcp_recv(struct app_runtime *, struct ps_socket_entry *, void *, size_t);
enum drop_reason tcp_input(struct app_runtime *, const struct packet_ctx *, const struct rte_tcp_hdr *,
                           uint16_t header_len, uint16_t payload_len, uint16_t mss, uint64_t now);
void tcp_tick(struct app_runtime *, uint64_t now);
void tcp_kick(struct app_runtime *, struct ps_socket_entry *, uint64_t now);
void tcp_fail(struct app_runtime *, struct ps_socket_entry *, int error);
void tcp_time_wait(struct ps_socket_entry *, uint64_t now);
int tcp_emit(struct app_runtime *, const struct ps_sockaddr *local, const struct ps_sockaddr *remote,
              uint32_t seq, uint32_t ack, uint8_t flags, uint16_t window,
              const void *data, uint16_t length);
int tcp_emit_flight(struct app_runtime *, struct ps_socket_entry *);
void tcp_ack(struct app_runtime *, struct ps_socket_entry *);
