#pragma once

#include <stdint.h>
#include "ps_socket.h"

#define IPC_MAGIC 0x50534e53u
#define IPC_VERSION 1
#define IPC_HEADER_SIZE 64
#define IPC_PAYLOAD_MAX 8192
#define IPC_FRAME_MAX (IPC_HEADER_SIZE + IPC_PAYLOAD_MAX)
#define IPC_TIMEOUT_MS 5000
#define IPC_FEATURE_DGRAM_BATCH 1
#define IPC_DGRAM_HEADER 12

enum ipc_operation {
    IPC_HELLO = 1, IPC_SOCKET, IPC_BIND, IPC_CONNECT, IPC_LISTEN, IPC_ACCEPT,
    IPC_SEND, IPC_RECV, IPC_SENDTO, IPC_RECVFROM, IPC_CLOSE,
    IPC_SENDMMSG, IPC_RECVMMSG,
    IPC_CLEANUP = 65535
};

/* This native representation never goes on the wire. The header is 16 big-endian
 * 32-bit words; IPv4 occupies four raw network-order bytes. Reserved words zero. */
struct ipc_message {
    uint32_t op, id, length;
    int32_t fd, a, b, c, result;
    struct ps_sockaddr addr;
    uint8_t data[IPC_PAYLOAD_MAX];
};

void ipc_encode(uint8_t header[IPC_HEADER_SIZE], const struct ipc_message *);
int ipc_decode(const uint8_t header[IPC_HEADER_SIZE], struct ipc_message *);
int ipc_request_valid(const struct ipc_message *);
void ipc_datagram_encode(uint8_t *, const struct ps_sockaddr *, uint32_t length);
int ipc_datagram_decode(const uint8_t *, size_t available, struct ps_sockaddr *, uint32_t *length);
