#include <arpa/inet.h>
#include <errno.h>
#include <string.h>
#include "ipc.h"

void ipc_encode(uint8_t header[IPC_HEADER_SIZE], const struct ipc_message *m)
{
    uint32_t words[16] = { IPC_MAGIC, IPC_VERSION, m->op, m->id, m->length,
        (uint32_t)m->fd, (uint32_t)m->a, (uint32_t)m->b, (uint32_t)m->c, 0,
        m->addr.port, (uint32_t)m->result, 0, 0, 0, 0 };
    for (unsigned i = 0; i < 16; i++) words[i] = htonl(words[i]);
    memcpy(header, words, sizeof(words));
    memcpy(header + 36, &m->addr.ip_be, 4);
}

int ipc_decode(const uint8_t header[IPC_HEADER_SIZE], struct ipc_message *m)
{
    uint32_t words[16];
    memcpy(words, header, sizeof(words));
    for (unsigned i = 0; i < 16; i++) words[i] = ntohl(words[i]);
    if (words[0] != IPC_MAGIC || words[1] != IPC_VERSION || words[4] > IPC_PAYLOAD_MAX ||
        words[10] > UINT16_MAX || words[12] || words[13] || words[14] || words[15] || !words[3]) return -EPROTO;
    memset(m, 0, sizeof(*m));
    m->op = words[2]; m->id = words[3]; m->length = words[4];
    m->fd = (int32_t)words[5]; m->a = (int32_t)words[6]; m->b = (int32_t)words[7]; m->c = (int32_t)words[8];
    memcpy(&m->addr.ip_be, header + 36, 4);
    m->addr.port = (uint16_t)words[10];
    m->result = (int32_t)words[11];
    return 0;
}

int ipc_request_valid(const struct ipc_message *m)
{
    if (m->op < IPC_HELLO || m->op > IPC_CLOSE || m->result) return 0;
    if (m->op != IPC_SEND && m->op != IPC_SENDTO && m->length) return 0;
    if ((m->op == IPC_RECV || m->op == IPC_RECVFROM) && (m->a < 0 || m->a > IPC_PAYLOAD_MAX)) return 0;
    return 1;
}
