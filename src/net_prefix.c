#include <arpa/inet.h>
#include "net_config.h"

uint32_t net_mask(uint32_t prefix) { return htonl(prefix ? UINT32_MAX << (32 - prefix) : 0); }
int net_match(uint32_t ip, uint32_t network, uint32_t prefix) { return (ip & net_mask(prefix)) == network; }
int net_prefix_valid(uint32_t ip, uint32_t prefix) { return prefix <= 32 && !(ip & ~net_mask(prefix)); }
int net_unicast(uint32_t ip)
{
    ip = ntohl(ip);
    return (ip >> 24) && (ip >> 24) != 127 && ip < 0xe0000000u;
}

int net_host(uint32_t ip, uint32_t prefix)
{
    if (prefix > 32) return 0;
    uint32_t mask = net_mask(prefix);
    return prefix >= 31 || ((ip & ~mask) && (ip & ~mask) != ~mask);
}
