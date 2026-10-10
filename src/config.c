#include "config.h"

#include <arpa/inet.h>
#include <ctype.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void app_config_defaults(struct app_config *conf)
{
    memset(conf, 0, sizeof(*conf));
    conf->mbufs = DPDK_MBUF_COUNT;
    conf->mbuf_cache = DPDK_MBUF_CACHE;
    conf->rx_desc = DPDK_RX_DESC;
    conf->tx_desc = DPDK_TX_DESC;
}

static char *trim(char *s)
{
    while (isspace((unsigned char)*s)) s++;
    char *end = s + strlen(s);
    while (end > s && isspace((unsigned char)end[-1])) *--end = '\0';
    return s;
}

static int number(const char *s, unsigned long max, unsigned long *out)
{
    if (!*s) return -1;
    for (const char *p = s; *p; p++) if (!isdigit((unsigned char)*p)) return -1;
    char *end;
    errno = 0;
    *out = strtoul(s, &end, 10);
    return errno || *end || *out > max ? -1 : 0;
}

static int parse_prefix(char *s, uint32_t *ip_be, uint8_t *prefix_len)
{
    char *slash = strchr(s, '/');
    unsigned long prefix;
    if (!slash) return -1;
    *slash++ = '\0';
    struct in_addr ip;
    if (number(slash, 32, &prefix) || inet_pton(AF_INET, s, &ip) != 1) return -1;
    *ip_be = ip.s_addr;
    *prefix_len = (uint8_t)prefix;
    return 0;
}

static int parse_cidr(char *s, struct netif_config *conf)
{
    if (parse_prefix(s, &conf->ip_be, &conf->prefix_len)) return -1;
    uint32_t host = ntohl(conf->ip_be);
    uint8_t prefix = conf->prefix_len;
    uint32_t mask = prefix ? UINT32_MAX << (32 - prefix) : 0;
    if ((host >> 24) == 0 || (host >> 24) == 127 || host >= 0xe0000000u ||
        (prefix <= 30 && ((host & ~mask) == 0 || (host & ~mask) == ~mask))) return -1;
    return 0;
}

int app_config_load(const char *path, struct app_config *conf, char *err, size_t err_len)
{
    FILE *file = fopen(path, "r");
    if (!file) { snprintf(err, err_len, "%s: %s", path, strerror(errno)); return -1; }
    app_config_defaults(conf);
    static const char *const keys[] = { "lcore", "pmd", "device", "ip", "no_huge", "ipv4_forwarding" };
    unsigned global_seen = 0, seen[NETIF_MAX] = {0}, line_no = 0;
    unsigned route_seen[ROUTE_CAPACITY] = {0};
    int sectioned = 0, in_route = 0;
    uint16_t current = 0;
    char line[256];
    const char *why = "invalid value";
    while (fgets(line, sizeof(line), file)) {
        line_no++;
        if (!strchr(line, '\n') && !feof(file)) { why = "line too long"; goto bad; }
        char *key = trim(line);
        if (!*key || *key == '#') continue;
        if (!strcmp(key, "[interface]")) {
            if (!sectioned && seen[0]) { why = "cannot mix legacy and interface sections"; goto bad; }
            if (conf->netif_count == NETIF_MAX) { why = "too many interfaces"; goto bad; }
            current = conf->netif_count++;
            sectioned = 1;
            in_route = 0;
            continue;
        }
        if (!strcmp(key, "[route]")) {
            if (conf->route_count == ROUTE_CAPACITY) { why = "too many routes"; goto bad; }
            conf->route_count++;
            in_route = 1;
            continue;
        }
        char *value = strchr(key, '=');
        if (!value) { why = "expected key=value"; goto bad; }
        *value++ = '\0';
        key = trim(key);
        value = trim(value);
        if (in_route && strcmp(key, "lcore") && strcmp(key, "no_huge") && strcmp(key, "ipv4_forwarding")) {
            struct route_config *route = &conf->routes[conf->route_count - 1];
            unsigned *scope = &route_seen[conf->route_count - 1];
            unsigned bit;
            if (!strcmp(key, "prefix")) bit = 1;
            else if (!strcmp(key, "device")) bit = 2;
            else if (!strcmp(key, "gateway")) bit = 4;
            else { why = "unknown route key"; goto bad; }
            if (*scope & bit) { why = "duplicate route key"; goto bad; }
            *scope |= bit;
            if (bit == 1) {
                if (parse_prefix(value, &route->prefix_be, &route->prefix_len)) goto bad;
                uint32_t mask = route->prefix_len ? UINT32_MAX << (32 - route->prefix_len) : 0;
                route->prefix_be &= htonl(mask);
            } else if (bit == 2) {
                if (!*value || strlen(value) >= sizeof(route->device)) goto bad;
                strcpy(route->device, value);
            } else {
                struct in_addr gateway;
                if (inet_pton(AF_INET, value, &gateway) != 1 || !gateway.s_addr) goto bad;
                route->gateway_be = gateway.s_addr;
            }
            continue;
        }
        unsigned k;
        for (k = 0; k < sizeof(keys) / sizeof(keys[0]); k++)
            if (!strcmp(key, keys[k])) break;
        if (k == sizeof(keys) / sizeof(keys[0])) { why = "unknown key"; goto bad; }
        unsigned *scope = k == 0 || k == 4 || k == 5 ? &global_seen : &seen[current];
        if (*scope & (1u << k)) { why = "duplicate key"; goto bad; }
        *scope |= 1u << k;
        struct netif_config *netif = &conf->interfaces[current];
        unsigned long n;
        switch (k) {
        case 0:
            if (number(value, 1023, &n)) goto bad;
            conf->lcore = (unsigned)n;
            break;
        case 1:
            if (!strcmp(value, "tap")) netif->pmd = PMD_TAP;
            else if (!strcmp(value, "af_packet")) netif->pmd = PMD_AFPKT;
            else if (!strcmp(value, "physical")) netif->pmd = PMD_PHYS;
            else goto bad;
            break;
        case 2:
            if (!*value || strlen(value) >= sizeof(netif->device)) goto bad;
            for (const char *p = value; *p; p++)
                if (!isalnum((unsigned char)*p) && !strchr("_.:-", *p)) goto bad;
            strcpy(netif->device, value);
            break;
        case 3:
            if (parse_cidr(value, netif)) goto bad;
            break;
        case 4:
            if (number(value, 1, &n)) goto bad;
            conf->no_huge = (uint8_t)n;
            break;
        case 5:
            if (number(value, 1, &n)) goto bad;
            conf->ipv4_forwarding = (uint8_t)n;
            break;
        }
    }
    if (ferror(file)) { why = "read failed"; goto bad; }
    if (!sectioned) conf->netif_count = 1;
    for (uint16_t i = 0; i < conf->netif_count; i++) {
        const struct netif_config *netif = &conf->interfaces[i];
        if ((seen[i] & 14u) != 14u) { why = "pmd, device and ip are required per interface"; goto bad; }
        if (netif->pmd != PMD_PHYS && strlen(netif->device) >= 16) {
            why = "interface name must be shorter than 16 bytes"; goto bad;
        }
        if (netif->pmd == PMD_PHYS && conf->no_huge) {
            why = "no_huge is only supported with virtual PMDs"; goto bad;
        }
        for (uint16_t j = 0; j < i; j++) {
            if (!strcmp(netif->device, conf->interfaces[j].device)) {
                why = "duplicate device"; goto bad;
            }
            if (netif->ip_be == conf->interfaces[j].ip_be) {
                why = "duplicate local IP"; goto bad;
            }
        }
    }
    for (uint16_t i = 0; i < conf->route_count; i++) {
        if ((route_seen[i] & 3u) != 3u) { why = "prefix and device are required per route"; goto bad; }
    }
    struct route_table routes;
    int rc = route_config_init(conf, &routes);
    if (rc) {
        why = rc == -ENOSPC ? "too many connected and static routes" :
              rc == -ENODEV ? "unknown route device" : "invalid or unreachable gateway";
        goto bad;
    }
    fclose(file);
    return 0;
bad:
    snprintf(err, err_len, "%s:%u: %s", path, line_no, why);
    fclose(file);
    return -1;
}
