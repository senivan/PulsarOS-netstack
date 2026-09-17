#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <rte_eal.h>
#include <rte_errno.h>
#include <rte_lcore.h>
#include "dpdk_port.h"

#define EAL_ARG_MAX (12 + 2 * NETIF_MAX)
#define EAL_ARG_LEN 128

static int add_arg(char *argv[], char storage[][EAL_ARG_LEN], int *argc, const char *arg)
{
    if (*argc >= EAL_ARG_MAX || strlen(arg) >= EAL_ARG_LEN) return -1;
    strcpy(storage[*argc], arg);
    argv[*argc] = storage[*argc];
    (*argc)++;
    return 0;
}

static void device_name(const struct netif_config *conf, uint16_t index, char *name, size_t size)
{
    if (conf->pmd == PMD_PHYS) snprintf(name, size, "%s", conf->device);
    else snprintf(name, size, "%s%u", conf->pmd == PMD_TAP ? "net_tap" : "net_af_packet", index);
}

int eal_init(const char *progname, const struct app_config *conf)
{
    if (!conf->netif_count || conf->netif_count > NETIF_MAX) return -1;
    char storage[EAL_ARG_MAX][EAL_ARG_LEN], *argv[EAL_ARG_MAX + 1] = {0};
    char core[16], prefix[EAL_ARG_LEN], device[EAL_ARG_LEN];
    int argc = 0;
    snprintf(core, sizeof(core), "%u", conf->lcore);
    snprintf(prefix, sizeof(prefix), "--file-prefix=pulsaros-netstack-%ld", (long)getpid());
    if (add_arg(argv, storage, &argc, progname) ||
        add_arg(argv, storage, &argc, "-l") || add_arg(argv, storage, &argc, core) ||
        add_arg(argv, storage, &argc, "-n") || add_arg(argv, storage, &argc, "1") ||
        add_arg(argv, storage, &argc, "--proc-type=primary") ||
        add_arg(argv, storage, &argc, prefix)) return -1;
    int physical = 0;
    for (uint16_t i = 0; i < conf->netif_count; i++) {
        const struct netif_config *netif = &conf->interfaces[i];
        if (netif->pmd == PMD_PHYS) {
            physical = 1;
            if (add_arg(argv, storage, &argc, "-a") ||
                add_arg(argv, storage, &argc, netif->device)) return -1;
        } else {
            char name[32];
            device_name(netif, i, name, sizeof(name));
            snprintf(device, sizeof(device), "--vdev=%s,iface=%s%s", name, netif->device,
                     netif->pmd == PMD_AFPKT ? ",qpairs=1" : "");
            if (add_arg(argv, storage, &argc, device)) return -1;
        }
    }
    if (physical && conf->no_huge) return -1;
    if (!physical && add_arg(argv, storage, &argc, "--no-pci")) return -1;
    if (conf->no_huge && add_arg(argv, storage, &argc, "--no-huge")) return -1;
    if (rte_eal_init(argc, argv) < 0) return -1;
    if (rte_lcore_count() != 1) { rte_eal_cleanup(); return -1; }
    return 0;
}

static int configure_port(const struct app_config *conf, struct app_runtime *rt, uint16_t index)
{
    const struct netif_config *netif = &conf->interfaces[index];
    struct port_state *port = &rt->ports[index];
    char name[64];
    device_name(netif, index, name, sizeof(name));
    uint16_t id;
    if (rte_eth_dev_get_port_by_name(name, &id) < 0 || netif_by_dpdk_port(rt, id)) {
        fprintf(stderr, "missing or duplicate DPDK port named %s\n", name);
        return -1;
    }
    port->id = index;
    port->port_id = id;
    /* Close the probed device even if configuration fails partway through. */
    port->configured = 1;
    port->ip_be = netif->ip_be;
    port->prefix_len = netif->prefix_len;
    struct rte_eth_conf ec = {0};
    ec.rxmode.mq_mode = RTE_ETH_MQ_RX_NONE;
    ec.txmode.mq_mode = RTE_ETH_MQ_TX_NONE;
    uint16_t rx_desc = conf->rx_desc, tx_desc = conf->tx_desc;
    int socket = rte_eth_dev_socket_id(id);
    if (socket < 0) socket = (int)rte_socket_id();
    int rc = rte_eth_dev_configure(id, 1, 1, &ec);
    if (!rc) rc = rte_eth_dev_adjust_nb_rx_tx_desc(id, &rx_desc, &tx_desc);
    if (!rc) rc = rte_eth_rx_queue_setup(id, 0, rx_desc, socket, NULL, rt->mbuf_pool);
    if (!rc) rc = rte_eth_tx_queue_setup(id, 0, tx_desc, socket, NULL);
    if (!rc) rc = rte_eth_macaddr_get(id, &port->mac);
    if (!rc) rc = rte_eth_dev_get_mtu(id, &port->mtu);
    if (!rc && (!rte_is_valid_assigned_ether_addr(&port->mac) || port->mtu > 1500)) rc = -1;
    if (!rc) rc = rte_eth_dev_start(id);
    if (rc) { fprintf(stderr, "failed to configure port %s: %d\n", name, rc); return -1; }
    port->started = 1;
    printf("configured %s as DPDK port %u, mtu %u, one RX/TX queue\n", name, id, port->mtu);
    return 0;
}

int port_init(const struct app_config *conf, struct app_runtime *rt)
{
    if (!conf->netif_count || conf->netif_count > NETIF_MAX) return -1;
    rt->port_count = conf->netif_count;
    rt->mbuf_pool = rte_pktmbuf_pool_create("netstack_mbufs", conf->mbufs, conf->mbuf_cache,
                                           0, RTE_MBUF_DEFAULT_BUF_SIZE, rte_socket_id());
    if (!rt->mbuf_pool) {
        fprintf(stderr, "failed to create mbuf pool: %s\n", rte_strerror(rte_errno));
        return -1;
    }
    for (uint16_t i = 0; i < rt->port_count; i++)
        if (configure_port(conf, rt, i)) return -1;
    return route_init_connected(rt);
}

void port_fini(struct app_runtime *rt)
{
    for (uint16_t i = 0; i < rt->port_count; i++) {
        struct port_state *port = &rt->ports[i];
        if (port->started) rte_eth_dev_stop(port->port_id);
        if (port->configured) rte_eth_dev_close(port->port_id);
        port->started = port->configured = 0;
    }
    rt->port_count = 0;
    if (rt->mbuf_pool) { rte_mempool_free(rt->mbuf_pool); rt->mbuf_pool = NULL; }
}
