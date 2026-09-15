#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <rte_eal.h>
#include <rte_errno.h>
#include <rte_lcore.h>
#include "dpdk_port.h"

#define EAL_ARG_MAX 20
#define EAL_ARG_LEN 128

static int add_arg(char *argv[], char storage[][EAL_ARG_LEN], int *argc, const char *arg)
{
    if (*argc >= EAL_ARG_MAX || strlen(arg) >= EAL_ARG_LEN) return -1;
    strcpy(storage[*argc], arg);
    argv[*argc] = storage[*argc];
    (*argc)++;
    return 0;
}

int eal_init(const char *progname, const struct app_config *conf)
{
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
    if (conf->pmd == PMD_PHYS) {
        if (add_arg(argv, storage, &argc, "-a") ||
            add_arg(argv, storage, &argc, conf->device)) return -1;
    } else {
        if (conf->pmd == PMD_TAP)
            snprintf(device, sizeof(device), "--vdev=net_tap0,iface=%s", conf->device);
        else
            snprintf(device, sizeof(device), "--vdev=net_af_packet0,iface=%s,qpairs=1", conf->device);
        if (add_arg(argv, storage, &argc, "--no-pci") ||
            add_arg(argv, storage, &argc, device)) return -1;
        if (conf->no_huge && add_arg(argv, storage, &argc, "--no-huge")) return -1;
    }
    if (rte_eal_init(argc, argv) < 0) return -1;
    if (rte_lcore_count() != 1) { rte_eal_cleanup(); return -1; }
    return 0;
}

int port_init(const struct app_config *conf, struct app_runtime *rt)
{
    const char *name = conf->pmd == PMD_TAP ? "net_tap0" :
                       conf->pmd == PMD_AFPKT ? "net_af_packet0" : conf->device;
    uint16_t id;
    if (rte_eth_dev_count_avail() != 1 || rte_eth_dev_get_port_by_name(name, &id) < 0) {
        fprintf(stderr, "expected exactly one DPDK port named %s\n", name);
        return -1;
    }
    rt->port.port_id = id;
    /* Close the probed device even if configuration fails partway through. */
    rt->port.configured = 1;
    rt->port.ip_be = conf->ip_be;
    rt->port.prefix_len = conf->prefix_len;
    rt->mbuf_pool = rte_pktmbuf_pool_create("netstack_mbufs", conf->mbufs, conf->mbuf_cache,
                                           0, RTE_MBUF_DEFAULT_BUF_SIZE, rte_socket_id());
    if (!rt->mbuf_pool) {
        fprintf(stderr, "failed to create mbuf pool: %s\n", rte_strerror(rte_errno));
        return -1;
    }
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
    if (!rc) rc = rte_eth_macaddr_get(id, &rt->port.mac);
    if (!rc) rc = rte_eth_dev_get_mtu(id, &rt->port.mtu);
    if (!rc && (!rte_is_valid_assigned_ether_addr(&rt->port.mac) || rt->port.mtu > 1500)) rc = -1;
    if (!rc) rc = rte_eth_dev_start(id);
    if (rc) { fprintf(stderr, "failed to configure port %s: %d\n", name, rc); return -1; }
    rt->port.started = 1;
    printf("configured %s as DPDK port %u, mtu %u, one RX/TX queue\n", name, id, rt->port.mtu);
    return 0;
}

void port_fini(struct app_runtime *rt)
{
    if (rt->port.started) rte_eth_dev_stop(rt->port.port_id);
    if (rt->port.configured) rte_eth_dev_close(rt->port.port_id);
    rt->port.started = rt->port.configured = 0;
    if (rt->mbuf_pool) { rte_mempool_free(rt->mbuf_pool); rt->mbuf_pool = NULL; }
}
