#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include "config.h"

static void check(const char *text, int valid)
{
    char path[] = "/tmp/netstack-config-XXXXXX";
    int fd = mkstemp(path);
    assert(fd >= 0);
    FILE *f = fdopen(fd, "w");
    assert(f);
    assert(fputs(text, f) >= 0);
    assert(fclose(f) == 0);
    struct app_config conf;
    char err[256];
    int rc = app_config_load(path, &conf, err, sizeof(err));
    assert((rc == 0) == valid);
    if (valid) {
        assert(conf.mbufs == DPDK_MBUF_COUNT);
        assert(conf.rx_desc == DPDK_RX_DESC);
        unsigned expected = 0;
        for (const char *s = text; (s = strstr(s, "[interface]")); s++) expected++;
        assert(conf.netif_count == (expected ? expected : 1));
        if (conf.netif_count == 2) {
            assert(conf.interfaces[0].ip_be == inet_addr("192.0.2.2"));
            assert(conf.interfaces[1].ip_be == inet_addr("198.51.100.2"));
            assert(conf.interfaces[1].prefix_len == 24);
            assert(!strcmp(conf.interfaces[1].device, "eth1"));
        }
    } else assert(err[0]);
    assert(unlink(path) == 0);
}

int main(void)
{
    const char *base = "pmd=tap\ndevice=pshost0\nip=192.0.2.2/24\n";
    check(base, 1);
    const char *bad[] = { "lcore=0-1\n", "lcore=-1\n", "lcore=\n", "lcore=1024\n",
        "lcore=0\nlcore=1\n", "unknown=yes\n", "no_huge=2\n", "pmd=physical\n",
        "ip=192.0.2.3/24\n", "not-a-setting\n" };
    for (unsigned i = 0; i < sizeof(bad) / sizeof(bad[0]); i++) {
        char text[512];
        snprintf(text, sizeof(text), "%s%s", base, bad[i]);
        check(text, 0);
    }
    const char *ips[] = { "0.0.0.0/0", "127.0.0.1/8", "224.1.2.3/24", "255.255.255.255/32",
        "192.0.2.0/24", "192.0.2.255/24", "192.0.2.2/", "192.0.2.2/-1", "192.0.2.2/33",
        "192.0.2.2", "192.0.2.999/24" };
    for (unsigned i = 0; i < sizeof(ips) / sizeof(ips[0]); i++) {
        char text[256];
        snprintf(text, sizeof(text), "pmd=tap\ndevice=pshost0\nip=%s\n", ips[i]);
        check(text, 0);
    }
    check("pmd=tap\nip=192.0.2.2/24\n", 0);
    check("pmd=tap\ndevice=net0,queues=4\nip=192.0.2.2/24\n", 0);
    check("pmd=tap\ndevice=interface-name-too-long\nip=192.0.2.2/24\n", 0);
    check("pmd=physical\ndevice=0000:01:00.0\nip=192.0.2.2/24\nno_huge=1\n", 0);
    check("pmd=physical\ndevice=0000:01:00.0\nip=192.0.2.2/24\n", 1);
    check(" # comment\n pmd = af_packet \n device = eth0\nip=192.0.2.2/31\nlcore=2\nno_huge=1\n", 1);
    check("pmd=tap\ndevice=pshost0\nip=192.0.2.2/32\n", 1);
    check("pmd=tap\ndevice=pshost0\nip=192.0.2.2/0\n", 1);
    const char *multi = "lcore=0\nno_huge=1\n[interface]\npmd=af_packet\ndevice=eth0\nip=192.0.2.2/24\n"
                        "[interface]\npmd=af_packet\ndevice=eth1\nip=198.51.100.2/24\n";
    check(multi, 1);
    check("[interface]\npmd=tap\ndevice=eth0\nip=192.0.2.2/24\n", 1);
    check("pmd=tap\ndevice=eth0\nip=192.0.2.2/24\n[interface]\n", 0);
    check("[interface]\n[interface]\npmd=tap\ndevice=eth1\nip=198.51.100.2/24\n", 0);
    check("[unknown]\npmd=tap\ndevice=eth0\nip=192.0.2.2/24\n", 0);
    const char *second[] = {
        "pmd=tap\ndevice=eth0\nip=198.51.100.2/24\n",
        "pmd=tap\ndevice=eth1\nip=192.0.2.2/24\n",
        "pmd=tap\ndevice=eth1\n",
        "pmd=tap\npmd=tap\ndevice=eth1\nip=198.51.100.2/24\n",
        "pmd=physical\ndevice=0000:00:13.0\nip=198.51.100.2/24\nno_huge=1\n"
    };
    for (unsigned i = 0; i < sizeof(second) / sizeof(second[0]); i++) {
        char text[512];
        snprintf(text, sizeof(text), "[interface]\npmd=tap\ndevice=eth0\nip=192.0.2.2/24\n[interface]\n%s", second[i]);
        check(text, 0);
    }
    char many[2048] = "";
    for (unsigned i = 0; i <= NETIF_MAX; i++) {
        char entry[128];
        snprintf(entry, sizeof(entry), "[interface]\npmd=tap\ndevice=eth%u\nip=10.%u.0.2/24\n", i, i);
        strcat(many, entry);
        if (i == NETIF_MAX - 1) check(many, 1);
    }
    check(many, 0);
    puts("config checks passed");
    return 0;
}
