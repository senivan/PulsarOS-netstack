#pragma once

#include <stdint.h>
#include "constants.h"

enum app_pmd { PMD_TAP, PMD_AFPKT, PMD_PHYS };

struct app_config {
    unsigned lcore;
    enum app_pmd pmd;
    char device[64]; /* Interface name for virtual PMDs; PCI BDF for physical. */
    uint32_t ip_be;
    uint8_t prefix_len;
    uint8_t no_huge;
    uint32_t mbufs, mbuf_cache;
    uint16_t rx_desc, tx_desc;
};
