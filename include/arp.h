#pragma once

#include <stdint.h>

struct app_runtime;
struct port_state;

void arp_request(struct app_runtime *, const struct port_state *, uint32_t target_ip_be);
