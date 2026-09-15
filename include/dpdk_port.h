#pragma once

#include "runtime.h"

int eal_init(const char *progname, const struct app_config *conf);
int port_init(const struct app_config *conf, struct app_runtime *rt);
void port_fini(struct app_runtime *rt);
