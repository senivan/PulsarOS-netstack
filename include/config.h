#pragma once

#include <stddef.h>
#include "app.h"

void app_config_defaults(struct app_config *conf);
int app_config_load(const char *path, struct app_config *conf, char *err, size_t err_len);
