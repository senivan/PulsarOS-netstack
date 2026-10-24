#pragma once

#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "ps_socket.h"

static volatile sig_atomic_t client_stopping;

static void client_stop(int signo)
{
    (void)signo;
    client_stopping = 1;
}

static void client_wait(void)
{
    struct timespec delay = { .tv_nsec = 1000000 };
    nanosleep(&delay, NULL);
}

static int client_options(int argc, char **argv, const char **path, uint16_t *port)
{
    *path = PS_DEFAULT_SOCKET;
    *port = 9000;
    for (int i = 1; i < argc; i += 2) {
        if (i + 1 == argc) return -EINVAL;
        if (!strcmp(argv[i], "--socket")) *path = argv[i + 1];
        else if (!strcmp(argv[i], "--port")) {
            char *end;
            errno = 0;
            unsigned long n = strtoul(argv[i + 1], &end, 10);
            if (errno || end == argv[i + 1] || *end || !n || n > UINT16_MAX) return -EINVAL;
            *port = (uint16_t)n;
        } else return -EINVAL;
    }
    signal(SIGINT, client_stop);
    signal(SIGTERM, client_stop);
    return 0;
}

static int client_error(const char *operation, int error)
{
    fprintf(stderr, "%s: %s (%d)\n", operation, strerror(-error), error);
    return 1;
}
