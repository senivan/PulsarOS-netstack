#include <arpa/inet.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <rte_cycles.h>
#include "config.h"
#include "runtime.h"

int main(int argc, char **argv)
{
    if (argc != 3) return 2;
    static struct app_runtime rt;
    struct app_config conf;
    struct ps_sockaddr peer = { .port = 9001 };
    char error[256];
    if (inet_pton(AF_INET, argv[2], &peer.ip_be) != 1 || app_config_load(argv[1], &conf, error, sizeof(error))) return 2;
    if (app_init(argv[0], &conf, &rt)) return 1;
    ps_fd_t fd = ps_socket(PS_AF_INET, PS_SOCK_STREAM, 0);
    int rc = 1;
    if (fd < 0 || ps_connect(fd, &peer) != -EINPROGRESS) goto done;
    uint8_t payload[5000], received[5000];
    for (unsigned i = 0; i < sizeof(payload); i++) payload[i] = (uint8_t)i;
    size_t sent = 0, read = 0;
    uint64_t start = rte_get_timer_cycles();
    while (rte_get_timer_cycles() - start < 15 * rte_get_timer_hz()) {
        app_step(&rt);
        if (sent < sizeof(payload)) {
            ssize_t n = ps_send(fd, payload + sent, sizeof(payload) - sent);
            if (n >= 0) sent += (size_t)n;
            else if (n != -EAGAIN && n != -ENOTCONN) goto done;
        }
        ssize_t n = ps_recv(fd, received + read, sizeof(received) - read);
        if (n > 0) read += (size_t)n;
        else if (n != -EAGAIN && n != -ENOTCONN) goto done;
        if (read != sizeof(payload)) continue;
        if (memcmp(received, payload, sizeof(payload))) goto done;
        ps_close(fd);
        fd = -1;
        start = rte_get_timer_cycles();
        while (rte_get_timer_cycles() - start < 2 * rte_get_timer_hz()) app_step(&rt);
        rc = 0;
        break;
    }
done:
    if (fd >= 0) ps_close(fd);
    app_dump_stats(&rt);
    app_fini(&rt);
    return rc;
}
