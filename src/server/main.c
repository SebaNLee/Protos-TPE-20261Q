#include "server/socks/socks.h"

#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static volatile sig_atomic_t shutdown_requested = 0;
static volatile sig_atomic_t force_quit = 0;

static void on_signal(int signo)
{
    (void)signo;

    if (shutdown_requested)
    {
        force_quit = 1;
        _exit(1);
    }

    shutdown_requested = 1;
}

static void install_signal_handlers(void)
{
    struct sigaction action = {
        .sa_handler = on_signal,
    };

    sigemptyset(&action.sa_mask);
    sigaction(SIGINT, &action, NULL);
    sigaction(SIGTERM, &action, NULL);
}

static void usage(const char *program)
{
    fprintf(stderr, "Usage: %s [-p port]\n", program);
}

static int parse_args(int argc, char **argv, uint16_t *port)
{
    int opt;

    *port = 1080;

    while ((opt = getopt(argc, argv, "p:h")) != -1)
    {
        switch (opt)
        {
        case 'p':
        {
            const long value = strtol(optarg, NULL, 10);
            if (value <= 0 || value > 65535)
            {
                return -1;
            }
            *port = (uint16_t)value;
            break;
        }
        case 'h':
            usage(argv[0]);
            return 1;
        default:
            usage(argv[0]);
            return -1;
        }
    }

    return 0;
}

int main(int argc, char **argv)
{
    uint16_t port = 1080;
    const int args_status = parse_args(argc, argv, &port);

    if (args_status != 0)
    {
        return args_status < 0 ? EXIT_FAILURE : EXIT_SUCCESS;
    }

    install_signal_handlers();

    const struct selector_init conf = {
        .signal = SIGUSR1,
        .select_timeout = {.tv_sec = 0, .tv_nsec = 0},
    };

    if (selector_init(&conf) != SELECTOR_SUCCESS)
    {
        fprintf(stderr, "selector_init failed\n");
        return EXIT_FAILURE;
    }

    fd_selector selector = selector_new(1024);
    if (selector == NULL)
    {
        fprintf(stderr, "selector_new failed\n");
        selector_close();
        return EXIT_FAILURE;
    }

    // entrypoint al socks server

    volatile bool stop = false;
    struct socks_server *server = NULL;

    if (socks_server_init(selector, port, &stop, &server) != SELECTOR_SUCCESS)
    {
        fprintf(stderr, "socks_server_init failed: %s\n", strerror(errno));
        selector_destroy(selector);
        selector_close();
        return EXIT_FAILURE;
    }

    // mientras haya conexiones activas atiende los pedidos de conexión
    while (!socks_server_is_empty(server))
    {
        if (shutdown_requested)
        {
            stop = true;
        }

        if (socks_server_run_once(server) != SELECTOR_SUCCESS && errno != EINTR)
        {
            break;
        }

        if (force_quit)
        {
            break;
        }
    }

    socks_server_destroy(server);
    selector_destroy(selector);
    selector_close();

    return EXIT_SUCCESS;
}
