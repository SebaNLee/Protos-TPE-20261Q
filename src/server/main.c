#include "server/monitor/monitor.h"
#include "server/monitor/store.h"
#include "server/socks/socks.h"

/*
 * main.c — punto de entrada del servidor.
 *
 * Arquitectura:
 *   - Un solo thread con selector (campus)
 *   - Un monitor_store compartido entre SOCKS y monitoreo
 *   - Dos sockets pasivos en el mismo selector:
 *       -p 1080  → clientes SOCKS5
 *       -m 8080  → administradores (protocolo de texto)
 *
 * Graceful shutdown (SIGINT / SIGTERM):
 *   1. Primera señal → deja de aceptar conexiones nuevas
 *   2. El loop sigue hasta que no queden sesiones activas
 *   3. Segunda señal → salida inmediata (_exit)
 */

#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "shared/flags.h"

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
    fprintf(stderr, "Usage: %s [-p socks_port] [-m monitor_port] -u <user>:<pass>... -a <admin>:<pass>...\n", program);
    fprintf(stderr, "  -p  SOCKS5 port (default 1080)\n");
    fprintf(stderr, "  -m  Monitor port (default 8080)\n");
    fprintf(stderr, "  -u  Add SOCKS user:password pair (required, repeatable)\n");
    fprintf(stderr, "  -a  Add admin user:password pair for monitoring (required, repeatable)\n");
}

static bool servers_is_empty(struct socks_server *socks,
                             struct monitor_server *monitor)
{
    return socks_server_is_empty(socks) && monitor_server_is_empty(monitor);
}

static bool add_flag_user(struct monitor_store *store, const char *input, bool is_admin)
{
    char *colon = strchr(input, ':');

    if (colon == NULL || colon == input || *(colon + 1) == '\0')
    {
        return false;
    }

    *colon = '\0';
    store_user_add(store, input, colon + 1, is_admin);
    *colon = ':';

    return true;
}

int main(int argc, char **argv)
{
    uint16_t socks_port = 1080;
    uint16_t monitor_port = 8080;

    if (setup_flags(argc, argv, "p:m:hu:a:") != 0)
    {
        usage(argv[0]);
        return EXIT_FAILURE;
    }

    if (has_flag('h'))
    {
        usage(argv[0]);
        return EXIT_SUCCESS;
    }
    if (has_flag('p'))
    {
        const long value = get_flag_long('p');
        if (value <= 0 || value > 65535)
        {
            usage(argv[0]);
            return EXIT_FAILURE;
        }
        socks_port = (uint16_t)value;
    }
    if (has_flag('m'))
    {
        const long value = get_flag_long('m');
        if (value <= 0 || value > 65535)
        {
            usage(argv[0]);
            return EXIT_FAILURE;
        }
        monitor_port = (uint16_t)value;
    }

    if (get_flag_count('u') < 1 || get_flag_count('a') < 1)
    {
        usage(argv[0]);
        return EXIT_FAILURE;
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

    struct monitor_store *store = store_create();
    if (store == NULL)
    {
        fprintf(stderr, "store_create failed\n");
        selector_destroy(selector);
        selector_close();
        return EXIT_FAILURE;
    }

    for (int i = 0; i < get_flag_count('u'); i++)
    {
        if (!add_flag_user(store, get_flag_str_nth('u', i), false))
        {
            usage(argv[0]);
            store_destroy(store);
            selector_destroy(selector);
            selector_close();

            return EXIT_FAILURE;
        }
    }

    for (int i = 0; i < get_flag_count('a'); i++)
    {
        if (!add_flag_user(store, get_flag_str_nth('a', i), true))
        {
            usage(argv[0]);
            store_destroy(store);
            selector_destroy(selector);
            selector_close();

            return EXIT_FAILURE;
        }
    }

    volatile bool stop = false;
    struct socks_server *socks = NULL;
    struct monitor_server *monitor = NULL;

    if (socks_server_init(selector, socks_port, &stop, store, &socks) !=
        SELECTOR_SUCCESS)
    {
        fprintf(stderr, "socks_server_init failed: %s\n", strerror(errno));
        store_destroy(store);
        selector_destroy(selector);
        selector_close();
        return EXIT_FAILURE;
    }

    if (monitor_server_init(selector, monitor_port, &stop, store, &monitor) !=
        SELECTOR_SUCCESS)
    {
        fprintf(stderr, "monitor_server_init failed: %s\n", strerror(errno));
        socks_server_destroy(socks);
        store_destroy(store);
        selector_destroy(selector);
        selector_close();
        return EXIT_FAILURE;
    }

    while (!servers_is_empty(socks, monitor))
    {
        if (shutdown_requested)
        {
            stop = true;
        }

        if (stop)
        {
            socks_server_stop_accepting(socks);
            monitor_server_stop_accepting(monitor);
        }

        if (selector_select(selector) != SELECTOR_SUCCESS && errno != EINTR)
        {
            break;
        }

        if (force_quit)
        {
            break;
        }
    }

    monitor_server_destroy(monitor);
    socks_server_destroy(socks);
    store_destroy(store);
    selector_destroy(selector);
    selector_close();

    return EXIT_SUCCESS;
}
