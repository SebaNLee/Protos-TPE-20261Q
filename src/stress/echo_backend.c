/*
 * echo_backend.c — servidor TCP de eco simple para pruebas de estrés.
 *
 * Acepta conexiones concurrentes (un hilo por cliente) y devuelve
 * los mismos bytes recibidos. Pensado solo como destino controlado
 * detrás del proxy SOCKS5.
 */

#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <sys/socket.h>

#include "shared/flags.h"

#define ECHO_BUF_SIZE 65536

static volatile sig_atomic_t keep_running = 1;

static void on_signal(int signo)
{
    (void)signo;
    keep_running = 0;
}

static void usage(const char *program)
{
    fprintf(stderr, "Usage: %s [-p port] [-h]\n", program);
    fprintf(stderr, "  -p  listen port (default 9999)\n");
}

static ssize_t read_write_loop(int fd)
{
    uint8_t buf[ECHO_BUF_SIZE];
    ssize_t total = 0;

    while (keep_running)
    {
        const ssize_t n = read(fd, buf, sizeof(buf));
        if (n == 0)
        {
            break;
        }
        if (n < 0)
        {
            if (errno == EINTR)
            {
                continue;
            }
            return -1;
        }

        ssize_t sent = 0;
        while (sent < n)
        {
            const ssize_t w = write(fd, buf + sent, (size_t)(n - sent));
            if (w < 0)
            {
                if (errno == EINTR)
                {
                    continue;
                }
                return -1;
            }
            sent += w;
        }
        total += n;
    }

    return total;
}

struct client_ctx
{
    int fd;
};

static void *client_thread(void *arg)
{
    struct client_ctx *ctx = arg;
    (void)read_write_loop(ctx->fd);
    close(ctx->fd);
    free(ctx);
    return NULL;
}

static int spawn_client_handler(int client_fd)
{
    struct client_ctx *ctx = malloc(sizeof(*ctx));
    if (ctx == NULL)
    {
        close(client_fd);
        return -1;
    }

    ctx->fd = client_fd;

    pthread_t tid;
    pthread_attr_t attr;
    pthread_attr_init(&attr);
    pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);

    if (pthread_create(&tid, &attr, client_thread, ctx) != 0)
    {
        pthread_attr_destroy(&attr);
        free(ctx);
        close(client_fd);
        return -1;
    }

    pthread_attr_destroy(&attr);
    return 0;
}

static void install_signal_handlers(void)
{
    struct sigaction action = {
        .sa_handler = on_signal,
    };

    sigemptyset(&action.sa_mask);
    /* Sin SA_RESTART: accept() retorna EINTR y el loop puede salir. */
    sigaction(SIGINT, &action, NULL);
    sigaction(SIGTERM, &action, NULL);
}

int main(int argc, char **argv)
{
    uint16_t port = 9999;

    if (setup_flags(argc, argv, "p:h") != 0)
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
        port = (uint16_t)value;
    }

    install_signal_handlers();

    const int listen_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (listen_fd < 0)
    {
        perror("socket");
        return EXIT_FAILURE;
    }

    const int reuse = 1;
    if (setsockopt(listen_fd, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse)) < 0)
    {
        perror("setsockopt");
        close(listen_fd);
        return EXIT_FAILURE;
    }

    struct sockaddr_in addr = {
        .sin_family = AF_INET,
        .sin_addr.s_addr = htonl(INADDR_ANY),
        .sin_port = htons(port),
    };

    if (bind(listen_fd, (struct sockaddr *)&addr, sizeof(addr)) < 0)
    {
        perror("bind");
        close(listen_fd);
        return EXIT_FAILURE;
    }

    if (listen(listen_fd, SOMAXCONN) < 0)
    {
        perror("listen");
        close(listen_fd);
        return EXIT_FAILURE;
    }

    fprintf(stderr, "echo_backend listening on port %u\n", port);

    while (keep_running)
    {
        const int client_fd = accept(listen_fd, NULL, NULL);
        if (client_fd < 0)
        {
            if (errno == EINTR)
            {
                if (!keep_running)
                {
                    break;
                }
                continue;
            }
            perror("accept");
            break;
        }

        if (spawn_client_handler(client_fd) < 0)
        {
            fprintf(stderr, "failed to spawn client handler\n");
        }
    }

    close(listen_fd);
    return EXIT_SUCCESS;
}
