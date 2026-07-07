#include <errno.h>
#include <netdb.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <sys/socket.h>

#include "shared/flags.h"

/*
 * client/main.c — REPL de monitoreo del proxy.
 *
 * Se conecta al puerto de monitoreo (-p, default 8080) y permite
 * ejecutar comandos del protocolo ChugusMonitor a modo REPL.
 */

#define LINE_BUF_SIZE 4096

static void usage(const char *program)
{
    fprintf(stderr, "Usage: %s [-p port]\n", program);
}

static int connect_server(const char *host, uint16_t port)
{
    struct addrinfo hints = {
        .ai_family = AF_UNSPEC,
        .ai_socktype = SOCK_STREAM,
    };
    struct addrinfo *result = NULL;
    char port_str[8];
    int fd = -1;

    snprintf(port_str, sizeof(port_str), "%u", port);
    if (getaddrinfo(host, port_str, &hints, &result) != 0)
    {
        return -1;
    }

    for (struct addrinfo *cursor = result; cursor != NULL; cursor = cursor->ai_next)
    {
        fd = socket(cursor->ai_family, cursor->ai_socktype, cursor->ai_protocol);
        if (fd < 0)
        {
            continue;
        }
        if (connect(fd, cursor->ai_addr, cursor->ai_addrlen) == 0)
        {
            break;
        }
        close(fd);
        fd = -1;
    }

    freeaddrinfo(result);
    return fd;
}

/* Lee una línea del socket byte a byte hasta '\n' (soporta \r\n) */
static int read_line(int fd, char *buf, size_t buf_len)
{
    size_t pos = 0;

    while (pos + 1 < buf_len)
    {
        const ssize_t n = read(fd, buf + pos, 1);
        if (n == 0)
        {
            return -1;
        }
        if (n < 0)
        {
            if (errno == EINTR)
            {
                continue;
            }
            return -1;
        }
        if (buf[pos] == '\n')
        {
            buf[pos] = '\0';
            if (pos > 0 && buf[pos - 1] == '\r')
            {
                buf[pos - 1] = '\0';
            }
            return 0;
        }
        pos++;
    }

    return -1;
}

/* Escribe un buffer completo al socket (reintenta si EINTR) */
static int write_all(int fd, const char *data)
{
    size_t total = 0;
    const size_t len = strlen(data);

    while (total < len)
    {
        const ssize_t n = write(fd, data + total, len - total);
        if (n < 0)
        {
            if (errno == EINTR)
            {
                continue;
            }
            return -1;
        }
        total += (size_t)n;
    }

    return 0;
}

/* Lee todas las líneas de respuesta hasta el terminador ".\n" */
static int read_until_dot(int fd)
{
    char line[LINE_BUF_SIZE];

    while (read_line(fd, line, sizeof(line)) == 0)
    {
        if (strcmp(line, ".") == 0)
        {
            return 0;
        }

        printf("%s\n", line);
    }

    return -1;
}

int main(int argc, char **argv)
{
    uint16_t port = 8080;

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

    const int fd = connect_server("127.0.0.1", port);
    if (fd < 0)
    {
        fprintf(stderr, "connect failed: %s\n", strerror(errno));

        return EXIT_FAILURE;
    }

    // greeting
    char line[LINE_BUF_SIZE];
    if (read_line(fd, line, sizeof(line)) < 0)
    {
        fprintf(stderr, "connection closed\n");
        close(fd);

        return EXIT_FAILURE;
    }
    printf("%s\n", line);

    // REPL main loop
    while (true)
    {
        printf("monitor$ ");
        fflush(stdout);

        char input[LINE_BUF_SIZE];
        if (fgets(input, sizeof(input), stdin) == NULL)
        {
            printf("\n");

            break;
        }

        size_t len = strlen(input);
        while (len > 0 && (input[len - 1] == '\n' || input[len - 1] == '\r'))
        {
            input[--len] = '\0';
        }

        if (len == 0)
        {
            continue;
        }

        if (strcmp(input, "QUIT") == 0)
        {
            break;
        }

        input[len] = '\n';
        if (write_all(fd, input) < 0)
        {
            fprintf(stderr, "write error\n");

            break;
        }

        if (read_until_dot(fd) < 0)
        {
            fprintf(stderr, "connection lost\n");

            break;
        }
    }

    close(fd);
    return EXIT_SUCCESS;
}
