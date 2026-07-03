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
 * client/main.c — CLI de monitoreo del proxy.
 *
 * Este programa no habla SOCKS; se conecta al puerto de monitoreo (-p, default 8080)
 * y traduce subcomandos (stats, add-user, …) a líneas del protocolo wire.
 */

#define MONITOR_GREETING "+OK Hello! from Proxy/1.0"
#define LINE_BUF_SIZE 4096

static void usage(const char *program)
{
    fprintf(stderr,
            "Usage: %s -p port [-u user] [-w pass] <command> [args...]\n",
            program);
    fprintf(stderr, "Commands: stats, connections, users, config, access-log,\n");
    fprintf(stderr, "          add-user, del-user, set-password, help, quit\n");
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

/*
 * Autenticación transparente para el usuario del CLI.
 * El servidor manda el greeting primero; nosotros respondemos con AUTH.
 */
static int read_greeting(int fd)
{
    char line[LINE_BUF_SIZE];

    if (read_line(fd, line, sizeof(line)) < 0)
    {
        return -1;
    }
    if (strcmp(line, MONITOR_GREETING) != 0)
    {
        fprintf(stderr, "unexpected greeting: %s\n", line);
        return -1;
    }

    return 0;
}

/*
 * Autenticación transparente para el usuario del CLI.
 * El servidor manda el greeting primero; nosotros respondemos con AUTH.
 */
static int monitor_auth(int fd, const char *user, const char *pass)
{
    char line[LINE_BUF_SIZE];

    if (read_greeting(fd) < 0)
    {
        return -1;
    }

    char auth_cmd[LINE_BUF_SIZE];
    snprintf(auth_cmd, sizeof(auth_cmd), "AUTH %s %s\n", user, pass);
    if (write_all(fd, auth_cmd) < 0)
    {
        return -1;
    }

    if (read_line(fd, line, sizeof(line)) < 0)
    {
        return -1;
    }
    if (strcmp(line, "+OK") != 0)
    {
        fprintf(stderr, "auth failed: %s\n", line);
        return -1;
    }

    return 0;
}

/*
 * Convierte el subcomando del CLI (stats, add-user, …) en una línea wire,
 * la envía, hace half-close y imprime todas las respuestas del servidor.
 */
static int run_command(int fd, int argc, char **argv, int arg_start)
{
    char cmd[LINE_BUF_SIZE];

    if (arg_start >= argc)
    {
        usage(argv[0]);
        return EXIT_FAILURE;
    }

    const char *sub = argv[arg_start];

    if (strcmp(sub, "stats") == 0)
    {
        strcpy(cmd, "STATS\n");
    }
    else if (strcmp(sub, "connections") == 0)
    {
        strcpy(cmd, "CONNECTIONS\n");
    }
    else if (strcmp(sub, "users") == 0)
    {
        strcpy(cmd, "USERS\n");
    }
    else if (strcmp(sub, "config") == 0)
    {
        if (arg_start + 2 >= argc)
        {
            fprintf(stderr, "usage: config <param> <value>\n");
            return EXIT_FAILURE;
        }
        snprintf(cmd,
                 sizeof(cmd),
                 "CONFIG %s %s\n",
                 argv[arg_start + 1],
                 argv[arg_start + 2]);
    }
    else if (strcmp(sub, "access-log") == 0)
    {
        if (arg_start + 1 < argc)
        {
            snprintf(cmd, sizeof(cmd), "ACCESS_LOG %s\n", argv[arg_start + 1]);
        }
        else
        {
            strcpy(cmd, "ACCESS_LOG\n");
        }
    }
    else if (strcmp(sub, "add-user") == 0)
    {
        if (arg_start + 2 >= argc)
        {
            fprintf(stderr, "usage: add-user <user> <pass> [admin]\n");
            return EXIT_FAILURE;
        }
        if (arg_start + 3 < argc && strcmp(argv[arg_start + 3], "admin") == 0)
        {
            snprintf(cmd,
                     sizeof(cmd),
                     "ADD_USER %s %s admin\n",
                     argv[arg_start + 1],
                     argv[arg_start + 2]);
        }
        else
        {
            snprintf(cmd,
                     sizeof(cmd),
                     "ADD_USER %s %s\n",
                     argv[arg_start + 1],
                     argv[arg_start + 2]);
        }
    }
    else if (strcmp(sub, "del-user") == 0)
    {
        if (arg_start + 1 >= argc)
        {
            fprintf(stderr, "usage: del-user <user>\n");
            return EXIT_FAILURE;
        }
        snprintf(cmd, sizeof(cmd), "DEL_USER %s\n", argv[arg_start + 1]);
    }
    else if (strcmp(sub, "set-password") == 0)
    {
        if (arg_start + 2 >= argc)
        {
            fprintf(stderr, "usage: set-password <user> <pass>\n");
            return EXIT_FAILURE;
        }
        snprintf(cmd,
                 sizeof(cmd),
                 "SET_PASSWORD %s %s\n",
                 argv[arg_start + 1],
                 argv[arg_start + 2]);
    }
    else if (strcmp(sub, "help") == 0)
    {
        if (arg_start + 1 < argc)
        {
            snprintf(cmd, sizeof(cmd), "HELP %s\n", argv[arg_start + 1]);
        }
        else
        {
            strcpy(cmd, "HELP\n");
        }
    }
    else if (strcmp(sub, "quit") == 0)
    {
        strcpy(cmd, "QUIT\n");
    }
    else
    {
        fprintf(stderr, "unknown command: %s\n", sub);
        return EXIT_FAILURE;
    }

    if (write_all(fd, cmd) < 0)
    {
        return EXIT_FAILURE;
    }

    /* Half-close: el server procesa lo buffered y responde antes de cerrar */
    if (shutdown(fd, SHUT_WR) < 0)
    {
        return EXIT_FAILURE;
    }

    char line[LINE_BUF_SIZE];
    int exit_code = EXIT_SUCCESS;
    while (read_line(fd, line, sizeof(line)) == 0)
    {
        printf("%s\n", line);
        if (strncmp(line, "-ERR", 4) == 0)
        {
            exit_code = EXIT_FAILURE;
        }
    }

    return exit_code;
}

int main(int argc, char **argv)
{
    uint16_t port = 8080;
    const char *user = "admin";
    const char *pass = "admin";

    if (setup_flags(argc, argv, "p:u:w:h") != 0)
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
    if (has_flag('u'))
    {
        user = get_flag_str('u');
    }
    if (has_flag('w'))
    {
        pass = get_flag_str('w');
    }

    if (optind >= argc)
    {
        usage(argv[0]);
        return EXIT_FAILURE;
    }

    const int fd = connect_server("127.0.0.1", port);
    if (fd < 0)
    {
        fprintf(stderr, "connect failed: %s\n", strerror(errno));
        return EXIT_FAILURE;
    }

    const char *sub = argv[optind];
    const bool needs_auth = strcmp(sub, "help") != 0;

    if (needs_auth)
    {
        if (monitor_auth(fd, user, pass) < 0)
        {
            close(fd);
            return EXIT_FAILURE;
        }
    }
    else if (read_greeting(fd) < 0)
    {
        close(fd);
        return EXIT_FAILURE;
    }

    const int status = run_command(fd, argc, argv, optind);
    close(fd);
    return status;
}
