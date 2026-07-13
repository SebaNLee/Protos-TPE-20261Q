#include "client/protocol.h"

#include <errno.h>
#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

int connect_server(const char *host, uint16_t port)
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
        return -1;

    for (struct addrinfo *cursor = result; cursor != NULL; cursor = cursor->ai_next)
    {
        fd = socket(cursor->ai_family, cursor->ai_socktype, cursor->ai_protocol);
        if (fd < 0)
            continue;
        if (connect(fd, cursor->ai_addr, cursor->ai_addrlen) == 0)
            break;
        close(fd);
        fd = -1;
    }
    freeaddrinfo(result);
    return fd;
}

static int write_all(int fd, const char *data)
{
    size_t total = 0;
    size_t len = strlen(data);

    while (total < len)
    {
        ssize_t n = write(fd, data + total, len - total);
        if (n < 0)
        {
            if (errno == EINTR)
                continue;
            return -1;
        }
        total += (size_t)n;
    }
    return 0;
}

int read_line(int fd, char *buf, size_t buf_len)
{
    size_t pos = 0;

    while (pos + 1 < buf_len)
    {
        ssize_t n = read(fd, buf + pos, 1);
        if (n == 0)
            return -1;
        if (n < 0)
        {
            if (errno == EINTR)
                continue;
            return -1;
        }
        if (buf[pos] == '\n')
        {
            buf[pos] = '\0';
            if (pos > 0 && buf[pos - 1] == '\r')
                buf[pos - 1] = '\0';
            return 0;
        }
        pos++;
    }
    return -1;
}

static int read_response(int fd, char lines[][MAX_RESP_LINE_LEN], int max_lines)
{
    char buf[LINE_BUF_SIZE];
    int count = 0;

    while (count < max_lines)
    {
        if (read_line(fd, buf, sizeof(buf)) < 0)
            return -1;

        if (strcmp(buf, ".") == 0)
            return count;

        strncpy(lines[count], buf, MAX_RESP_LINE_LEN - 1);
        lines[count][MAX_RESP_LINE_LEN - 1] = '\0';
        count++;
    }
    return count;
}

bool cmd_simple(int fd, const char *cmd, char *err, size_t err_sz)
{
    char lines[2][MAX_RESP_LINE_LEN];

    if (write_all(fd, cmd) < 0)
    {
        snprintf(err, err_sz, "Error de escritura");
        return false;
    }

    int n = read_response(fd, lines, 2);
    if (n < 1)
    {
        snprintf(err, err_sz, "Conexion perdida");
        return false;
    }

    if (lines[0][0] == '-' && lines[0][1] == 'E' &&
        lines[0][2] == 'R' && lines[0][3] == 'R')
    {
        const char *msg = lines[0][4] == ' ' ? lines[0] + 5 : lines[0] + 4;
        snprintf(err, err_sz, "%s", msg);
        return false;
    }

    return true;
}

bool cmd_auth(int fd, const char *user, const char *pass, char *err, size_t err_sz)
{
    char cmd[LINE_BUF_SIZE];
    snprintf(cmd, sizeof(cmd), "AUTH %s %s\n", user, pass);
    return cmd_simple(fd, cmd, err, err_sz);
}

bool cmd_stats(int fd, uint64_t *total, uint64_t *conc, uint64_t *bytes_up, uint64_t *bytes_down)
{
    char lines[2][MAX_RESP_LINE_LEN];

    if (write_all(fd, "STATS\n") < 0)
        return false;

    int n = read_response(fd, lines, 2);
    if (n < 1)
        return false;
    if (lines[0][0] == '-')
        return false;

    sscanf(lines[0],
           "+OK total_connections=%llu concurrent_connections=%llu "
           "bytes_up=%llu bytes_down=%llu",
           (unsigned long long *)total,
           (unsigned long long *)conc,
           (unsigned long long *)bytes_up,
           (unsigned long long *)bytes_down);
    return true;
}

int cmd_list(int fd, const char *cmd, char lines[][MAX_RESP_LINE_LEN], int max_lines)
{
    if (write_all(fd, cmd) < 0)
        return -1;
    return read_response(fd, lines, max_lines);
}

int cmd_access_log(int fd, const char *filter, char lines[][MAX_RESP_LINE_LEN], int max_lines)
{
    char cmd[LINE_BUF_SIZE];
    if (filter && filter[0])
        snprintf(cmd, sizeof(cmd), "ACCESS_LOG %s\n", filter);
    else
        snprintf(cmd, sizeof(cmd), "ACCESS_LOG\n");
    return cmd_list(fd, cmd, lines, max_lines);
}

bool cmd_config(int fd, const char *param, uint32_t value, char *err, size_t err_sz)
{
    char cmd[LINE_BUF_SIZE];
    snprintf(cmd, sizeof(cmd), "CONFIG %s %u\n", param, value);
    return cmd_simple(fd, cmd, err, err_sz);
}

bool cmd_add_user(int fd, const char *user, const char *pass, bool admin, char *err, size_t err_sz)
{
    char cmd[LINE_BUF_SIZE];
    if (admin)
        snprintf(cmd, sizeof(cmd), "ADD_USER %s %s admin\n", user, pass);
    else
        snprintf(cmd, sizeof(cmd), "ADD_USER %s %s\n", user, pass);
    return cmd_simple(fd, cmd, err, err_sz);
}

bool cmd_del_user(int fd, const char *user, char *err, size_t err_sz)
{
    char cmd[LINE_BUF_SIZE];
    snprintf(cmd, sizeof(cmd), "DEL_USER %s\n", user);
    return cmd_simple(fd, cmd, err, err_sz);
}

bool cmd_set_password(int fd, const char *user, const char *pass, char *err, size_t err_sz)
{
    char cmd[LINE_BUF_SIZE];
    snprintf(cmd, sizeof(cmd), "SET_PASSWORD %s %s\n", user, pass);
    return cmd_simple(fd, cmd, err, err_sz);
}

void cmd_quit(int fd)
{
    write_all(fd, "QUIT\n");
    char buf[LINE_BUF_SIZE];
    while (read_line(fd, buf, sizeof(buf)) == 0)
    {
        if (strcmp(buf, ".") == 0)
            break;
    }
}
