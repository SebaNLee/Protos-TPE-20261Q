#include <arpa/inet.h>
#include <check.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>

#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <unistd.h>

#include "monitor.h"
#include "monitor_commands.h"

/*
 * monitor_test.c — integración TCP del puerto de administración.
 *
 * Fork del servidor real, sockets de loopback, pipelining y half-close
 * (shutdown SHUT_WR + lectura hasta EOF con respuestas pendientes).
 */

static int connect_server(uint16_t port)
{
    const int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0)
    {
        return -1;
    }

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);

    if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0)
    {
        close(fd);
        return -1;
    }

    return fd;
}

static int read_line(int fd, char *buf, size_t buf_len)
{
    size_t pos = 0;

    while (pos + 1 < buf_len)
    {
        const ssize_t n = read(fd, buf + pos, 1);
        if (n < 0)
        {
            if (errno == EINTR)
            {
                continue;
            }
            return -1;
        }
        if (n == 0)
        {
            break;
        }
        if (buf[pos] == '\n')
        {
            buf[pos] = '\0';
            if (pos > 0 && buf[pos - 1] == '\r')
            {
                buf[pos - 1] = '\0';
            }
            return (int)pos;
        }
        pos++;
    }

    buf[pos] = '\0';
    return (int)pos;
}

static ssize_t read_until_eof(int fd, char *buf, size_t buf_len)
{
    size_t total = 0;

    while (total + 1 < buf_len)
    {
        const ssize_t n = read(fd, buf + total, buf_len - total - 1);
        if (n < 0)
        {
            if (errno == EINTR)
            {
                continue;
            }
            return -1;
        }
        if (n == 0)
        {
            break;
        }
        total += (size_t)n;
    }

    buf[total] = '\0';
    return (ssize_t)total;
}

static void run_server_child(int port_pipe_w, int stop_pipe_r)
{
    const struct selector_init conf = {
        .select_timeout = {.tv_sec = 1, .tv_nsec = 0},
    };

    if (selector_init(&conf) != SELECTOR_SUCCESS)
    {
        _exit(2);
    }

    fd_selector selector = selector_new(64);
    if (selector == NULL)
    {
        selector_close();
        _exit(3);
    }

    struct monitor_store *store = store_create();
    if (store == NULL)
    {
        selector_destroy(selector);
        selector_close();
        _exit(4);
    }
    store_user_add(store, "admin", "admin", true);

    volatile bool stop = false;
    struct monitor_server *server = NULL;

    if (monitor_server_init(selector, 0, &stop, store, &server) != SELECTOR_SUCCESS)
    {
        store_destroy(store);
        selector_destroy(selector);
        selector_close();
        _exit(5);
    }

    const uint16_t port = monitor_server_port(server);
    if (write(port_pipe_w, &port, sizeof(port)) != (ssize_t)sizeof(port))
    {
        monitor_server_destroy(server);
        store_destroy(store);
        selector_destroy(selector);
        selector_close();
        _exit(6);
    }

    close(port_pipe_w);

    const int flags = fcntl(stop_pipe_r, F_GETFL, 0);
    if (flags >= 0)
    {
        fcntl(stop_pipe_r, F_SETFL, flags | O_NONBLOCK);
    }

    alarm(10);

    while (!monitor_server_is_empty(server))
    {
        char byte = 0;
        const ssize_t n = read(stop_pipe_r, &byte, 1);
        if (n > 0)
        {
            stop = true;
        }

        if (monitor_server_run_once(server) != SELECTOR_SUCCESS && errno != EINTR)
        {
            break;
        }
    }

    monitor_server_destroy(server);
    store_destroy(store);
    selector_destroy(selector);
    selector_close();
    _exit(0);
}

static uint16_t start_server(pid_t *pid_out, int *stop_pipe_w_out)
{
    int port_pipe[2];
    int stop_pipe[2];

    ck_assert_int_eq(0, pipe(port_pipe));
    ck_assert_int_eq(0, pipe(stop_pipe));

    const pid_t pid = fork();
    ck_assert(pid >= 0);

    if (pid == 0)
    {
        close(port_pipe[0]);
        close(stop_pipe[1]);
        run_server_child(port_pipe[1], stop_pipe[0]);
    }

    close(port_pipe[1]);
    close(stop_pipe[0]);

    uint16_t port = 0;
    ck_assert_int_eq((ssize_t)sizeof(port), read(port_pipe[0], &port, sizeof(port)));
    close(port_pipe[0]);

    *pid_out = pid;
    *stop_pipe_w_out = stop_pipe[1];
    return port;
}

static void stop_server(pid_t pid, int stop_pipe_w)
{
    ck_assert_int_eq(1, write(stop_pipe_w, "x", 1));
    close(stop_pipe_w);

    int status = 0;
    ck_assert_int_eq(pid, waitpid(pid, &status, 0));
    ck_assert(WIFEXITED(status));
    ck_assert_int_eq(0, WEXITSTATUS(status));
}

static void assert_response_dot(int fd)
{
    char line[256];
    ck_assert_int_gt(read_line(fd, line, sizeof(line)), 0);
    ck_assert_str_eq(".", line);
}

START_TEST(test_tcp_greeting)
{
    pid_t pid = 0;
    int stop_w = -1;
    const uint16_t port = start_server(&pid, &stop_w);

    const int fd = connect_server(port);
    ck_assert_int_ge(fd, 0);

    char line[256];
    ck_assert_int_gt(read_line(fd, line, sizeof(line)), 0);
    ck_assert_str_eq("+OK ChungusMonitor v1.0", line);
    assert_response_dot(fd);

    close(fd);
    stop_server(pid, stop_w);
}
END_TEST

START_TEST(test_tcp_auth_and_stats)
{
    pid_t pid = 0;
    int stop_w = -1;
    const uint16_t port = start_server(&pid, &stop_w);

    const int fd = connect_server(port);
    ck_assert_int_ge(fd, 0);

    char line[512];
    read_line(fd, line, sizeof(line));
    assert_response_dot(fd);

    ck_assert_int_eq(17, write(fd, "AUTH admin admin\n", 17));
    ck_assert_int_gt(read_line(fd, line, sizeof(line)), 0);
    ck_assert_str_eq("+OK", line);
    assert_response_dot(fd);

    ck_assert_int_eq(6, write(fd, "STATS\n", 6));
    ck_assert_int_gt(read_line(fd, line, sizeof(line)), 0);
    ck_assert(strstr(line, "total_connections=") != NULL);
    assert_response_dot(fd);

    close(fd);
    stop_server(pid, stop_w);
}
END_TEST

START_TEST(test_tcp_pipelining)
{
    /* AUTH + STATS + QUIT en un solo write */
    pid_t pid = 0;
    int stop_w = -1;
    const uint16_t port = start_server(&pid, &stop_w);

    const int fd = connect_server(port);
    ck_assert_int_ge(fd, 0);

    char line[512];
    read_line(fd, line, sizeof(line));
    assert_response_dot(fd);

    const char *batch = "AUTH admin admin\nSTATS\nQUIT\n";
    ck_assert_int_eq((ssize_t)strlen(batch), write(fd, batch, strlen(batch)));

    ck_assert_int_gt(read_line(fd, line, sizeof(line)), 0);
    ck_assert_str_eq("+OK", line);
    assert_response_dot(fd);
    ck_assert_int_gt(read_line(fd, line, sizeof(line)), 0);
    ck_assert(strstr(line, "total_connections=") != NULL);
    assert_response_dot(fd);
    ck_assert_int_gt(read_line(fd, line, sizeof(line)), 0);
    ck_assert_str_eq("+OK", line);
    assert_response_dot(fd);

    close(fd);
    stop_server(pid, stop_w);
}
END_TEST

START_TEST(test_tcp_half_close)
{
    /* shutdown(SHUT_WR): el servidor drena wb antes de cerrar */
    pid_t pid = 0;
    int stop_w = -1;
    const uint16_t port = start_server(&pid, &stop_w);

    const int fd = connect_server(port);
    ck_assert_int_ge(fd, 0);

    char line[512];
    read_line(fd, line, sizeof(line));
    assert_response_dot(fd);

    const char *batch = "AUTH admin admin\nSTATS\n";
    ck_assert_int_eq((ssize_t)strlen(batch), write(fd, batch, strlen(batch)));
    shutdown(fd, SHUT_WR);

    char buf[1024];
    ck_assert_int_gt(read_until_eof(fd, buf, sizeof(buf)), 0);
    ck_assert(strstr(buf, "+OK") != NULL);
    ck_assert(strstr(buf, "total_connections=") != NULL);

    close(fd);
    stop_server(pid, stop_w);
}
END_TEST

START_TEST(test_tcp_add_user)
{
    pid_t pid = 0;
    int stop_w = -1;
    const uint16_t port = start_server(&pid, &stop_w);

    const int fd = connect_server(port);
    ck_assert_int_ge(fd, 0);

    char line[512];
    read_line(fd, line, sizeof(line));
    assert_response_dot(fd);

    const char *setup = "AUTH admin admin\nADD_USER cliuser clipass\n";
    ck_assert_int_eq((ssize_t)strlen(setup), write(fd, setup, strlen(setup)));

    read_line(fd, line, sizeof(line));
    ck_assert_str_eq("+OK", line);
    assert_response_dot(fd);
    read_line(fd, line, sizeof(line));
    ck_assert_str_eq("+OK", line);
    assert_response_dot(fd);
    close(fd);

    const int fd2 = connect_server(port);
    ck_assert_int_ge(fd2, 0);
    read_line(fd2, line, sizeof(line));
    assert_response_dot(fd2);

    const char *try_socks = "AUTH cliuser clipass\n";
    ck_assert_int_eq((ssize_t)strlen(try_socks), write(fd2, try_socks, strlen(try_socks)));
    read_line(fd2, line, sizeof(line));
    ck_assert_str_eq("-ERR not admin", line);
    assert_response_dot(fd2);

    close(fd2);
    stop_server(pid, stop_w);
}
END_TEST

Suite *monitor_suite(void)
{
    Suite *s = suite_create("monitor_server");

    TCase *tc = tcase_create("integration");
    tcase_set_timeout(tc, 10);
    tcase_add_test(tc, test_tcp_greeting);
    tcase_add_test(tc, test_tcp_auth_and_stats);
    tcase_add_test(tc, test_tcp_pipelining);
    tcase_add_test(tc, test_tcp_half_close);
    tcase_add_test(tc, test_tcp_add_user);
    suite_add_tcase(s, tc);

    return s;
}

int main(void)
{
    SRunner *sr = srunner_create(monitor_suite());
    srunner_run_all(sr, CK_NORMAL);
    const int n = srunner_ntests_failed(sr);
    srunner_free(sr);
    return n == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}
