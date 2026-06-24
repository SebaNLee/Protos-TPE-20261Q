#include <arpa/inet.h>
#include <check.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <unistd.h>

#include "server/echo.h"

static int connect_to_server(uint16_t port)
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

static ssize_t read_all(int fd, uint8_t *buf, size_t len)
{
    size_t total = 0;

    while (total < len)
    {
        const ssize_t n = read(fd, buf + total, len - total);
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

    return (ssize_t)total;
}

static void run_server_child(int port_pipe_w, int stop_pipe_r)
{
    const struct selector_init conf = {
        .signal = SIGUSR1,
        .select_timeout = {.tv_sec = 0, .tv_nsec = 0},
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

    volatile bool stop = false;
    struct echo_server *server = NULL;

    if (echo_server_init(selector, 0, &stop, &server) != SELECTOR_SUCCESS)
    {
        selector_destroy(selector);
        selector_close();
        _exit(4);
    }

    const uint16_t port = echo_server_port(server);
    if (write(port_pipe_w, &port, sizeof(port)) != (ssize_t)sizeof(port))
    {
        echo_server_destroy(server);
        selector_destroy(selector);
        selector_close();
        _exit(5);
    }

    close(port_pipe_w);

    const int flags = fcntl(stop_pipe_r, F_GETFL, 0);
    if (flags >= 0)
    {
        fcntl(stop_pipe_r, F_SETFL, flags | O_NONBLOCK);
    }

    alarm(5);

    while (!echo_server_is_empty(server))
    {
        char byte = 0;
        const ssize_t n = read(stop_pipe_r, &byte, 1);
        if (n > 0)
        {
            stop = true;
        }

        if (echo_server_run_once(server) != SELECTOR_SUCCESS && errno != EINTR)
        {
            break;
        }
    }

    echo_server_destroy(server);
    selector_destroy(selector);
    selector_close();
    _exit(0);
}

static uint16_t start_server_process(pid_t *pid_out, int *stop_pipe_w_out)
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

static void stop_server_process(pid_t pid, int stop_pipe_w)
{
    ck_assert_int_eq(1, write(stop_pipe_w, "x", 1));
    close(stop_pipe_w);

    int status = 0;
    ck_assert_int_eq(pid, waitpid(pid, &status, 0));
    ck_assert(WIFEXITED(status));
    ck_assert_int_eq(0, WEXITSTATUS(status));
}

START_TEST(test_calc_interest_empty)
{
    struct echo_client client;
    buffer_init(&client.rb, ECHO_BUFFER_SIZE, client.backing);

    ck_assert_int_eq(OP_READ, echo_client_interest(&client));
}
END_TEST

START_TEST(test_calc_interest_pending)
{
    struct echo_client client;
    buffer_init(&client.rb, ECHO_BUFFER_SIZE, client.backing);

    size_t wbytes = 0;
    uint8_t *ptr = buffer_write_ptr(&client.rb, &wbytes);
    ck_assert(wbytes == ECHO_BUFFER_SIZE);

    memset(ptr, 'A', wbytes);
    buffer_write_adv(&client.rb, (ssize_t)wbytes);

    ck_assert_int_eq(OP_WRITE, echo_client_interest(&client));
}
END_TEST

START_TEST(test_calc_interest_both)
{
    struct echo_client client;
    buffer_init(&client.rb, ECHO_BUFFER_SIZE, client.backing);

    size_t wbytes = 0;
    uint8_t *ptr = buffer_write_ptr(&client.rb, &wbytes);
    ck_assert(wbytes == ECHO_BUFFER_SIZE);

    memset(ptr, 'B', ECHO_BUFFER_SIZE / 2);
    buffer_write_adv(&client.rb, (ssize_t)(ECHO_BUFFER_SIZE / 2));

    const fd_interest interest = echo_client_interest(&client);
    ck_assert_int_eq(OP_READ | OP_WRITE, interest);
}
END_TEST

START_TEST(test_echo_single_client)
{
    pid_t pid = 0;
    int stop_pipe_w = -1;
    const uint16_t port = start_server_process(&pid, &stop_pipe_w);

    const int client_fd = connect_to_server(port);
    ck_assert_int_ge(client_fd, 0);

    const char msg[] = "hola\n";
    ck_assert_int_eq((ssize_t)sizeof(msg) - 1, write(client_fd, msg, sizeof(msg) - 1));

    uint8_t response[16] = {0};
    ck_assert_int_eq((ssize_t)sizeof(msg) - 1,
                     read_all(client_fd, response, sizeof(msg) - 1));
    ck_assert_mem_eq(msg, response, sizeof(msg) - 1);

    close(client_fd);
    stop_server_process(pid, stop_pipe_w);
}
END_TEST

START_TEST(test_echo_two_clients)
{
    pid_t pid = 0;
    int stop_pipe_w = -1;
    const uint16_t port = start_server_process(&pid, &stop_pipe_w);

    const int client_a = connect_to_server(port);
    const int client_b = connect_to_server(port);
    ck_assert_int_ge(client_a, 0);
    ck_assert_int_ge(client_b, 0);

    const char msg_a[] = "cliente-a";
    const char msg_b[] = "cliente-b";

    ck_assert_int_eq((ssize_t)sizeof(msg_a) - 1,
                     write(client_a, msg_a, sizeof(msg_a) - 1));
    ck_assert_int_eq((ssize_t)sizeof(msg_b) - 1,
                     write(client_b, msg_b, sizeof(msg_b) - 1));

    uint8_t response_a[16] = {0};
    uint8_t response_b[16] = {0};

    ck_assert_int_eq((ssize_t)sizeof(msg_a) - 1,
                     read_all(client_a, response_a, sizeof(msg_a) - 1));
    ck_assert_int_eq((ssize_t)sizeof(msg_b) - 1,
                     read_all(client_b, response_b, sizeof(msg_b) - 1));

    ck_assert_mem_eq(msg_a, response_a, sizeof(msg_a) - 1);
    ck_assert_mem_eq(msg_b, response_b, sizeof(msg_b) - 1);

    close(client_a);
    close(client_b);
    stop_server_process(pid, stop_pipe_w);
}
END_TEST

START_TEST(test_echo_pipelining)
{
    pid_t pid = 0;
    int stop_pipe_w = -1;
    const uint16_t port = start_server_process(&pid, &stop_pipe_w);

    const int client_fd = connect_to_server(port);
    ck_assert_int_ge(client_fd, 0);

    const char msg[] = "ABCD";
    ck_assert_int_eq((ssize_t)sizeof(msg) - 1, write(client_fd, msg, sizeof(msg) - 1));

    uint8_t response[8] = {0};
    ck_assert_int_eq((ssize_t)sizeof(msg) - 1,
                     read_all(client_fd, response, sizeof(msg) - 1));
    ck_assert_mem_eq(msg, response, sizeof(msg) - 1);

    close(client_fd);
    stop_server_process(pid, stop_pipe_w);
}
END_TEST

Suite *echo_suite(void)
{
    Suite *s = suite_create("echo_server");

    TCase *tc_unit = tcase_create("unit");
    tcase_add_test(tc_unit, test_calc_interest_empty);
    tcase_add_test(tc_unit, test_calc_interest_pending);
    tcase_add_test(tc_unit, test_calc_interest_both);
    suite_add_tcase(s, tc_unit);

    TCase *tc_integration = tcase_create("integration");
    tcase_set_timeout(tc_integration, 10);
    tcase_add_test(tc_integration, test_echo_single_client);
    tcase_add_test(tc_integration, test_echo_two_clients);
    tcase_add_test(tc_integration, test_echo_pipelining);
    suite_add_tcase(s, tc_integration);

    return s;
}

int main(void)
{
    int number_failed = 0;
    SRunner *sr = srunner_create(echo_suite());

    srunner_run_all(sr, CK_NORMAL);
    number_failed = srunner_ntests_failed(sr);
    srunner_free(sr);

    return number_failed == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}
