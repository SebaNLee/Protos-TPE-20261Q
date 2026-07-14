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
#include <sys/time.h>
#include <sys/wait.h>
#include <unistd.h>

#include "server/monitor/store.h"
#include "server/socks/socks.h"
#include "shared/selector.h"

/*
 * Simula el bug de la pre entrega:
 * un byte cada 200 ms que cruzan el límite greeting→auth (y auth→request) en un mismo read().
 * Sin drenar c2o tras el salto STM, el siguiente parser nunca corre.
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

static int set_recv_timeout(int fd, int sec)
{
    struct timeval tv = {.tv_sec = sec, .tv_usec = 0};
    return setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
}

static ssize_t read_exact(int fd, uint8_t *buf, size_t len)
{
    size_t got = 0;

    while (got < len)
    {
        const ssize_t n = read(fd, buf + got, len - got);
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
            return (ssize_t)got;
        }
        got += (size_t)n;
    }

    return (ssize_t)got;
}

static void write_all(int fd, const uint8_t *buf, size_t len)
{
    size_t sent = 0;

    while (sent < len)
    {
        const ssize_t n = write(fd, buf + sent, len - sent);
        ck_assert(n > 0);
        sent += (size_t)n;
    }
}

static void write_bytes_delayed(int fd, const uint8_t *buf, size_t len,
                                useconds_t delay_us)
{
    for (size_t i = 0; i < len; i++)
    {
        ck_assert_int_eq(1, write(fd, &buf[i], 1));
        if (delay_us > 0 && i + 1 < len)
        {
            usleep(delay_us);
        }
    }
}

static void run_server_child(int port_pipe_w, int stop_pipe_r)
{
    const struct selector_init conf = {
        .signal = SIGUSR1,
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
    store_user_add(store, "user", "pass", false);

    volatile bool stop = false;
    struct socks_server *server = NULL;

    if (socks_server_init(selector, 0, &stop, store, &server) != SELECTOR_SUCCESS)
    {
        store_destroy(store);
        selector_destroy(selector);
        selector_close();
        _exit(5);
    }

    const uint16_t port = socks_server_port(server);
    if (write(port_pipe_w, &port, sizeof(port)) != (ssize_t)sizeof(port))
    {
        socks_server_destroy(server);
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

    alarm(30);

    while (!socks_server_is_empty(server))
    {
        char byte = 0;
        const ssize_t n = read(stop_pipe_r, &byte, 1);
        if (n > 0)
        {
            stop = true;
        }

        socks_server_expire_idle(server);
        if (socks_server_run_once(server) != SELECTOR_SUCCESS && errno != EINTR)
        {
            break;
        }
    }

    socks_server_destroy(server);
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

/* greeting (user/pass) + RFC 1929 auth for user/pass */
static const uint8_t k_greeting_auth[] = {
    0x05,
    0x01,
    0x02, /* VER NMETHODS METHOD=0x02 */
    0x01,
    0x04,
    'u',
    's',
    'e',
    'r', /* VER ULEN UNAME */
    0x04,
    'p',
    'a',
    's',
    's', /* PLEN PASSWD */
};

static void assert_method_and_auth_ok(int fd)
{
    uint8_t method_reply[2];
    uint8_t auth_reply[2];

    ck_assert_int_eq(2, read_exact(fd, method_reply, 2));
    ck_assert_uint_eq(0x05, method_reply[0]);
    ck_assert_uint_eq(0x02, method_reply[1]);

    ck_assert_int_eq(2, read_exact(fd, auth_reply, 2));
    ck_assert_uint_eq(0x01, auth_reply[0]);
    ck_assert_uint_eq(0x00, auth_reply[1]);
}

START_TEST(test_coalesced_greeting_and_auth)
{
    pid_t pid = 0;
    int stop_w = -1;
    const uint16_t port = start_server(&pid, &stop_w);

    const int fd = connect_server(port);
    ck_assert_int_ge(fd, 0);
    ck_assert_int_eq(0, set_recv_timeout(fd, 5));

    write_all(fd, k_greeting_auth, sizeof(k_greeting_auth));
    assert_method_and_auth_ok(fd);

    close(fd);
    stop_server(pid, stop_w);
}
END_TEST

START_TEST(test_byte_at_a_time_200ms)
{
    pid_t pid = 0;
    int stop_w = -1;
    const uint16_t port = start_server(&pid, &stop_w);

    const int fd = connect_server(port);
    ck_assert_int_ge(fd, 0);
    ck_assert_int_eq(0, set_recv_timeout(fd, 10));

    write_bytes_delayed(fd, k_greeting_auth, sizeof(k_greeting_auth), 200000);
    assert_method_and_auth_ok(fd);

    close(fd);
    stop_server(pid, stop_w);
}
END_TEST

START_TEST(test_coalesced_through_connect)
{
    int dest_fd = socket(AF_INET, SOCK_STREAM, 0);
    ck_assert_int_ge(dest_fd, 0);

    int reuse = 1;
    setsockopt(dest_fd, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse));

    struct sockaddr_in dest_addr;
    memset(&dest_addr, 0, sizeof(dest_addr));
    dest_addr.sin_family = AF_INET;
    dest_addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    dest_addr.sin_port = 0;
    ck_assert_int_eq(0, bind(dest_fd, (struct sockaddr *)&dest_addr,
                             sizeof(dest_addr)));
    ck_assert_int_eq(0, listen(dest_fd, 1));

    socklen_t dest_len = sizeof(dest_addr);
    ck_assert_int_eq(0, getsockname(dest_fd, (struct sockaddr *)&dest_addr,
                                    &dest_len));
    const uint16_t dest_port = ntohs(dest_addr.sin_port);

    pid_t pid = 0;
    int stop_w = -1;
    const uint16_t socks_port = start_server(&pid, &stop_w);

    const int fd = connect_server(socks_port);
    ck_assert_int_ge(fd, 0);
    ck_assert_int_eq(0, set_recv_timeout(fd, 5));

    uint8_t msg[sizeof(k_greeting_auth) + 10];
    memcpy(msg, k_greeting_auth, sizeof(k_greeting_auth));
    size_t off = sizeof(k_greeting_auth);
    msg[off++] = 0x05; /* VER */
    msg[off++] = 0x01; /* CONNECT */
    msg[off++] = 0x00; /* RSV */
    msg[off++] = 0x01; /* IPv4 */
    msg[off++] = 127;
    msg[off++] = 0;
    msg[off++] = 0;
    msg[off++] = 1;
    msg[off++] = (uint8_t)(dest_port >> 8);
    msg[off++] = (uint8_t)(dest_port & 0xff);

    write_all(fd, msg, off);
    assert_method_and_auth_ok(fd);

    uint8_t connect_reply[10];
    ck_assert_int_eq(10, read_exact(fd, connect_reply, 10));
    ck_assert_uint_eq(0x05, connect_reply[0]);
    ck_assert_uint_eq(0x00, connect_reply[1]); /* succeeded */

    close(fd);
    close(dest_fd);
    stop_server(pid, stop_w);
}
END_TEST

Suite *socks_partial_suite(void)
{
    Suite *s = suite_create("socks_partial_read");

    TCase *tc = tcase_create("handshake");
    tcase_set_timeout(tc, 30);
    tcase_add_test(tc, test_coalesced_greeting_and_auth);
    tcase_add_test(tc, test_byte_at_a_time_200ms);
    tcase_add_test(tc, test_coalesced_through_connect);
    suite_add_tcase(s, tc);

    return s;
}

int main(void)
{
    SRunner *sr = srunner_create(socks_partial_suite());
    srunner_run_all(sr, CK_NORMAL);
    const int n = srunner_ntests_failed(sr);
    srunner_free(sr);
    return n == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}
