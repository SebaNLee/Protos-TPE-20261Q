/*
 * stress_client.c — generador de carga SOCKS5 para pruebas de estrés.
 *
 * Modos:
 *   connections  (-M connections) — abre N túneles concurrentes y reporta éxitos/fallos
 *   throughput   (-M throughput)  — N clientes transfieren -b bytes cada uno y mide MB/s
 *
 * Consulta métricas del monitor (STATS) antes y después si se indica -m / -A.
 */

#include <arpa/inet.h>
#include <errno.h>
#include <netdb.h>
#include <netinet/in.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include <sys/socket.h>
#include <sys/time.h>

#include "shared/flags.h"

#define STRESS_BUF_SIZE 65536
#define LINE_BUF_SIZE 4096

typedef enum
{
    STRESS_MODE_CONNECTIONS,
    STRESS_MODE_THROUGHPUT,
} stress_mode;

typedef struct stress_config
{
    const char *proxy_host;
    uint16_t proxy_port;
    const char *username;
    const char *password;
    const char *dest_host;
    uint16_t dest_port;
    const char *monitor_host;
    uint16_t monitor_port;
    const char *admin_user;
    const char *admin_pass;
    stress_mode mode;
    int clients;
    size_t bytes_per_client;
    int hold_seconds;
    bool query_monitor;
} stress_config;

typedef struct monitor_metrics
{
    uint64_t total_connections;
    uint64_t concurrent_connections;
    uint64_t bytes_up;
    uint64_t bytes_down;
    bool valid;
} monitor_metrics;

typedef struct worker_result
{
    atomic_int successes;
    atomic_int failures;
    atomic_uint_fast64_t bytes_sent;
    atomic_uint_fast64_t bytes_received;
} worker_result;

/* ------------------------------------------------------------------------- */
/* Utilidades de I/O bloqueante                                              */
/* ------------------------------------------------------------------------- */

static int write_all(int fd, const void *data, size_t len)
{
    const uint8_t *ptr = data;
    size_t total = 0;

    while (total < len)
    {
        const ssize_t n = write(fd, ptr + total, len - total);
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
            return -1;
        }
        total += (size_t)n;
    }

    return 0;
}

static int read_all(int fd, void *data, size_t len)
{
    uint8_t *ptr = data;
    size_t total = 0;

    while (total < len)
    {
        const ssize_t n = read(fd, ptr + total, len - total);
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
            return -1;
        }
        total += (size_t)n;
    }

    return 0;
}

static double now_seconds(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (double)ts.tv_sec + (double)ts.tv_nsec / 1e9;
}

static void usage(const char *program)
{
    fprintf(stderr,
            "Usage: %s -u user:pass -d host:port [options]\n"
            "  -H <host>       SOCKS proxy host (default 127.0.0.1)\n"
            "  -p <port>       SOCKS proxy port (default 1080)\n"
            "  -u <user:pass>  SOCKS credentials (required)\n"
            "  -d <host:port>  destination behind proxy (required)\n"
            "  -n <count>      number of concurrent clients (default 10)\n"
            "  -b <bytes>      bytes to send per client in throughput mode (default 65536)\n"
            "  -k <seconds>    hold connections open after handshake (connections mode)\n"
            "  -M <mode>       connections | throughput (default connections)\n"
            "  -m <port>       monitor port for STATS (default 8080)\n"
            "  -A <user:pass>  monitor admin credentials (enables STATS query)\n"
            "  -q              query monitor STATS before and after the run\n"
            "  -h              show this help\n",
            program);
}

/* ------------------------------------------------------------------------- */
/* Cliente SOCKS5 mínimo (RFC 1928 + RFC 1929)                               */
/* ------------------------------------------------------------------------- */

static int tcp_connect(const char *host, uint16_t port)
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

static bool parse_host_port(const char *input, char *host, size_t host_len, uint16_t *port)
{
    const char *colon = strrchr(input, ':');
    if (colon == NULL || colon == input || *(colon + 1) == '\0')
    {
        return false;
    }

    const size_t host_part = (size_t)(colon - input);
    if (host_part >= host_len)
    {
        return false;
    }

    memcpy(host, input, host_part);
    host[host_part] = '\0';

    char *end = NULL;
    const long value = strtol(colon + 1, &end, 10);
    if (end == colon + 1 || value <= 0 || value > 65535)
    {
        return false;
    }

    *port = (uint16_t)value;
    return true;
}

static bool parse_user_pass(const char *input, char *user, size_t user_len, char *pass, size_t pass_len)
{
    const char *colon = strchr(input, ':');
    if (colon == NULL || colon == input || *(colon + 1) == '\0')
    {
        return false;
    }

    const size_t user_part = (size_t)(colon - input);
    const size_t pass_part = strlen(colon + 1);
    if (user_part >= user_len || pass_part >= pass_len)
    {
        return false;
    }

    memcpy(user, input, user_part);
    user[user_part] = '\0';
    memcpy(pass, colon + 1, pass_part + 1);
    return true;
}

static int socks5_connect(const stress_config *cfg)
{
    const int fd = tcp_connect(cfg->proxy_host, cfg->proxy_port);
    if (fd < 0)
    {
        return -1;
    }

    const uint8_t greeting[] = {0x05, 0x01, 0x02};
    if (write_all(fd, greeting, sizeof(greeting)) < 0)
    {
        close(fd);
        return -1;
    }

    uint8_t method_resp[2];
    if (read_all(fd, method_resp, sizeof(method_resp)) < 0 || method_resp[0] != 0x05 ||
        method_resp[1] != 0x02)
    {
        close(fd);
        return -1;
    }

    const uint8_t ulen = (uint8_t)strlen(cfg->username);
    const uint8_t plen = (uint8_t)strlen(cfg->password);
    const uint8_t auth_ver_ulen[2] = {0x01, ulen};
    if (write_all(fd, auth_ver_ulen, sizeof(auth_ver_ulen)) < 0 ||
        write_all(fd, cfg->username, ulen) < 0 || write_all(fd, &plen, 1) < 0 ||
        write_all(fd, cfg->password, plen) < 0)
    {
        close(fd);
        return -1;
    }

    uint8_t auth_resp[2];
    if (read_all(fd, auth_resp, sizeof(auth_resp)) < 0 || auth_resp[0] != 0x01 || auth_resp[1] != 0x00)
    {
        close(fd);
        return -1;
    }

    struct in_addr dest_ipv4;
    if (inet_pton(AF_INET, cfg->dest_host, &dest_ipv4) != 1)
    {
        close(fd);
        return -1;
    }

    uint8_t request[10] = {
        0x05,
        0x01,
        0x00,
        0x01,
        0,
        0,
        0,
        0,
        0,
        0,
    };
    memcpy(request + 4, &dest_ipv4, sizeof(dest_ipv4));
    request[8] = (uint8_t)(cfg->dest_port >> 8);
    request[9] = (uint8_t)(cfg->dest_port & 0xff);

    if (write_all(fd, request, sizeof(request)) < 0)
    {
        close(fd);
        return -1;
    }

    uint8_t connect_resp[10];
    if (read_all(fd, connect_resp, sizeof(connect_resp)) < 0 || connect_resp[0] != 0x05 ||
        connect_resp[1] != 0x00)
    {
        close(fd);
        return -1;
    }

    return fd;
}

/* ------------------------------------------------------------------------- */
/* Monitor STATS                                                             */
/* ------------------------------------------------------------------------- */

static int read_line(int fd, char *buf, size_t buf_len)
{
    size_t pos = 0;

    while (pos + 1 < buf_len)
    {
        const ssize_t n = read(fd, buf + pos, 1);
        if (n <= 0)
        {
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

static int read_until_dot(int fd)
{
    char line[LINE_BUF_SIZE];

    while (read_line(fd, line, sizeof(line)) == 0)
    {
        if (strcmp(line, ".") == 0)
        {
            return 0;
        }
    }

    return -1;
}

static bool monitor_fetch_stats(const stress_config *cfg, monitor_metrics *out)
{
    out->valid = false;

    if (!cfg->query_monitor || cfg->admin_user == NULL || cfg->admin_pass == NULL)
    {
        return false;
    }

    const int fd = tcp_connect(cfg->monitor_host, cfg->monitor_port);
    if (fd < 0)
    {
        return false;
    }

    if (read_until_dot(fd) < 0)
    {
        close(fd);
        return false;
    }

    char auth_cmd[LINE_BUF_SIZE];
    snprintf(auth_cmd, sizeof(auth_cmd), "AUTH %s %s\n", cfg->admin_user, cfg->admin_pass);
    if (write_all(fd, auth_cmd, strlen(auth_cmd)) < 0 || read_until_dot(fd) < 0)
    {
        close(fd);
        return false;
    }

    const char stats_cmd[] = "STATS\n";
    if (write_all(fd, stats_cmd, sizeof(stats_cmd) - 1) < 0)
    {
        close(fd);
        return false;
    }

    char line[LINE_BUF_SIZE];
    if (read_line(fd, line, sizeof(line)) < 0)
    {
        close(fd);
        return false;
    }

    (void)read_until_dot(fd);
    close(fd);

    unsigned long long total = 0;
    unsigned long long concurrent = 0;
    unsigned long long up = 0;
    unsigned long long down = 0;

    if (sscanf(line,
               "+OK total_connections=%llu concurrent_connections=%llu bytes_up=%llu bytes_down=%llu",
               &total,
               &concurrent,
               &up,
               &down) != 4)
    {
        return false;
    }

    out->total_connections = total;
    out->concurrent_connections = concurrent;
    out->bytes_up = up;
    out->bytes_down = down;
    out->valid = true;
    return true;
}

static void print_monitor_metrics(const char *label, const monitor_metrics *m)
{
    if (!m->valid)
    {
        fprintf(stderr, "%s: monitor STATS unavailable\n", label);
        return;
    }

    fprintf(stderr,
            "%s: total=%llu concurrent=%llu bytes_up=%llu bytes_down=%llu\n",
            label,
            (unsigned long long)m->total_connections,
            (unsigned long long)m->concurrent_connections,
            (unsigned long long)m->bytes_up,
            (unsigned long long)m->bytes_down);
}

/* ------------------------------------------------------------------------- */
/* Workers                                                                   */
/* ------------------------------------------------------------------------- */

typedef struct worker_args
{
    const stress_config *cfg;
    worker_result *result;
    int worker_id;
    int clients_for_worker;
} worker_args;

static bool transfer_payload(int fd, size_t bytes)
{
    uint8_t buf[STRESS_BUF_SIZE];
    memset(buf, 0xA5, sizeof(buf));

    /* Ping-pong por chunks: evita deadlock al llenar buffers del túnel
     * cuando el eco devuelve datos mientras el cliente sigue escribiendo. */
    const size_t chunk_size = 4096;
    size_t remaining = bytes;

    while (remaining > 0)
    {
        const size_t chunk = remaining < chunk_size ? remaining : chunk_size;
        if (write_all(fd, buf, chunk) < 0)
        {
            return false;
        }
        if (read_all(fd, buf, chunk) < 0)
        {
            return false;
        }
        remaining -= chunk;
    }

    return true;
}

static void run_single_client(const stress_config *cfg, worker_result *result)
{
    const int fd = socks5_connect(cfg);
    if (fd < 0)
    {
        atomic_fetch_add(&result->failures, 1);
        return;
    }

    if (cfg->mode == STRESS_MODE_CONNECTIONS)
    {
        if (cfg->hold_seconds > 0)
        {
            sleep((unsigned)cfg->hold_seconds);
        }
        close(fd);
        atomic_fetch_add(&result->successes, 1);
        return;
    }

    if (cfg->bytes_per_client == 0)
    {
        close(fd);
        atomic_fetch_add(&result->successes, 1);
        return;
    }

    if (!transfer_payload(fd, cfg->bytes_per_client))
    {
        close(fd);
        atomic_fetch_add(&result->failures, 1);
        return;
    }

    atomic_fetch_add(&result->bytes_sent, cfg->bytes_per_client);
    atomic_fetch_add(&result->bytes_received, cfg->bytes_per_client);
    close(fd);
    atomic_fetch_add(&result->successes, 1);
}

static void *worker_thread(void *arg)
{
    worker_args *args = arg;

    for (int i = 0; i < args->clients_for_worker; i++)
    {
        run_single_client(args->cfg, args->result);
    }

    free(args);
    return NULL;
}

static int run_stress(const stress_config *cfg, worker_result *result)
{
    const int clients = cfg->clients;
    if (clients <= 0)
    {
        return -1;
    }

    const int thread_count = clients < 64 ? clients : 64;
    const int base = clients / thread_count;
    const int extra = clients % thread_count;

    pthread_t threads[64];
    int spawned = 0;

    for (int i = 0; i < thread_count; i++)
    {
        worker_args *args = malloc(sizeof(*args));
        if (args == NULL)
        {
            return -1;
        }

        args->cfg = cfg;
        args->result = result;
        args->worker_id = i;
        args->clients_for_worker = base + (i < extra ? 1 : 0);

        if (pthread_create(&threads[i], NULL, worker_thread, args) != 0)
        {
            free(args);
            break;
        }
        spawned++;
    }

    for (int i = 0; i < spawned; i++)
    {
        pthread_join(threads[i], NULL);
    }

    return spawned == thread_count ? 0 : -1;
}

/* ------------------------------------------------------------------------- */
/* main                                                                      */
/* ------------------------------------------------------------------------- */

int main(int argc, char **argv)
{
    stress_config cfg = {
        .proxy_host = "127.0.0.1",
        .proxy_port = 1080,
        .dest_host = NULL,
        .dest_port = 0,
        .monitor_host = "127.0.0.1",
        .monitor_port = 8080,
        .mode = STRESS_MODE_CONNECTIONS,
        .clients = 10,
        .bytes_per_client = 65536,
        .hold_seconds = 0,
        .query_monitor = false,
    };

    char user_buf[256];
    char pass_buf[256];
    char dest_host_buf[256];
    char admin_user_buf[256];
    char admin_pass_buf[256];
    char dest_input[300];
    char cred_input[300];
    char admin_input[300];

    if (setup_flags(argc, argv, "H:p:u:d:n:b:k:M:m:A:qh") != 0)
    {
        usage(argv[0]);
        return EXIT_FAILURE;
    }

    if (has_flag('h'))
    {
        usage(argv[0]);
        return EXIT_SUCCESS;
    }

    if (has_flag('H'))
    {
        cfg.proxy_host = get_flag_str('H');
    }

    if (has_flag('p'))
    {
        const long value = get_flag_long('p');
        if (value <= 0 || value > 65535)
        {
            usage(argv[0]);
            return EXIT_FAILURE;
        }
        cfg.proxy_port = (uint16_t)value;
    }

    if (!has_flag('u') || !has_flag('d'))
    {
        usage(argv[0]);
        return EXIT_FAILURE;
    }

    strncpy(cred_input, get_flag_str('u'), sizeof(cred_input) - 1);
    cred_input[sizeof(cred_input) - 1] = '\0';
    if (!parse_user_pass(cred_input, user_buf, sizeof(user_buf), pass_buf, sizeof(pass_buf)))
    {
        usage(argv[0]);
        return EXIT_FAILURE;
    }
    cfg.username = user_buf;
    cfg.password = pass_buf;

    strncpy(dest_input, get_flag_str('d'), sizeof(dest_input) - 1);
    dest_input[sizeof(dest_input) - 1] = '\0';
    if (!parse_host_port(dest_input, dest_host_buf, sizeof(dest_host_buf), &cfg.dest_port))
    {
        usage(argv[0]);
        return EXIT_FAILURE;
    }
    cfg.dest_host = dest_host_buf;

    if (has_flag('n'))
    {
        cfg.clients = (int)get_flag_long('n');
        if (cfg.clients <= 0)
        {
            usage(argv[0]);
            return EXIT_FAILURE;
        }
    }

    if (has_flag('b'))
    {
        const long value = get_flag_long('b');
        if (value < 0)
        {
            usage(argv[0]);
            return EXIT_FAILURE;
        }
        cfg.bytes_per_client = (size_t)value;
    }

    if (has_flag('k'))
    {
        cfg.hold_seconds = (int)get_flag_long('k');
        if (cfg.hold_seconds < 0)
        {
            usage(argv[0]);
            return EXIT_FAILURE;
        }
    }

    if (has_flag('M'))
    {
        const char *mode = get_flag_str('M');
        if (strcmp(mode, "connections") == 0)
        {
            cfg.mode = STRESS_MODE_CONNECTIONS;
        }
        else if (strcmp(mode, "throughput") == 0)
        {
            cfg.mode = STRESS_MODE_THROUGHPUT;
        }
        else
        {
            usage(argv[0]);
            return EXIT_FAILURE;
        }
    }

    if (has_flag('m'))
    {
        const long value = get_flag_long('m');
        if (value <= 0 || value > 65535)
        {
            usage(argv[0]);
            return EXIT_FAILURE;
        }
        cfg.monitor_port = (uint16_t)value;
    }

    if (has_flag('A'))
    {
        strncpy(admin_input, get_flag_str('A'), sizeof(admin_input) - 1);
        admin_input[sizeof(admin_input) - 1] = '\0';
        if (!parse_user_pass(admin_input, admin_user_buf, sizeof(admin_user_buf), admin_pass_buf,
                            sizeof(admin_pass_buf)))
        {
            usage(argv[0]);
            return EXIT_FAILURE;
        }
        cfg.admin_user = admin_user_buf;
        cfg.admin_pass = admin_pass_buf;
    }

    if (has_flag('q'))
    {
        cfg.query_monitor = true;
    }

    monitor_metrics before = {0};
    monitor_metrics after = {0};

    if (cfg.query_monitor)
    {
        monitor_fetch_stats(&cfg, &before);
        print_monitor_metrics("STATS before", &before);
    }

    worker_result result = {0};
    const double start = now_seconds();
    const int run_rc = run_stress(&cfg, &result);
    const double elapsed = now_seconds() - start;

    if (cfg.query_monitor)
    {
        monitor_fetch_stats(&cfg, &after);
        print_monitor_metrics("STATS after", &after);
    }

    const int ok = atomic_load(&result.successes);
    const int fail = atomic_load(&result.failures);
    const uint64_t sent = atomic_load(&result.bytes_sent);
    const uint64_t recv = atomic_load(&result.bytes_received);

    printf("mode=%s clients=%d elapsed=%.3fs successes=%d failures=%d\n",
           cfg.mode == STRESS_MODE_CONNECTIONS ? "connections" : "throughput",
           cfg.clients,
           elapsed,
           ok,
           fail);

    if (cfg.mode == STRESS_MODE_THROUGHPUT)
    {
        const double total_bytes = (double)(sent + recv);
        const double mbps = elapsed > 0.0 ? (total_bytes / elapsed) / (1024.0 * 1024.0) : 0.0;
        const double per_client_mbps =
            cfg.clients > 0 ? (mbps / (double)cfg.clients) : 0.0;

        printf("bytes_sent=%llu bytes_received=%llu throughput=%.2f MiB/s aggregate (%.2f MiB/s per client)\n",
               (unsigned long long)sent,
               (unsigned long long)recv,
               mbps,
               per_client_mbps);
    }

    if (cfg.query_monitor && before.valid && after.valid)
    {
        const uint64_t delta_up = after.bytes_up - before.bytes_up;
        const uint64_t delta_down = after.bytes_down - before.bytes_down;
        printf("monitor_delta_bytes_up=%llu monitor_delta_bytes_down=%llu peak_concurrent=%llu\n",
               (unsigned long long)delta_up,
               (unsigned long long)delta_down,
               (unsigned long long)after.concurrent_connections);
    }

    if (run_rc != 0)
    {
        fprintf(stderr, "warning: worker spawn incomplete\n");
    }

    return fail > 0 ? EXIT_FAILURE : EXIT_SUCCESS;
}
