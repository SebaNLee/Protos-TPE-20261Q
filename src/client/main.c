#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "client/protocol.h"
#include "client/ui.h"
#include "shared/flags.h"

#define CFG_TIMEOUT_DEFAULT 0
#define CFG_MAX_CONN_DEFAULT 1024
#define CFG_IO_BUF_DEFAULT 4096

typedef struct
{
    const char *name;
    const char *label;
    uint32_t min;
    uint32_t max;
    uint32_t value;
} config_param;

static config_param params[3] = {
    {"timeout", "Max idle time (seconds)", 0, 86400, CFG_TIMEOUT_DEFAULT},
    {"max_connections", "Max concurrent conns", 1, 16384, CFG_MAX_CONN_DEFAULT},
    {"io_buffer_size", "I/O buffer size (bytes)", 1024, 65536, CFG_IO_BUF_DEFAULT},
};

static int config_count = 3;

static bool fetch_config_values(int fd)
{
    char err[MAX_RESP_LINE_LEN];

    for (int i = 0; i < config_count; i++)
    {
        uint32_t val = 0;
        if (!cmd_config_get(fd, params[i].name, &val, err, sizeof(err)))
        {
            return false;
        }
        params[i].value = val;
    }

    return true;
}

static bool screen_login(int fd);
static void screen_stats(int fd);
static void screen_connections(int fd);
static void screen_users(int fd);
static void screen_config(int fd);
static void screen_add_user(int fd);
static void screen_del_user(int fd);
static void screen_set_password(int fd);
static void screen_access_log(int fd);
static void screen_deny_host(int fd);
static void screen_deny_ip(int fd);
static void screen_undeny(int fd);
static void screen_deny_list(int fd);

typedef struct
{
    const char *label;
    void (*handler)(int fd);
} menu_item;

static menu_item main_menu[] = {
    {"Stats", screen_stats},
    {"Active connections", screen_connections},
    {"Registered users", screen_users},
    {"Configuration", screen_config},
    {"Add user", screen_add_user},
    {"Delete user", screen_del_user},
    {"Change password", screen_set_password},
    {"Access log", screen_access_log},
    {"Deny host", screen_deny_host},
    {"Deny IP", screen_deny_ip},
    {"Undeny", screen_undeny},
    {"Deny list", screen_deny_list},
    {"Quit", NULL},
};

static int menu_count = sizeof(main_menu) / sizeof(main_menu[0]);

static bool screen_login(int fd)
{
    char user[MAX_INPUT_LEN];
    char pass[MAX_INPUT_LEN];
    char err[MAX_RESP_LINE_LEN];

    printf("\033[s");

    while (1)
    {
        printf("\n");
        input_line("Username: ", user, sizeof(user));
        if (user[0] == '\0')
        {
            printf("\033[u\033[J");
            return false;
        }

        input_password("Password: ", pass, sizeof(pass));

        printf("Authenticating...\n");
        if (cmd_auth(fd, user, pass, err, sizeof(err)))
        {
            printf("\033[u\033[J");
            printf("User: %s\n", user);
            return true;
        }

        printf("Error: %s\n", err);
        printf("[Enter] Retry  [q] Quit\n");

        term_enter_raw();
        int key = term_getkey();
        term_exit_raw();

        if (key == 'q' || key == KEY_ESC)
            return false;
        printf("\033[u\033[J");
    }
}

static void screen_main_menu(int fd)
{
    const char *labels[menu_count];
    for (int i = 0; i < menu_count; i++)
        labels[i] = main_menu[i].label;

    while (1)
    {
        printf("\033[s");
        int opt = select_menu(labels, menu_count, "Quit");

        if (opt >= menu_count || opt < 0)
            return;

        if (main_menu[opt].handler == NULL)
            return;

        int n = menu_count + 3;
        printf("\033[%dA\033[J", n);
        main_menu[opt].handler(fd);
        printf("\033[u\033[J");
    }
}

static void screen_stats(int fd)
{
    uint64_t total = 0, conc = 0, up = 0, down = 0;

    printf("\nStats\n");
    if (!cmd_stats(fd, &total, &conc, &up, &down))
    {
        printf("  Error fetching stats\n");
    }
    else
    {
        printf("  %-22s %llu\n", "Total connections:", (unsigned long long)total);
        printf("  %-22s %llu\n", "Active connections:", (unsigned long long)conc);
        printf("  %-22s %llu\n", "Bytes uploaded:", (unsigned long long)up);
        printf("  %-22s %llu\n", "Bytes downloaded:", (unsigned long long)down);
    }

    wait_enter();
}

static void screen_connections(int fd)
{
    char lines[MAX_RESP_LINES][MAX_RESP_LINE_LEN];
    int count = cmd_connections(fd, lines, MAX_RESP_LINES);

    if (count < 0)
    {
        printf("\n  Error fetching connections\n");
    }
    else if (count == 1 && strcmp(lines[0], "+OK") == 0)
    {
        printf("\nActive connections\n  No active connections o7\n");
    }
    else
    {
        show_lines("Active connections", lines, count, 0);
    }

    wait_enter();
}

static void screen_users(int fd)
{
    char lines[MAX_RESP_LINES][MAX_RESP_LINE_LEN];
    int count = cmd_users(fd, lines, MAX_RESP_LINES);

    if (count < 0)
    {
        printf("\n  Error fetching users\n");
    }
    else
    {
        show_lines("Registered users", lines, count, 0);
    }

    wait_enter();
}

static void screen_config(int fd)
{
    char err[MAX_RESP_LINE_LEN];
    const char *labels[config_count + 1];
    char labels_buf[config_count][64];

    if (!fetch_config_values(fd))
    {
        printf("\n  Warning: could not refresh configuration from server\n");
        wait_enter();
        return;
    }

    while (1)
    {
        for (int i = 0; i < config_count; i++)
        {
            snprintf(labels_buf[i], sizeof(labels_buf[i]),
                     "%-30s [%u]", params[i].label, params[i].value);
            labels[i] = labels_buf[i];
        }
        labels[config_count] = "Back";

        printf("\033[s");
        int sel = select_menu(labels, config_count + 1, "Back");
        if (sel < 0 || sel >= config_count)
        {
            printf("\033[u\033[J");
            return;
        }

        int n = config_count + 4;
        printf("\033[%dA\033[J", n);
        printf("\n%s\n", params[sel].label);

        long val = input_number("  New value: ",
                                (long)params[sel].min,
                                (long)params[sel].max);

        printf("\n");
        if (cmd_config(fd, params[sel].name, (uint32_t)val, err, sizeof(err)))
        {
            params[sel].value = (uint32_t)val;
            printf("  Configuration updated o7\n");
        }
        else
        {
            printf("  Error: %s\n", err);
        }

        wait_enter();
        printf("\033[u\033[J");
    }
}

static void screen_add_user(int fd)
{
    char user[MAX_INPUT_LEN];
    char pass[MAX_INPUT_LEN];
    char err[MAX_RESP_LINE_LEN];

    printf("\nAdd user\n");
    input_line("  Username: ", user, sizeof(user));
    if (user[0] == '\0')
        return;

    input_password("  Password: ", pass, sizeof(pass));
    if (pass[0] == '\0')
        return;

    input_line("Admin? (y/n): ", err, sizeof(err));
    bool admin = (err[0] == 'y' || err[0] == 'Y');

    printf("\n");
    if (cmd_add_user(fd, user, pass, admin, err, sizeof(err)))
    {
        printf("  User created o7\n");
    }
    else
    {
        printf("  Error: %s\n", err);
    }

    wait_enter();
}

static void screen_del_user(int fd)
{
    char user[MAX_INPUT_LEN];
    char err[MAX_RESP_LINE_LEN];

    printf("\nDelete user\n");
    input_line("  Username: ", user, sizeof(user));
    if (user[0] == '\0')
        return;

    printf("  Delete '%s'? (y/N): ", user);
    fflush(stdout);
    char buf[64];
    fgets(buf, sizeof(buf), stdin);
    if (buf[0] != 'y' && buf[0] != 'Y')
    {
        printf("  Cancelled.\n");
        return;
    }

    printf("\n");
    if (cmd_del_user(fd, user, err, sizeof(err)))
    {
        printf("  User deleted o7\n");
    }
    else
    {
        printf("  Error: %s\n", err);
    }

    wait_enter();
}

static void screen_set_password(int fd)
{
    char user[MAX_INPUT_LEN];
    char pass[MAX_INPUT_LEN];
    char err[MAX_RESP_LINE_LEN];

    printf("\nChange password\n");
    input_line("  Username: ", user, sizeof(user));
    if (user[0] == '\0')
        return;

    input_password("  New password: ", pass, sizeof(pass));
    if (pass[0] == '\0')
        return;

    printf("\n");
    if (cmd_set_password(fd, user, pass, err, sizeof(err)))
    {
        printf("  Password updated o7\n");
    }
    else
    {
        printf("  Error: %s\n", err);
    }

    wait_enter();
}

static void screen_access_log(int fd)
{
    char lines[MAX_RESP_LINES][MAX_RESP_LINE_LEN];
    int count = cmd_access_log(fd, NULL, lines, MAX_RESP_LINES);

    if (count < 0)
    {
        printf("\n  Error fetching access log\n");
    }
    else
    {
        show_lines("Access log", lines, count, 1);
    }

    wait_enter();
}

static void screen_deny_host(int fd)
{
    char hostname[MAX_INPUT_LEN];
    char err[MAX_RESP_LINE_LEN];

    printf("\nDeny host\n");
    input_line("  Hostname: ", hostname, sizeof(hostname));
    if (hostname[0] == '\0')
        return;

    printf("\n");
    if (cmd_deny_host(fd, hostname, err, sizeof(err)))
    {
        printf("  Host denied o7\n");
    }
    else
    {
        printf("  Error: %s\n", err);
    }

    wait_enter();
}

static void screen_deny_ip(int fd)
{
    char ip[MAX_INPUT_LEN];
    char err[MAX_RESP_LINE_LEN];

    printf("\nDeny IP\n");
    input_line("  IP address: ", ip, sizeof(ip));
    if (ip[0] == '\0')
        return;

    printf("\n");
    if (cmd_deny_ip(fd, ip, err, sizeof(err)))
    {
        printf("  IP denied o7\n");
    }
    else
    {
        printf("  Error: %s\n", err);
    }

    wait_enter();
}

static void screen_undeny(int fd)
{
    char target[MAX_INPUT_LEN];
    char err[MAX_RESP_LINE_LEN];

    printf("\nUndeny\n");
    input_line("  Hostname or IP: ", target, sizeof(target));
    if (target[0] == '\0')
        return;

    printf("\n");
    if (cmd_undeny(fd, target, err, sizeof(err)))
    {
        printf("  Rule removed o7\n");
    }
    else
    {
        printf("  Error: %s\n", err);
    }

    wait_enter();
}

static void screen_deny_list(int fd)
{
    char lines[MAX_RESP_LINES][MAX_RESP_LINE_LEN];
    int count = cmd_deny_list(fd, lines, MAX_RESP_LINES);

    if (count < 0)
    {
        printf("\n  Error fetching deny list\n");
    }
    else
    {
        show_lines("Denied hosts and IPs", lines, count, 0);
    }

    wait_enter();
}

int main(int argc, char **argv)
{
    uint16_t port = 8080;

    if (setup_flags(argc, argv, "p:h") != 0)
    {
        fprintf(stderr, "Usage: %s [-p port]\n", argv[0]);
        return EXIT_FAILURE;
    }

    if (has_flag('h'))
    {
        fprintf(stderr, "Usage: %s [-p port]\n", argv[0]);
        return EXIT_SUCCESS;
    }

    if (has_flag('p'))
    {
        long value = get_flag_long('p');
        if (value <= 0 || value > 65535)
        {
            fprintf(stderr, "Usage: %s [-p port]\n", argv[0]);
            return EXIT_FAILURE;
        }
        port = (uint16_t)value;
    }

    printf("Connecting to 127.0.0.1:%u...\n", port);

    int fd = connect_server("127.0.0.1", port);
    if (fd < 0)
    {
        fprintf(stderr, "Error: %s\n", strerror(errno));
        return EXIT_FAILURE;
    }

    char buf[LINE_BUF_SIZE];
    while (read_line(fd, buf, sizeof(buf)) == 0)
    {
        if (strcmp(buf, ".") == 0)
            break;
    }

    printf("Connected.\n\n");

    printf("\033[3A\033[J");
    printf("ChungusMonitor v1.0 - 127.0.0.1:%u\n\033[?25l", port);

    if (!screen_login(fd))
    {
        close(fd);
        return EXIT_SUCCESS;
    }

    if (!fetch_config_values(fd))
    {
        fprintf(stderr, "Warning: could not load server configuration\n");
    }

    screen_main_menu(fd);

    printf("\033[?25h\nDisconnecting...\n");
    cmd_quit(fd);
    close(fd);
    return EXIT_SUCCESS;
}
