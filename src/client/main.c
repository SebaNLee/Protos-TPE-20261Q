#include <errno.h>
#include <netdb.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <termios.h>
#include <unistd.h>

#include "shared/flags.h"

/*
 * client/main.c — Cliente interactivo ChungusMonitor.
 *
 * Wizard por línea de comandos estilo "npm init". Sin ncurses,
 * sin raw mode permanente, sin ANSI codes de posicionamiento.
 * Contraseña con ECHO off momentáneo.
 */

/* ===========================================================================
 * Constantes
 * =========================================================================== */

#define LINE_BUF_SIZE 4096
#define MAX_RESP_LINES 512
#define MAX_RESP_LINE_LEN 256
#define MAX_INPUT_LEN 200

#define CFG_TIMEOUT_DEFAULT 0
#define CFG_MAX_CONN_DEFAULT 1024
#define CFG_IO_BUF_DEFAULT 4096

/* ===========================================================================
 * Raw mode para navegación del menú + SIGINT
 * =========================================================================== */

typedef enum
{
    KEY_NONE = 0,
    KEY_UP,
    KEY_DOWN,
    KEY_ENTER,
    KEY_ESC,
} key_code;

static struct termios saved_term;
static bool raw_active = false;

static void sigint_handler(int sig)
{
    (void)sig;
    tcsetattr(STDIN_FILENO, TCSANOW, &saved_term);
    _exit(1);
}

static void term_enter_raw(void)
{
    struct termios raw;
    tcgetattr(STDIN_FILENO, &saved_term);
    raw = saved_term;
    raw.c_lflag &= ~(ICANON | ECHO);
    raw.c_cc[VMIN] = 1;
    raw.c_cc[VTIME] = 0;
    tcsetattr(STDIN_FILENO, TCSAFLUSH, &raw);
    raw_active = true;
    signal(SIGINT, sigint_handler);
}

static void term_exit_raw(void)
{
    if (raw_active)
    {
        tcsetattr(STDIN_FILENO, TCSANOW, &saved_term);
        raw_active = false;
    }
}

static int term_getkey(void)
{
    char c;
    if (read(STDIN_FILENO, &c, 1) != 1)
        return KEY_NONE;
    if (c == '\033')
    {
        char seq[2];
        if (read(STDIN_FILENO, &seq[0], 1) != 1)
            return KEY_ESC;
        if (read(STDIN_FILENO, &seq[1], 1) != 1)
            return KEY_ESC;
        if (seq[0] == '[')
        {
            if (seq[1] == 'A')
                return KEY_UP;
            if (seq[1] == 'B')
                return KEY_DOWN;
        }
        return KEY_ESC;
    }
    if (c == '\n' || c == '\r')
        return KEY_ENTER;
    return (unsigned char)c;
}

/* ===========================================================================
 * Socket I/O
 * =========================================================================== */

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

static int read_line(int fd, char *buf, size_t buf_len)
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

/* ===========================================================================
 * Input helpers (wizard-style)
 * =========================================================================== */

static void input_line(const char *prompt, char *buf, size_t max)
{
    printf("%s", prompt);
    fflush(stdout);
    if (fgets(buf, (int)max, stdin) == NULL)
    {
        buf[0] = '\0';
        return;
    }
    size_t len = strlen(buf);
    while (len > 0 && (buf[len - 1] == '\n' || buf[len - 1] == '\r'))
        buf[--len] = '\0';
}

static void input_password(const char *prompt, char *buf, size_t max)
{
    struct termios old, noecho;
    tcgetattr(STDIN_FILENO, &old);
    saved_term = old;
    signal(SIGINT, sigint_handler);
    noecho = old;
    noecho.c_lflag &= ~ECHO;
    tcsetattr(STDIN_FILENO, TCSAFLUSH, &noecho);

    printf("%s", prompt);
    fflush(stdout);
    if (fgets(buf, (int)max, stdin) == NULL)
        buf[0] = '\0';

    tcsetattr(STDIN_FILENO, TCSAFLUSH, &old);

    size_t len = strlen(buf);
    while (len > 0 && (buf[len - 1] == '\n' || buf[len - 1] == '\r'))
        buf[--len] = '\0';
    printf("\n");
}

static long input_number(const char *prompt, long min, long max)
{
    char buf[64];
    while (1)
    {
        input_line(prompt, buf, sizeof(buf));
        char *end = NULL;
        long val = strtol(buf, &end, 10);
        if (*end == '\0' && val >= min && val <= max)
            return val;
        printf("  Valor invalido (rango %ld-%ld)\n", min, max);
    }
}

static void wait_enter(void)
{
    printf("\nPresione Enter para continuar...");
    fflush(stdout);
    char buf[64];
    fgets(buf, sizeof(buf), stdin);
}

/* Menú navegable con flechas arriba/abajo + Enter.
 * count incluye "Salir" como último ítem.
 * Devuelve el índice seleccionado (0-based). */
static int select_menu(const char *title, const char *items[], int count)
{
    int sel = 0;

    printf("\n--- %s ---\n", title);
    for (int i = 0; i < count; i++)
        printf("  %c %s\n", i == sel ? '>' : ' ', items[i]);
    printf("  [\xe2\x86\x91\xe2\x86\x93] Navegar  [Enter] Elegir  0. Salir\n");

    term_enter_raw();

    while (1)
    {
        int key = term_getkey();

        if (key == KEY_UP)
        {
            sel = (sel - 1 + count) % count;
        }
        else if (key == KEY_DOWN)
        {
            sel = (sel + 1) % count;
        }
        else if (key == KEY_ENTER)
        {
            term_exit_raw();
            return sel;
        }
        else if (key == KEY_ESC || key == '0')
        {
            term_exit_raw();
            return count - 1;
        }
        else
        {
            continue;
        }

        /* redibujar el menú en el mismo lugar */
        int n = count + 2;
        printf("\033[%dA", n);
        printf("\r\033[K--- %s ---\n", title);
        for (int i = 0; i < count; i++)
            printf("\r\033[K  %c %s\n", i == sel ? '>' : ' ', items[i]);
        printf("\r\033[K  [\xe2\x86\x91\xe2\x86\x93] Navegar  [Enter] Elegir  0. Salir\n");
    }
}

/* ===========================================================================
 * Capa de protocolo ChungusMonitor
 * =========================================================================== */

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

static bool cmd_simple(int fd, const char *cmd, char *err, size_t err_sz)
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

static bool cmd_auth(int fd, const char *user, const char *pass, char *err, size_t err_sz)
{
    char cmd[LINE_BUF_SIZE];
    snprintf(cmd, sizeof(cmd), "AUTH %s %s\n", user, pass);
    return cmd_simple(fd, cmd, err, err_sz);
}

static bool cmd_stats(int fd, uint64_t *total, uint64_t *conc,
                      uint64_t *bytes_up, uint64_t *bytes_down)
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

static int cmd_list(int fd, const char *cmd,
                    char lines[][MAX_RESP_LINE_LEN], int max_lines)
{
    if (write_all(fd, cmd) < 0)
        return -1;
    return read_response(fd, lines, max_lines);
}

#define cmd_connections(fd, l, m) cmd_list(fd, "CONNECTIONS\n", l, m)
#define cmd_users(fd, l, m) cmd_list(fd, "USERS\n", l, m)

static int cmd_access_log(int fd, const char *filter,
                          char lines[][MAX_RESP_LINE_LEN], int max_lines)
{
    char cmd[LINE_BUF_SIZE];
    if (filter && filter[0])
        snprintf(cmd, sizeof(cmd), "ACCESS_LOG %s\n", filter);
    else
        snprintf(cmd, sizeof(cmd), "ACCESS_LOG\n");
    return cmd_list(fd, cmd, lines, max_lines);
}

static bool cmd_config(int fd, const char *param, uint32_t value,
                       char *err, size_t err_sz)
{
    char cmd[LINE_BUF_SIZE];
    snprintf(cmd, sizeof(cmd), "CONFIG %s %u\n", param, value);
    return cmd_simple(fd, cmd, err, err_sz);
}

static bool cmd_add_user(int fd, const char *user, const char *pass,
                         bool admin, char *err, size_t err_sz)
{
    char cmd[LINE_BUF_SIZE];
    if (admin)
        snprintf(cmd, sizeof(cmd), "ADD_USER %s %s admin\n", user, pass);
    else
        snprintf(cmd, sizeof(cmd), "ADD_USER %s %s\n", user, pass);
    return cmd_simple(fd, cmd, err, err_sz);
}

static bool cmd_del_user(int fd, const char *user, char *err, size_t err_sz)
{
    char cmd[LINE_BUF_SIZE];
    snprintf(cmd, sizeof(cmd), "DEL_USER %s\n", user);
    return cmd_simple(fd, cmd, err, err_sz);
}

static bool cmd_set_password(int fd, const char *user, const char *pass,
                             char *err, size_t err_sz)
{
    char cmd[LINE_BUF_SIZE];
    snprintf(cmd, sizeof(cmd), "SET_PASSWORD %s %s\n", user, pass);
    return cmd_simple(fd, cmd, err, err_sz);
}

static void cmd_quit(int fd)
{
    write_all(fd, "QUIT\n");
    char buf[LINE_BUF_SIZE];
    while (read_line(fd, buf, sizeof(buf)) == 0)
    {
        if (strcmp(buf, ".") == 0)
            break;
    }
}

/* ===========================================================================
 * Helpers de visualización
 * =========================================================================== */

static const char *fmt_bytes(uint64_t bytes)
{
    static char buf[32];
    if (bytes >= 1073741824ULL)
        snprintf(buf, sizeof(buf), "%.1f GiB", (double)bytes / 1073741824.0);
    else if (bytes >= 1048576)
        snprintf(buf, sizeof(buf), "%.1f MiB", (double)bytes / 1048576.0);
    else if (bytes >= 1024)
        snprintf(buf, sizeof(buf), "%.1f KiB", (double)bytes / 1024.0);
    else
        snprintf(buf, sizeof(buf), "%llu B", (unsigned long long)bytes);
    return buf;
}

/* Muestra líneas de respuesta (strippeando +OK ) con un título */
static void show_lines(const char *title, char lines[][MAX_RESP_LINE_LEN], int count,
                       int skip)
{
    printf("\n--- %s ---\n", title);
    for (int i = skip; i < count; i++)
    {
        const char *line = lines[i];
        if (strncmp(line, "+OK ", 4) == 0)
            line += 4;
        printf("  %s\n", line);
    }
}

/* ===========================================================================
 * Pantallas
 * =========================================================================== */

/* --- Login --- */
static bool screen_login(int fd)
{
    char user[MAX_INPUT_LEN];
    char pass[MAX_INPUT_LEN];
    char err[MAX_RESP_LINE_LEN];

    printf("ChungusMonitor v1.0\n\n");

    while (1)
    {
        input_line("Usuario: ", user, sizeof(user));
        if (user[0] == '\0')
            return false;

        input_password("Contrasenia: ", pass, sizeof(pass));

        printf("Autenticando...\n");
        if (cmd_auth(fd, user, pass, err, sizeof(err)))
        {
            printf("Autenticacion exitosa.\n");
            return true;
        }

        printf("Error: %s\n", err);
        printf("[Enter] reintentar  [Ctrl+C] salir\n");
        char buf[64];
        fgets(buf, sizeof(buf), stdin);
    }
}

/* --- Main Menu --- */
typedef struct
{
    const char *label;
    void (*handler)(int fd);
} menu_item;

static void screen_stats(int fd);
static void screen_connections(int fd);
static void screen_users(int fd);
static void screen_config(int fd);
static void screen_add_user(int fd);
static void screen_del_user(int fd);
static void screen_set_password(int fd);
static void screen_access_log(int fd);

static menu_item main_menu[] = {
    {"Estadisticas", screen_stats},
    {"Conexiones activas", screen_connections},
    {"Usuarios registrados", screen_users},
    {"Configuracion", screen_config},
    {"Agregar usuario", screen_add_user},
    {"Eliminar usuario", screen_del_user},
    {"Cambiar contrasenia", screen_set_password},
    {"Log de accesos", screen_access_log},
    {"Salir", NULL},
};

static int menu_count = sizeof(main_menu) / sizeof(main_menu[0]);

static void screen_main_menu(int fd)
{
    const char *labels[menu_count];
    for (int i = 0; i < menu_count; i++)
        labels[i] = main_menu[i].label;

    while (1)
    {
        printf("\033[s");
        int opt = select_menu("Menu principal", labels, menu_count);

        if (opt >= menu_count || opt < 0)
            return;

        if (main_menu[opt].handler == NULL)
            return;

        printf("\n");
        main_menu[opt].handler(fd);
        printf("\033[u\033[J");
    }
}

/* --- Stats --- */
static void screen_stats(int fd)
{
    uint64_t total = 0, conc = 0, up = 0, down = 0;

    printf("\n");
    if (!cmd_stats(fd, &total, &conc, &up, &down))
    {
        printf("  Error al obtener estadisticas\n");
    }
    else
    {
        printf("  Conexiones totales:    %llu\n", (unsigned long long)total);
        printf("  Conexiones activas:    %llu\n", (unsigned long long)conc);
        printf("  Bytes subidos:         %s\n", fmt_bytes(up));
        printf("  Bytes bajados:         %s\n", fmt_bytes(down));
    }

    wait_enter();
}

/* --- Connections --- */
static void screen_connections(int fd)
{
    char lines[MAX_RESP_LINES][MAX_RESP_LINE_LEN];
    int count = cmd_connections(fd, lines, MAX_RESP_LINES);

    if (count < 0)
    {
        printf("  Error al obtener conexiones\n");
    }
    else
    {
        show_lines("Conexiones Activas", lines, count, 0);
    }

    wait_enter();
}

/* --- Users --- */
static void screen_users(int fd)
{
    char lines[MAX_RESP_LINES][MAX_RESP_LINE_LEN];
    int count = cmd_users(fd, lines, MAX_RESP_LINES);

    if (count < 0)
    {
        printf("  Error al obtener usuarios\n");
    }
    else
    {
        show_lines("Usuarios Registrados", lines, count, 0);
    }

    wait_enter();
}

/* --- Config (cache local de valores actuales) --- */
typedef struct
{
    const char *name;
    const char *label;
    uint32_t min;
    uint32_t max;
    uint32_t value;
} config_param;

static config_param params[3] = {
    {"timeout", "Tiempo maximo inactividad (s)", 0, 86400, CFG_TIMEOUT_DEFAULT},
    {"max_connections", "Maximo conexiones simultaneas", 1, 16384, CFG_MAX_CONN_DEFAULT},
    {"io_buffer_size", "Tamano buffer I/O (bytes)", 1024, 65536, CFG_IO_BUF_DEFAULT},
};

static int config_count = 3;

static void screen_config(int fd)
{
    char err[MAX_RESP_LINE_LEN];

    while (1)
    {
        printf("\n--- Configuracion ---\n");
        for (int i = 0; i < config_count; i++)
        {
            printf("  %d. %s [%u] (%u-%u)\n",
                   i + 1, params[i].label, params[i].value,
                   params[i].min, params[i].max);
        }
        printf("  0. Volver\n");

        long opt = input_number("Parametro: ", 0, config_count);
        if (opt == 0)
            return;

        int idx = (int)opt - 1;
        long val = input_number("Nuevo valor: ",
                                (long)params[idx].min,
                                (long)params[idx].max);

        if (cmd_config(fd, params[idx].name, (uint32_t)val, err, sizeof(err)))
        {
            params[idx].value = (uint32_t)val;
            printf("  OK\n");
        }
        else
        {
            printf("  Error: %s\n", err);
        }
    }
}

/* --- Add User --- */
static void screen_add_user(int fd)
{
    char user[MAX_INPUT_LEN];
    char pass[MAX_INPUT_LEN];
    char err[MAX_RESP_LINE_LEN];

    printf("\n");
    input_line("Usuario: ", user, sizeof(user));
    if (user[0] == '\0')
        return;

    input_password("Contrasenia: ", pass, sizeof(pass));
    if (pass[0] == '\0')
        return;

    input_line("Admin? (s/N): ", err, sizeof(err));
    bool admin = (err[0] == 's' || err[0] == 'S');

    if (cmd_add_user(fd, user, pass, admin, err, sizeof(err)))
    {
        printf("  Usuario creado exitosamente.\n");
    }
    else
    {
        printf("  Error: %s\n", err);
    }

    wait_enter();
}

/* --- Del User --- */
static void screen_del_user(int fd)
{
    char user[MAX_INPUT_LEN];
    char err[MAX_RESP_LINE_LEN];

    printf("\n");
    input_line("Usuario a eliminar: ", user, sizeof(user));
    if (user[0] == '\0')
        return;

    printf("  Confirmar eliminacion de '%s'? (s/N): ", user);
    fflush(stdout);
    char buf[64];
    fgets(buf, sizeof(buf), stdin);
    if (buf[0] != 's' && buf[0] != 'S')
    {
        printf("  Cancelado.\n");
        return;
    }

    if (cmd_del_user(fd, user, err, sizeof(err)))
    {
        printf("  Usuario eliminado.\n");
    }
    else
    {
        printf("  Error: %s\n", err);
    }

    wait_enter();
}

/* --- Set Password --- */
static void screen_set_password(int fd)
{
    char user[MAX_INPUT_LEN];
    char pass[MAX_INPUT_LEN];
    char err[MAX_RESP_LINE_LEN];

    printf("\n");
    input_line("Usuario: ", user, sizeof(user));
    if (user[0] == '\0')
        return;

    input_password("Nueva contrasenia: ", pass, sizeof(pass));
    if (pass[0] == '\0')
        return;

    if (cmd_set_password(fd, user, pass, err, sizeof(err)))
    {
        printf("  Contrasenia actualizada.\n");
    }
    else
    {
        printf("  Error: %s\n", err);
    }

    wait_enter();
}

/* --- Access Log --- */
static void screen_access_log(int fd)
{
    char filter[MAX_INPUT_LEN];
    printf("\n");
    input_line("Filtro de usuario (vacio = todos): ", filter, sizeof(filter));

    char lines[MAX_RESP_LINES][MAX_RESP_LINE_LEN];
    int count = cmd_access_log(fd, filter, lines, MAX_RESP_LINES);

    if (count < 0)
    {
        printf("  Error al obtener log de accesos\n");
    }
    else
    {
        show_lines("Log de Accesos", lines, count, 0);
    }

    wait_enter();
}

/* ===========================================================================
 * Main
 * =========================================================================== */

int main(int argc, char **argv)
{
    uint16_t port = 8080;

    if (setup_flags(argc, argv, "p:h") != 0)
    {
        fprintf(stderr, "Uso: %s [-p puerto]\n", argv[0]);
        return EXIT_FAILURE;
    }

    if (has_flag('h'))
    {
        fprintf(stderr, "Uso: %s [-p puerto]\n", argv[0]);
        return EXIT_SUCCESS;
    }

    if (has_flag('p'))
    {
        long value = get_flag_long('p');
        if (value <= 0 || value > 65535)
        {
            fprintf(stderr, "Uso: %s [-p puerto]\n", argv[0]);
            return EXIT_FAILURE;
        }
        port = (uint16_t)value;
    }

    printf("Conectando a 127.0.0.1:%u...\n", port);

    int fd = connect_server("127.0.0.1", port);
    if (fd < 0)
    {
        fprintf(stderr, "Error: %s\n", strerror(errno));
        return EXIT_FAILURE;
    }

    /* leer greeting */
    char buf[LINE_BUF_SIZE];
    while (read_line(fd, buf, sizeof(buf)) == 0)
    {
        if (strcmp(buf, ".") == 0)
            break;
    }

    printf("Conectado.\n\n");

    if (!screen_login(fd))
    {
        close(fd);
        return EXIT_SUCCESS;
    }

    screen_main_menu(fd);

    printf("\nDesconectando...\n");
    cmd_quit(fd);
    close(fd);
    return EXIT_SUCCESS;
}
