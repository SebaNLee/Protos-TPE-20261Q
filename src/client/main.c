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
    {"timeout", "Tiempo maximo inactividad (s)", 0, 86400, CFG_TIMEOUT_DEFAULT},
    {"max_connections", "Maximo conexiones simultaneas", 1, 16384, CFG_MAX_CONN_DEFAULT},
    {"io_buffer_size", "Tamano buffer I/O (bytes)", 1024, 65536, CFG_IO_BUF_DEFAULT},
};

static int config_count = 3;

static bool screen_login(int fd);
static void screen_stats(int fd);
static void screen_connections(int fd);
static void screen_users(int fd);
static void screen_config(int fd);
static void screen_add_user(int fd);
static void screen_del_user(int fd);
static void screen_set_password(int fd);
static void screen_access_log(int fd);

typedef struct
{
    const char *label;
    void (*handler)(int fd);
} menu_item;

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

static bool screen_login(int fd)
{
    char user[MAX_INPUT_LEN];
    char pass[MAX_INPUT_LEN];
    char err[MAX_RESP_LINE_LEN];

    printf("ChungusMonitor v1.0\n\n");

    while (1)
    {
        printf("\033[s");
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
