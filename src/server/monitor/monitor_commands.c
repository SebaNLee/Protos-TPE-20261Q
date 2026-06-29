#include "monitor_commands.h"

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/*
 * monitor_commands.c — comandos del protocolo Proxy/1.0.
 *
 * Formato: texto línea a línea, termina con '\n' (acepta '\r\n').
 * monitor.c lee del socket → feed(); las respuestas van a wb.
 *
 * Pre-auth: AUTH, HELP. Post-auth: STATS, CONNECTIONS, USERS, CONFIG,
 * ACCESS_LOG, ADD_USER, DEL_USER, SET_PASSWORD, HELP, QUIT.
 */

typedef struct
{
    struct monitor_commands_session *session;
    const char *cmd;
    char *args[8];
    size_t argc;
} monitor_cmd;

/* ==========================================================================
 * Respuestas en wb (buffer de salida)
 * ========================================================================== */

/* Copia texto literal al buffer de respuestas wb. */
static bool commands_wb_append(struct monitor_commands_session *session, const char *text)
{
    const size_t len = strlen(text);
    size_t available = 0;
    uint8_t *ptr = buffer_write_ptr(&session->wb, &available);

    if (available < len)
    {
        /* wb lleno: la respuesta se descarta en silencio */
        return false;
    }

    memcpy(ptr, text, len);
    buffer_write_adv(&session->wb, (ssize_t)len);
    return true;
}

/* Formatea con printf y delega en commands_wb_append. */
static bool commands_wb_appendf(struct monitor_commands_session *session, const char *fmt, ...)
{
    char buf[MONITOR_BUFFER_SIZE];
    va_list ap;

    va_start(ap, fmt);
    const int n = vsnprintf(buf, sizeof(buf), fmt, ap);
    va_end(ap);

    if (n < 0 || (size_t)n >= sizeof(buf))
    {
        return false;
    }

    return commands_wb_append(session, buf);
}

/* Resetea estado de auth, línea y buffer de salida para una sesión nueva. */
void monitor_commands_session_init(struct monitor_commands_session *session,
                                   struct monitor_store *store)
{
    session->state = MONITOR_ST_AWAIT_AUTH;
    session->store = store;
    session->line_len = 0;
    session->close_after_flush = false;
    buffer_init(&session->wb, MONITOR_BUFFER_SIZE, session->wb_backing);
}

/* Encola el greeting Proxy/1.0 en wb (primera respuesta al conectar). */
void monitor_commands_queue_greeting(struct monitor_commands_session *session)
{
    commands_wb_append(session, MONITOR_COMMANDS_GREETING);
}

/* Lee hasta max bytes de wb para enviar al socket (write parcial). */
size_t monitor_commands_wb_read(struct monitor_commands_session *session,
                                uint8_t *out,
                                size_t max)
{
    size_t pending = 0;
    const uint8_t *ptr = buffer_read_ptr(&session->wb, &pending);
    const size_t n = pending < max ? pending : max;

    if (n > 0)
    {
        memcpy(out, ptr, n);
        buffer_read_adv(&session->wb, (ssize_t)n);
        buffer_compact(&session->wb);
    }

    return n;
}

/* true si QUIT ya vació wb y la conexión puede cerrarse. */
bool monitor_commands_should_close(const struct monitor_commands_session *session)
{
    return session->close_after_flush && !buffer_can_read((buffer *)&session->wb);
}

/* Parte una línea en comando y argumentos (máx. 8 tokens). */
static void split_line(monitor_cmd *cmd, char *line)
{
    cmd->argc = 0;
    char *saveptr = NULL;
    char *token = strtok_r(line, " ", &saveptr);

    while (token != NULL && cmd->argc < 8)
    {
        cmd->args[cmd->argc++] = token;
        token = strtok_r(NULL, " ", &saveptr);
    }

    cmd->cmd = cmd->argc > 0 ? cmd->args[0] : "";
}

/* ==========================================================================
 * Handlers de comandos Proxy/1.0
 * ========================================================================== */

/* AUTH: valida admin contra store y pasa a MONITOR_ST_AUTHENTICATED. */
static void handle_auth(struct monitor_commands_session *session, monitor_cmd *cmd)
{
    if (session->state == MONITOR_ST_AUTHENTICATED)
    {
        commands_wb_append(session, "-ERR already authenticated\n");
        return;
    }

    if (cmd->argc < 3)
    {
        commands_wb_append(session, "-ERR syntax error\n");
        return;
    }

    const store_auth_result result =
        store_admin_authenticate(session->store, cmd->args[1], cmd->args[2]);

    switch (result)
    {
    case STORE_AUTH_OK:
        session->state = MONITOR_ST_AUTHENTICATED;
        commands_wb_append(session, "+OK\n");
        break;
    case STORE_AUTH_NOT_ADMIN:
        commands_wb_append(session, "-ERR not admin\n");
        break;
    case STORE_AUTH_INVALID:
    default:
        commands_wb_append(session, "-ERR invalid credentials\n");
        break;
    }
}

/* STATS: devuelve métricas globales del store en una línea +OK. */
static void handle_stats(struct monitor_commands_session *session)
{
    store_metrics metrics;

    store_metrics_get(session->store, &metrics);
    commands_wb_appendf(session,
                        "+OK total_connections=%llu concurrent_connections=%llu "
                        "bytes_up=%llu bytes_down=%llu\n",
                        (unsigned long long)metrics.total_connections,
                        (unsigned long long)metrics.concurrent_connections,
                        (unsigned long long)metrics.bytes_up,
                        (unsigned long long)metrics.bytes_down);
}

typedef struct
{
    struct monitor_commands_session *session;
} conn_ctx;

/* Callback: emite una línea +OK por sesión SOCKS activa. */
static bool append_connection(const store_active_session *s, void *ctx)
{
    conn_ctx *cctx = ctx;

    commands_wb_appendf(cctx->session,
                        "+OK %s %s:%u %s %llu %llu\n",
                        s->username[0] != '\0' ? s->username : "-",
                        s->host[0] != '\0' ? s->host : "-",
                        s->port,
                        store_session_phase_str(s->phase),
                        (unsigned long long)s->bytes_up,
                        (unsigned long long)s->bytes_down);
    return true;
}

/* Callback: marca que hay al menos una sesión activa. */
static bool count_connection(const store_active_session *s, void *ctx)
{
    (void)s;
    *(bool *)ctx = true;
    return true;
}

/* Dos pasadas: si no hay sesiones activas → +OK\n; si hay → una línea por sesión */
static void handle_connections(struct monitor_commands_session *session)
{
    conn_ctx ctx = {.session = session};
    bool any = false;

    store_sessions_foreach(session->store, count_connection, &any);
    if (!any)
    {
        commands_wb_append(session, "+OK\n");
        return;
    }

    store_sessions_foreach(session->store, append_connection, &ctx);
}

typedef struct
{
    struct monitor_commands_session *session;
} user_ctx;

/* Callback: emite una línea +OK por username único conectado. */
static bool append_user(const char *username, void *ctx)
{
    user_ctx *uctx = ctx;
    commands_wb_appendf(uctx->session, "+OK %s\n", username);
    return true;
}

/* Callback: marca que hay al menos un usuario conectado. */
static bool count_user(const char *username, void *ctx)
{
    (void)username;
    *(bool *)ctx = true;
    return true;
}

/* Dos pasadas: si no hay usuarios conectados → +OK\n; si hay → una línea por usuario */
static void handle_users(struct monitor_commands_session *session)
{
    user_ctx ctx = {.session = session};
    bool any = false;

    store_active_usernames_foreach(session->store, count_user, &any);
    if (!any)
    {
        commands_wb_append(session, "+OK\n");
        return;
    }

    store_active_usernames_foreach(session->store, append_user, &ctx);
}

/*
 * Valida rangos en la capa protocolo; store_config_set repite límites en el store.
 * Params: timeout (0..86400), max_connections (1..65535), io_buffer_size (1024..65536).
 */
static void handle_config(struct monitor_commands_session *session, monitor_cmd *cmd)
{
    store_config_key key;
    char *end = NULL;

    if (cmd->argc < 3)
    {
        commands_wb_append(session, "-ERR syntax error\n");
        return;
    }

    if (!store_config_key_from_name(cmd->args[1], &key))
    {
        commands_wb_append(session, "-ERR unknown param\n");
        return;
    }

    const long value = strtol(cmd->args[2], &end, 10);
    if (end == cmd->args[2] || *end != '\0' || value < 0)
    {
        commands_wb_append(session, "-ERR invalid value\n");
        return;
    }

    if (strcmp(cmd->args[1], "timeout") == 0 && value > 86400)
    {
        commands_wb_append(session, "-ERR invalid value\n");
        return;
    }
    if (strcmp(cmd->args[1], "max_connections") == 0 &&
        (value < 1 || value > 65535))
    {
        commands_wb_append(session, "-ERR invalid value\n");
        return;
    }
    if (strcmp(cmd->args[1], "io_buffer_size") == 0 &&
        (value < 1024 || value > 65536))
    {
        commands_wb_append(session, "-ERR invalid value\n");
        return;
    }

    switch (store_config_set(session->store, key, (uint32_t)value))
    {
    case STORE_CFG_OK:
        commands_wb_append(session, "+OK\n");
        break;
    case STORE_CFG_UNKNOWN_KEY:
        commands_wb_append(session, "-ERR unknown param\n");
        break;
    case STORE_CFG_INVALID_VALUE:
    default:
        commands_wb_append(session, "-ERR invalid value\n");
        break;
    }
}

typedef struct
{
    struct monitor_commands_session *session;
} log_ctx;

/* Callback: emite una entrada del access log en formato +OK. */
static bool append_log_entry(const store_log_entry *entry, void *ctx)
{
    log_ctx *lctx = ctx;

    commands_wb_appendf(lctx->session,
                        "+OK %s: %s:%u %s %s\n",
                        entry->username,
                        entry->host,
                        entry->port,
                        entry->timestamp,
                        store_log_state_str(entry->state));
    return true;
}

/* filter opcional por username; si se pasa, debe existir en la tabla de usuarios */
static void handle_access_log(struct monitor_commands_session *session, monitor_cmd *cmd)
{
    const char *filter = cmd->argc >= 2 ? cmd->args[1] : NULL;
    log_ctx ctx = {.session = session};

    if (filter != NULL && !store_user_exists(session->store, filter))
    {
        commands_wb_append(session, "-ERR user not found\n");
        return;
    }

    if (filter == NULL)
    {
        commands_wb_append(session, "+OK Access log for all users:\n");
    }
    else
    {
        commands_wb_appendf(session, "+OK Access log for user %s:\n", filter);
    }

    store_log_foreach(session->store, filter, append_log_entry, &ctx);
}

/* ADD_USER: crea usuario SOCKS (opcional rol admin). */
static void handle_add_user(struct monitor_commands_session *session, monitor_cmd *cmd)
{
    const bool is_admin = cmd->argc >= 4 && strcmp(cmd->args[3], "admin") == 0;

    if (cmd->argc < 3)
    {
        commands_wb_append(session, "-ERR syntax error\n");
        return;
    }

    switch (store_user_add(session->store, cmd->args[1], cmd->args[2], is_admin))
    {
    case STORE_USER_OK:
        commands_wb_append(session, "+OK\n");
        break;
    case STORE_USER_EXISTS:
        commands_wb_append(session, "-ERR user exists\n");
        break;
    case STORE_USER_TABLE_FULL:
        commands_wb_append(session, "-ERR user table full\n");
        break;
    default:
        commands_wb_append(session, "-ERR syntax error\n");
        break;
    }
}

/* DEL_USER: borra usuario; rechaza si es el último admin. */
static void handle_del_user(struct monitor_commands_session *session, monitor_cmd *cmd)
{
    if (cmd->argc < 2)
    {
        commands_wb_append(session, "-ERR syntax error\n");
        return;
    }

    switch (store_user_delete(session->store, cmd->args[1]))
    {
    case STORE_USER_OK:
        commands_wb_append(session, "+OK\n");
        break;
    case STORE_USER_NOT_FOUND:
        commands_wb_append(session, "-ERR user not found\n");
        break;
    case STORE_USER_LAST_ADMIN:
        commands_wb_append(session, "-ERR cannot delete last admin\n");
        break;
    default:
        commands_wb_append(session, "-ERR syntax error\n");
        break;
    }
}

/* SET_PASSWORD: cambia la contraseña de un usuario existente. */
static void handle_set_password(struct monitor_commands_session *session, monitor_cmd *cmd)
{
    if (cmd->argc < 3)
    {
        commands_wb_append(session, "-ERR syntax error\n");
        return;
    }

    if (store_user_set_password(session->store, cmd->args[1], cmd->args[2]) ==
        STORE_USER_OK)
    {
        commands_wb_append(session, "+OK\n");
    }
    else
    {
        commands_wb_append(session, "-ERR user not found\n");
    }
}

/* HELP: lista comandos o describe uno puntual. */
static void handle_help(struct monitor_commands_session *session, monitor_cmd *cmd)
{
    static const struct
    {
        const char *name;
        const char *desc;
    } topics[] = {
        {"AUTH",
         "AUTH username password — authenticate as admin (required before other "
         "commands except HELP)"},
        {"STATS",
         "STATS — show server metrics (total_connections, concurrent_connections, "
         "bytes_up, bytes_down)"},
        {"CONNECTIONS",
         "CONNECTIONS — list active SOCKS sessions (username host:port phase "
         "bytes_up bytes_down)"},
        {"USERS", "USERS — list usernames with active SOCKS connections"},
        {"CONFIG",
         "CONFIG param value — change runtime setting (timeout, max_connections, "
         "io_buffer_size)"},
        {"ACCESS_LOG",
         "ACCESS_LOG [username] — show connection audit trail, optionally filtered "
         "by user"},
        {"ADD_USER",
         "ADD_USER username password [admin] — create SOCKS user; append admin "
         "for admin role"},
        {"DEL_USER", "DEL_USER username — remove user from table"},
        {"SET_PASSWORD",
         "SET_PASSWORD username newpassword — change password for an existing user"},
        {"HELP", "HELP [command] — list commands or describe one command"},
        {"QUIT", "QUIT — close the connection gracefully"},
    };

    if (cmd->argc == 1)
    {
        commands_wb_append(session, "+OK Available commands:\n");
        commands_wb_append(session, "+OK AUTH username password\n");
        commands_wb_append(session, "+OK STATS\n");
        commands_wb_append(session, "+OK CONNECTIONS\n");
        commands_wb_append(session, "+OK USERS\n");
        commands_wb_append(session, "+OK CONFIG param value\n");
        commands_wb_append(session, "+OK ACCESS_LOG [username]\n");
        commands_wb_append(session, "+OK ADD_USER username password [admin]\n");
        commands_wb_append(session, "+OK DEL_USER username\n");
        commands_wb_append(session, "+OK SET_PASSWORD username newpassword\n");
        commands_wb_append(session, "+OK HELP [command]\n");
        commands_wb_append(session, "+OK QUIT\n");
        return;
    }

    for (size_t i = 0; i < sizeof(topics) / sizeof(topics[0]); i++)
    {
        if (strcmp(cmd->args[1], topics[i].name) == 0)
        {
            commands_wb_appendf(session, "+OK %s\n", topics[i].desc);
            return;
        }
    }

    commands_wb_append(session, "-ERR unknown command\n");
}

/* Encola +OK y marca cierre; monitor.c cierra el fd cuando wb quede vacío */
static void handle_quit(struct monitor_commands_session *session)
{
    commands_wb_append(session, "+OK\n");
    session->close_after_flush = true;
}

/*
 * Puerta de auth y router de comandos.
 * AWAIT_AUTH: AUTH y HELP; AUTHENTICATED: resto (AUTH repetido → error).
 */
static void dispatch_line(struct monitor_commands_session *session, char *line)
{
    monitor_cmd cmd = {.session = session};

    split_line(&cmd, line);

    if (cmd.cmd[0] == '\0')
    {
        return;
    }

    if (session->state == MONITOR_ST_AWAIT_AUTH)
    {
        if (strcmp(cmd.cmd, "AUTH") == 0)
        {
            handle_auth(session, &cmd);
        }
        else if (strcmp(cmd.cmd, "HELP") == 0)
        {
            handle_help(session, &cmd);
        }
        else
        {
            commands_wb_append(session, "-ERR not authenticated\n");
        }
        return;
    }

    if (strcmp(cmd.cmd, "AUTH") == 0)
    {
        commands_wb_append(session, "-ERR already authenticated\n");
        return;
    }
    if (strcmp(cmd.cmd, "STATS") == 0)
    {
        handle_stats(session);
    }
    else if (strcmp(cmd.cmd, "CONNECTIONS") == 0)
    {
        handle_connections(session);
    }
    else if (strcmp(cmd.cmd, "USERS") == 0)
    {
        handle_users(session);
    }
    else if (strcmp(cmd.cmd, "CONFIG") == 0)
    {
        handle_config(session, &cmd);
    }
    else if (strcmp(cmd.cmd, "ACCESS_LOG") == 0)
    {
        handle_access_log(session, &cmd);
    }
    else if (strcmp(cmd.cmd, "ADD_USER") == 0)
    {
        handle_add_user(session, &cmd);
    }
    else if (strcmp(cmd.cmd, "DEL_USER") == 0)
    {
        handle_del_user(session, &cmd);
    }
    else if (strcmp(cmd.cmd, "SET_PASSWORD") == 0)
    {
        handle_set_password(session, &cmd);
    }
    else if (strcmp(cmd.cmd, "HELP") == 0)
    {
        handle_help(session, &cmd);
    }
    else if (strcmp(cmd.cmd, "QUIT") == 0)
    {
        handle_quit(session);
    }
    else
    {
        commands_wb_append(session, "-ERR unknown command\n");
    }
}

/* ==========================================================================
 * Framing de líneas y dispatch
 * ========================================================================== */

/*
 * Acumula bytes hasta '\n'; strip '\r' final.
 * Línea > MONITOR_LINE_MAX → -ERR line too long y se descarta el acumulado.
 */
static void process_byte(struct monitor_commands_session *session, char ch)
{
    if (session->line_len >= MONITOR_LINE_MAX)
    {
        session->line_len = 0;
        commands_wb_append(session, "-ERR line too long\n");
        return;
    }

    if (ch == '\n')
    {
        session->line_buf[session->line_len] = '\0';
        if (session->line_len > 0 && session->line_buf[session->line_len - 1] == '\r')
        {
            session->line_buf[session->line_len - 1] = '\0';
        }
        if (session->line_len > 0 || session->line_buf[0] != '\0')
        {
            dispatch_line(session, session->line_buf);
        }
        session->line_len = 0;
        return;
    }

    session->line_buf[session->line_len++] = ch;
}

/* Procesa cada byte del chunk recibido (pipelining soportado). */
void monitor_commands_feed(struct monitor_commands_session *session,
                           const uint8_t *data,
                           size_t len)
{
    for (size_t i = 0; i < len; i++)
    {
        process_byte(session, (char)data[i]);
    }
}

/* Última línea sin '\n' al half-close del cliente (requisito del TPE) */
void monitor_commands_flush_on_eof(struct monitor_commands_session *session)
{
    if (session->line_len > 0)
    {
        session->line_buf[session->line_len] = '\0';
        dispatch_line(session, session->line_buf);
        session->line_len = 0;
    }
}
