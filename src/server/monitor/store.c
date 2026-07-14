#include "store.h"

/*
 * store.c — almacena usuarios, métricas, access log (circular + stdout) y sesiones SOCKS activas.
 *
 * monitor_store es el único lugar con estado compartido entre socks.c y
 * monitor_commands.c. Un solo hilo del selector lo modifica.
 */

#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

struct store_user
{
    bool used;
    char username[STORE_MAX_USERNAME + 1];
    char password[STORE_MAX_PASSWORD + 1];
    store_role role;
};

struct store_session_node
{
    bool active;
    store_active_session info;
    store_log_id log_id;
};

struct monitor_store
{
    struct store_user users[STORE_MAX_USERS];
    size_t user_count;

    store_metrics metrics;

    store_log_entry log[STORE_LOG_CAPACITY];
    size_t log_count;
    size_t log_head;
    store_log_id next_log_id;

    uint32_t timeout;
    uint32_t sessions_cap;
    uint32_t io_buffer_size;

    acl_rule *denied_hosts;
    acl_rule *last_denied_host;

    acl_rule *denied_addresses;
    acl_rule *last_denied_addr;

    struct store_session_node *sessions;
    size_t sessions_slots;
    store_session_id next_session_id;
};

/* Genera timestamp UTC ISO8601 para entradas del access log. */
static void store_now_iso8601(char *out, size_t out_len)
{
    time_t now = time(NULL);
    struct tm tm_utc;

    gmtime_r(&now, &tm_utc);
    strftime(out, out_len, "%Y-%m-%dT%H:%M:%SZ", &tm_utc);
}

/* Busca un nodo de sesión activo por id. */
static struct store_session_node *store_find_session(struct monitor_store *store,
                                                     store_session_id id)
{
    if (store == NULL || id == 0)
    {
        return NULL;
    }

    for (size_t i = 0; i < store->sessions_slots; i++)
    {
        if (store->sessions[i].active && store->sessions[i].info.id == id)
        {
            return &store->sessions[i];
        }
    }

    return NULL;
}

/* Emite una entrada del access log a stdout (redirigible por el operador). */
static void store_log_print(const store_log_entry *entry)
{
    fprintf(stdout,
            "%s: %s:%u %s %s up=%llu down=%llu\n",
            entry->username,
            entry->host,
            entry->port,
            entry->timestamp,
            store_log_state_str(entry->state),
            (unsigned long long)entry->bytes_up,
            (unsigned long long)entry->bytes_down);
    fflush(stdout);
}

/* Access log circular: al llenarse, log_head avanza y pisa la entrada más antigua */
static store_log_id store_log_append(struct monitor_store *store,
                                     const char *username,
                                     const char *host,
                                     uint16_t port,
                                     store_log_state state)
{
    store_log_entry *entry;

    if (store->log_count < STORE_LOG_CAPACITY)
    {
        entry = &store->log[store->log_count++];
    }
    else
    {
        entry = &store->log[store->log_head];
        store->log_head = (store->log_head + 1) % STORE_LOG_CAPACITY;
    }

    entry->id = store->next_log_id++;
    strncpy(entry->username, username, STORE_MAX_USERNAME);
    entry->username[STORE_MAX_USERNAME] = '\0';
    strncpy(entry->host, host, STORE_MAX_DEST_HOST);
    entry->host[STORE_MAX_DEST_HOST] = '\0';
    entry->port = port;
    store_now_iso8601(entry->timestamp, sizeof(entry->timestamp));
    entry->state = state;
    entry->bytes_up = 0;
    entry->bytes_down = 0;

    store_log_print(entry);
    return entry->id;
}

/* Actualiza estado y bytes de una entrada existente del log por log_id. */
static void store_log_update(struct monitor_store *store,
                             store_log_id log_id,
                             store_log_state state,
                             uint64_t bytes_up,
                             uint64_t bytes_down)
{
    if (log_id == STORE_LOG_INVALID || store->log_count == 0)
    {
        return;
    }

    for (size_t i = 0; i < store->log_count; i++)
    {
        if (store->log[i].id == log_id)
        {
            store->log[i].state = state;
            store->log[i].bytes_up = bytes_up;
            store->log[i].bytes_down = bytes_down;
            /* Solo eventos de cierre; CONNECTED+bytes no spamea stdout. */
            if (state != STORE_LOG_CONNECTED)
            {
                store_log_print(&store->log[i]);
            }
            return;
        }
    }
}

/* Marca el slot inactivo y decrementa concurrent_connections. */
static void store_session_remove(struct monitor_store *store,
                                 struct store_session_node *node)
{
    if (node == NULL || !node->active)
    {
        return;
    }

    node->active = false;
    if (store->metrics.concurrent_connections > 0)
    {
        store->metrics.concurrent_connections--;
    }
}

/* ==========================================================================
 * Usuarios y autenticación
 * ========================================================================== */

/* Alloc del store, defaults de config y usuarios vienen del -u al levantar el binario o ADD_USER */
struct monitor_store *store_create(void)
{
    struct monitor_store *store = calloc(1, sizeof(*store));

    if (store == NULL)
    {
        return NULL;
    }

    store->timeout = 0;
    store->sessions_cap = STORE_SESSIONS_CAP_DEFAULT;
    store->io_buffer_size = 4096;
    store->next_log_id = 1;
    store->next_session_id = 1;

    store->sessions_slots = (size_t)store->sessions_cap;
    store->sessions = calloc(store->sessions_slots, sizeof(*store->sessions));
    if (store->sessions == NULL)
    {
        free(store);
        return NULL;
    }

    return store;
}

static void free_acl_list(acl_rule *list)
{
    while (list != NULL)
    {
        acl_rule *next = list->next;
        free(list);
        list = next;
    }
}

/* Libera sessions[], el struct monitor_store y ACL rules */
void store_destroy(struct monitor_store *store)
{
    if (store == NULL)
    {
        return;
    }

    free_acl_list(store->denied_hosts);
    free_acl_list(store->denied_addresses);
    free(store->sessions);
    free(store);
}

/* Comprueba username+password para autenticación SOCKS (cualquier rol). */
bool store_user_validate(const struct monitor_store *store,
                         const char *username,
                         const char *password)
{
    if (store == NULL || username == NULL || password == NULL)
    {
        return false;
    }

    for (size_t i = 0; i < STORE_MAX_USERS; i++)
    {
        const struct store_user *user = &store->users[i];

        if (user->used &&
            strcmp(user->username, username) == 0 &&
            strcmp(user->password, password) == 0)
        {
            return true;
        }
    }

    return false;
}

/* Comprueba credenciales para monitor AUTH; exige rol admin. */
store_auth_result store_admin_authenticate(const struct monitor_store *store,
                                           const char *username,
                                           const char *password)
{
    if (store == NULL || username == NULL || password == NULL)
    {
        return STORE_AUTH_INVALID;
    }

    for (size_t i = 0; i < STORE_MAX_USERS; i++)
    {
        const struct store_user *user = &store->users[i];

        if (!user->used || strcmp(user->username, username) != 0)
        {
            continue;
        }

        if (strcmp(user->password, password) != 0)
        {
            return STORE_AUTH_INVALID;
        }

        return user->role == STORE_ROLE_ADMIN ? STORE_AUTH_OK : STORE_AUTH_NOT_ADMIN;
    }

    return STORE_AUTH_INVALID;
}

/* Agrega usuario a la tabla; is_admin define rol admin o user. */
store_user_result store_user_add(struct monitor_store *store,
                                 const char *username,
                                 const char *password,
                                 bool is_admin)
{
    if (store == NULL || username == NULL || password == NULL)
    {
        return STORE_USER_NOT_FOUND;
    }

    for (size_t i = 0; i < STORE_MAX_USERS; i++)
    {
        if (store->users[i].used && strcmp(store->users[i].username, username) == 0)
        {
            return STORE_USER_EXISTS;
        }
    }

    for (size_t i = 0; i < STORE_MAX_USERS; i++)
    {
        if (!store->users[i].used)
        {
            store->users[i].used = true;
            strncpy(store->users[i].username, username, STORE_MAX_USERNAME);
            store->users[i].username[STORE_MAX_USERNAME] = '\0';
            strncpy(store->users[i].password, password, STORE_MAX_PASSWORD);
            store->users[i].password[STORE_MAX_PASSWORD] = '\0';
            store->users[i].role = is_admin ? STORE_ROLE_ADMIN : STORE_ROLE_USER;
            store->user_count++;
            return STORE_USER_OK;
        }
    }

    return STORE_USER_TABLE_FULL;
}

/* Cuenta cuántos admins hay en la tabla (para proteger al último). */
static size_t store_admin_count(const struct monitor_store *store)
{
    size_t count = 0;

    for (size_t i = 0; i < STORE_MAX_USERS; i++)
    {
        if (store->users[i].used && store->users[i].role == STORE_ROLE_ADMIN)
        {
            count++;
        }
    }

    return count;
}

/* Elimina usuario por nombre; falla si es el único admin. */
store_user_result store_user_delete(struct monitor_store *store,
                                    const char *username)
{
    if (store == NULL || username == NULL)
    {
        return STORE_USER_NOT_FOUND;
    }

    for (size_t i = 0; i < STORE_MAX_USERS; i++)
    {
        struct store_user *user = &store->users[i];

        if (!user->used || strcmp(user->username, username) != 0)
        {
            continue;
        }

        if (user->role == STORE_ROLE_ADMIN && store_admin_count(store) <= 1)
        {
            return STORE_USER_LAST_ADMIN;
        }

        user->used = false;
        user->username[0] = '\0';
        user->password[0] = '\0';
        if (store->user_count > 0)
        {
            store->user_count--;
        }
        return STORE_USER_OK;
    }

    return STORE_USER_NOT_FOUND;
}

/* Reemplaza la contraseña de un usuario existente. */
store_user_result store_user_set_password(struct monitor_store *store,
                                          const char *username,
                                          const char *new_password)
{
    if (store == NULL || username == NULL || new_password == NULL)
    {
        return STORE_USER_NOT_FOUND;
    }

    for (size_t i = 0; i < STORE_MAX_USERS; i++)
    {
        struct store_user *user = &store->users[i];

        if (user->used && strcmp(user->username, username) == 0)
        {
            strncpy(user->password, new_password, STORE_MAX_PASSWORD);
            user->password[STORE_MAX_PASSWORD] = '\0';
            return STORE_USER_OK;
        }
    }

    return STORE_USER_NOT_FOUND;
}

/* ==========================================================================
 * Configuración en runtime
 * ========================================================================== */

/*
 * Aumenta sessions_slots hasta new_sessions_slots cuando CONFIG sube sessions_cap.
 * Invariante tras éxito: sessions_slots >= sessions_cap.
 */
static store_config_result store_grow_sessions_slots(struct monitor_store *store,
                                                     size_t new_sessions_slots)
{
    if (store == NULL || new_sessions_slots <= store->sessions_slots)
    {
        return STORE_CFG_OK;
    }

    struct store_session_node *resized_sessions =
        realloc(store->sessions, new_sessions_slots * sizeof(*resized_sessions));
    if (resized_sessions == NULL)
    {
        return STORE_CFG_INVALID_VALUE;
    }

    const size_t old_sessions_slots = store->sessions_slots;
    memset(resized_sessions + old_sessions_slots,
           0,
           (new_sessions_slots - old_sessions_slots) * sizeof(*resized_sessions));

    store->sessions = resized_sessions;
    store->sessions_slots = new_sessions_slots;
    return STORE_CFG_OK;
}

/* Lee un parámetro de config runtime por clave enum. */
bool store_config_get(const struct monitor_store *store,
                      store_config_key key,
                      uint32_t *out_value)
{
    if (store == NULL || out_value == NULL)
    {
        return false;
    }

    switch (key)
    {
    case STORE_CFG_TIMEOUT:
        *out_value = store->timeout;
        return true;
    case STORE_CFG_SESSIONS_CAP:
        *out_value = store->sessions_cap;
        return true;
    case STORE_CFG_IO_BUFFER_SIZE:
        *out_value = store->io_buffer_size;
        return true;
    default:
        return false;
    }
}

/* Escribe un parámetro de config; valida rangos por clave. */
store_config_result store_config_set(struct monitor_store *store,
                                     store_config_key key,
                                     uint32_t value)
{
    if (store == NULL)
    {
        return STORE_CFG_INVALID_VALUE;
    }

    switch (key)
    {
    case STORE_CFG_TIMEOUT:
        if (value > 86400)
        {
            return STORE_CFG_INVALID_VALUE;
        }
        store->timeout = value;
        return STORE_CFG_OK;
    case STORE_CFG_SESSIONS_CAP:
    {
        const uint32_t sessions_cap_min = STORE_SESSIONS_CAP_MIN;
        const uint32_t sessions_cap_max = STORE_SESSIONS_CAP_MAX;

        if (value < sessions_cap_min || value > sessions_cap_max)
        {
            return STORE_CFG_INVALID_VALUE;
        }

        /* No bajar sessions_cap por debajo de las sesiones SOCKS ya abiertas. */
        if (value < store->metrics.concurrent_connections)
        {
            return STORE_CFG_INVALID_VALUE;
        }

        const uint32_t new_sessions_cap = value;

        if (new_sessions_cap > store->sessions_cap)
        {
            const size_t new_sessions_slots = (size_t)new_sessions_cap;
            const store_config_result grow =
                store_grow_sessions_slots(store, new_sessions_slots);
            if (grow != STORE_CFG_OK)
            {
                return grow;
            }
        }

        store->sessions_cap = new_sessions_cap;
        return STORE_CFG_OK;
    }
    case STORE_CFG_IO_BUFFER_SIZE:
        if (value < 1024 || value > 65536)
        {
            return STORE_CFG_INVALID_VALUE;
        }
        store->io_buffer_size = value;
        return STORE_CFG_OK;
    default:
        return STORE_CFG_UNKNOWN_KEY;
    }
}

/* Mapea nombre de texto (CONFIG) a store_config_key. */
bool store_config_key_from_name(const char *param, store_config_key *out_key)
{
    if (param == NULL || out_key == NULL)
    {
        return false;
    }

    if (strcmp(param, "timeout") == 0)
    {
        *out_key = STORE_CFG_TIMEOUT;
        return true;
    }
    if (strcmp(param, "max_connections") == 0)
    {
        *out_key = STORE_CFG_SESSIONS_CAP;
        return true;
    }
    if (strcmp(param, "io_buffer_size") == 0)
    {
        *out_key = STORE_CFG_IO_BUFFER_SIZE;
        return true;
    }

    return false;
}

/* Copia el snapshot actual de métricas globales. */
void store_metrics_get(const struct monitor_store *store, store_metrics *out)
{
    if (store == NULL || out == NULL)
    {
        return;
    }

    *out = store->metrics;
}

/* ==========================================================================
 * Sesiones SOCKS activas y access log
 * ========================================================================== */

/* Reserva slot de sesión SOCKS; incrementa contadores de métricas. */
store_session_id store_session_begin(struct monitor_store *store)
{
    if (store == NULL)
    {
        return STORE_SESSION_INVALID;
    }

    if (store->metrics.concurrent_connections >= store->sessions_cap)
    {
        return STORE_SESSION_INVALID;
    }

    /* sessions_slots >= sessions_cap (store_config_set mantiene el invariante). */
    for (size_t i = 0; i < store->sessions_slots; i++)
    {
        if (!store->sessions[i].active)
        {
            struct store_session_node *node = &store->sessions[i];

            node->active = true;
            node->log_id = STORE_LOG_INVALID;
            node->info.id = store->next_session_id++;
            node->info.username[0] = '\0';
            node->info.host[0] = '\0';
            node->info.port = 0;
            node->info.phase = STORE_SESSION_AUTH;
            node->info.bytes_up = 0;
            node->info.bytes_down = 0;

            store->metrics.total_connections++;
            store->metrics.concurrent_connections++;
            return node->info.id;
        }
    }

    return STORE_SESSION_INVALID;
}

/* Guarda el username tras auth SOCKS exitosa. */
void store_session_set_user(struct monitor_store *store,
                            store_session_id id,
                            const char *username)
{
    struct store_session_node *node = store_find_session(store, id);

    if (node == NULL || username == NULL)
    {
        return;
    }

    strncpy(node->info.username, username, STORE_MAX_USERNAME);
    node->info.username[STORE_MAX_USERNAME] = '\0';
}

/*
 * CONNECT exitoso: fija destino en la sesión activa y crea entrada
 * STORE_LOG_CONNECTED en el access log (si ya hay username).
 */
store_log_id store_session_set_dest(struct monitor_store *store,
                                    store_session_id id,
                                    const char *host,
                                    uint16_t port)
{
    struct store_session_node *node = store_find_session(store, id);

    if (node == NULL || host == NULL)
    {
        return STORE_LOG_INVALID;
    }

    strncpy(node->info.host, host, STORE_MAX_DEST_HOST);
    node->info.host[STORE_MAX_DEST_HOST] = '\0';
    node->info.port = port;
    node->info.phase = STORE_SESSION_RELAY;

    if (node->info.username[0] != '\0')
    {
        node->log_id = store_log_append(store,
                                        node->info.username,
                                        host,
                                        port,
                                        STORE_LOG_CONNECTED);
    }

    return node->log_id;
}

/* Actualiza la fase visible (AUTH, CONNECTING, RELAY) de una sesión. */
void store_session_set_phase(struct monitor_store *store,
                             store_session_id id,
                             store_session_phase phase)
{
    struct store_session_node *node = store_find_session(store, id);

    if (node == NULL)
    {
        return;
    }

    node->info.phase = phase;
}

/* Propaga bytes a la sesión, métricas globales y al log abierto (si hay log_id). */
void store_session_add_bytes(struct monitor_store *store,
                             store_session_id id,
                             uint64_t up,
                             uint64_t down)
{
    struct store_session_node *node = store_find_session(store, id);

    if (node == NULL)
    {
        return;
    }

    node->info.bytes_up += up;
    node->info.bytes_down += down;
    store->metrics.bytes_up += up;
    store->metrics.bytes_down += down;

    if (node->log_id != STORE_LOG_INVALID)
    {
        store_log_update(store,
                         node->log_id,
                         STORE_LOG_CONNECTED,
                         node->info.bytes_up,
                         node->info.bytes_down);
    }
}

/* Fallo al conectar: nueva entrada FAILED en log y libera el slot. */
void store_session_mark_failed(struct monitor_store *store, store_session_id id)
{
    struct store_session_node *node = store_find_session(store, id);

    if (node == NULL)
    {
        return;
    }

    if (node->info.username[0] != '\0' && node->info.host[0] != '\0')
    {
        store_log_append(store,
                         node->info.username,
                         node->info.host,
                         node->info.port,
                         STORE_LOG_FAILED);
    }

    store_session_remove(store, node);
}

/* Cierre normal: marca log CLOSED y libera el slot. */
void store_session_end(struct monitor_store *store, store_session_id id)
{
    struct store_session_node *node = store_find_session(store, id);

    if (node == NULL)
    {
        return;
    }

    if (node->log_id != STORE_LOG_INVALID)
    {
        store_log_update(store,
                         node->log_id,
                         STORE_LOG_CLOSED,
                         node->info.bytes_up,
                         node->info.bytes_down);
    }

    store_session_remove(store, node);
}

/* Cierre por idle timeout: marca log TTL_EXPIRED y libera el slot. */
void store_session_mark_ttl_expired(struct monitor_store *store, store_session_id id)
{
    struct store_session_node *node = store_find_session(store, id);

    if (node == NULL)
    {
        return;
    }

    if (node->log_id != STORE_LOG_INVALID)
    {
        store_log_update(store,
                         node->log_id,
                         STORE_LOG_TTL_EXPIRED,
                         node->info.bytes_up,
                         node->info.bytes_down);
    }
    else if (node->info.username[0] != '\0' && node->info.host[0] != '\0')
    {
        store_log_append(store,
                         node->info.username,
                         node->info.host,
                         node->info.port,
                         STORE_LOG_TTL_EXPIRED);
    }

    store_session_remove(store, node);
}

/* Invoca fn por cada sesión SOCKS activa; se detiene si fn devuelve false. */
void store_sessions_foreach(const struct monitor_store *store,
                            bool (*fn)(const store_active_session *session, void *ctx),
                            void *ctx)
{
    if (store == NULL || fn == NULL)
    {
        return;
    }

    for (size_t i = 0; i < store->sessions_slots; i++)
    {
        if (store->sessions[i].active &&
            !fn(&store->sessions[i].info, ctx))
        {
            return;
        }
    }
}

void store_log_foreach(const struct monitor_store *store,
                       const char *username_filter,
                       bool (*fn)(const store_log_entry *entry, void *ctx),
                       void *ctx)
{
    if (store == NULL || fn == NULL || store->log_count == 0)
    {
        return;
    }

    for (size_t offset = 0; offset < store->log_count; offset++)
    {
        size_t idx;

        if (store->log_count < STORE_LOG_CAPACITY)
        {
            idx = store->log_count - 1 - offset;
        }
        else
        {
            idx = (store->log_head + STORE_LOG_CAPACITY - 1 - offset) %
                  STORE_LOG_CAPACITY;
        }

        const store_log_entry *entry = &store->log[idx];

        if (username_filter != NULL &&
            strcmp(entry->username, username_filter) != 0)
        {
            continue;
        }

        if (!fn(entry, ctx))
        {
            return;
        }
    }
}

/* true si el username existe en la tabla de usuarios. */
bool store_user_exists(const struct monitor_store *store, const char *username)
{
    if (store == NULL || username == NULL)
    {
        return false;
    }

    for (size_t i = 0; i < STORE_MAX_USERS; i++)
    {
        if (store->users[i].used && strcmp(store->users[i].username, username) == 0)
        {
            return true;
        }
    }

    return false;
}

void store_users_foreach(const struct monitor_store *store, bool (*fn)(const char *username, store_role role, void *ctx), void *ctx)
{
    if (store == NULL || fn == NULL)
    {
        return;
    }

    for (size_t i = 0; i < STORE_MAX_USERS; i++)
    {
        if (!store->users[i].used)
        {
            continue;
        }

        if (!fn(store->users[i].username, store->users[i].role, ctx))
        {
            return;
        }
    }
}

/* Devuelve etiqueta textual del estado de una entrada de log. */
const char *store_log_state_str(store_log_state state)
{
    switch (state)
    {
    case STORE_LOG_CONNECTED:
        return "CONNECTED";
    case STORE_LOG_CLOSED:
        return "CLOSED";
    case STORE_LOG_FAILED:
        return "FAILED";
    case STORE_LOG_TTL_EXPIRED:
        return "TTL_EXPIRED";
    default:
        return "UNKNOWN";
    }
}

/* Devuelve etiqueta textual de la fase de una sesión SOCKS activa. */
const char *store_session_phase_str(store_session_phase phase)
{
    switch (phase)
    {
    case STORE_SESSION_AUTH:
        return "AUTH";
    case STORE_SESSION_CONNECTING:
        return "CONNECTING";
    case STORE_SESSION_RELAY:
        return "RELAY";
    case STORE_SESSION_DONE:
        return "DONE";
    default:
        return "UNKNOWN";
    }
}

static void add_host_rule(struct monitor_store *store, acl_rule *rule)
{
    if (store->last_denied_host == NULL)
    {
        store->denied_hosts = store->last_denied_host = rule;
        return;
    }

    store->last_denied_host->next = rule;
    store->last_denied_host = rule;
}

static void add_ip_rule(struct monitor_store *store, acl_rule *rule)
{
    if (store->last_denied_addr == NULL)
    {
        store->denied_addresses = store->last_denied_addr = rule;
        return;
    }

    store->last_denied_addr->next = rule;
    store->last_denied_addr = rule;
}

bool store_deny_host(struct monitor_store *store, const char *hostname)
{
    if (is_host_denied(store, hostname))
        return false;

    {
        struct in_addr addr4;
        struct in6_addr addr6;

        // Las IPs deben registrarse con store_deny_ip
        if (inet_pton(AF_INET, hostname, &addr4) == 1 || inet_pton(AF_INET6, hostname, &addr6) == 1)
        {
            return false;
        }
    }

    acl_rule *rule = calloc(1, sizeof(acl_rule));
    rule->type = ACL_DENIED_HOST;
    strcpy(rule->host, hostname);

    add_host_rule(store, rule);
    return true;
}

bool store_deny_ip(struct monitor_store *store, const char *ip)
{
    if (is_ip_denied(store, ip))
        return false;

    acl_rule *rule = calloc(1, sizeof(acl_rule));
    rule->type = ACL_DENIED_ADDRESS;

    if (inet_pton(AF_INET, ip, &rule->ipv4) == 1)
    {
        rule->is_v4 = true;
    }
    else if (inet_pton(AF_INET6, ip, &rule->ipv6) == 1)
    {
        rule->is_v4 = false;
    }
    else
    {
        free(rule);
        return false;
    }

    add_ip_rule(store, rule);
    return true;
}

static bool host_rule_match(const acl_rule *rule, const char *hostname)
{
    return strcmp(rule->host, hostname) == 0;
}

static bool ip_rule_match(const acl_rule *rule, const char *ip)
{
    struct in_addr addr4;
    struct in6_addr addr6;

    if (inet_pton(AF_INET, ip, &addr4) == 1)
    {
        return rule->is_v4 && memcmp(&rule->ipv4, &addr4, sizeof(addr4)) == 0;
    }

    if (inet_pton(AF_INET6, ip, &addr6) == 1)
    {
        return !rule->is_v4 && memcmp(&rule->ipv6, &addr6, sizeof(addr6)) == 0;
    }

    return false;
}

bool is_host_denied(const struct monitor_store *store, const char *hostname)
{
    if (store == NULL || hostname == NULL)
        return false;

    for (const acl_rule *r = store->denied_hosts; r != NULL; r = r->next)
    {
        if (host_rule_match(r, hostname))
            return true;
    }

    return false;
}

bool is_ip_denied(const struct monitor_store *store, const char *ip)
{
    if (store == NULL || ip == NULL)
        return false;

    for (const acl_rule *r = store->denied_addresses; r != NULL; r = r->next)
    {
        if (ip_rule_match(r, ip))
            return true;
    }

    return false;
}

bool store_undeny_host(struct monitor_store *store, const char *hostname)
{
    if (store == NULL || hostname == NULL)
        return false;

    acl_rule *previous = NULL;
    acl_rule *current = store->denied_hosts;

    while (current != NULL)
    {
        if (host_rule_match(current, hostname))
        {
            if (previous == NULL)
                store->denied_hosts = current->next;
            else
                previous->next = current->next;

            if (store->last_denied_host == current)
                store->last_denied_host = previous;

            free(current);
            return true;
        }
        previous = current;
        current = current->next;
    }

    return false;
}

bool store_undeny_ip(struct monitor_store *store, const char *ip)
{
    if (store == NULL || ip == NULL)
        return false;

    acl_rule *previous = NULL;
    acl_rule *current = store->denied_addresses;

    while (current != NULL)
    {
        if (ip_rule_match(current, ip))
        {
            if (previous == NULL)
                store->denied_addresses = current->next;
            else
                previous->next = current->next;

            if (store->last_denied_addr == current)
                store->last_denied_addr = previous;

            free(current);
            return true;
        }
        previous = current;
        current = current->next;
    }

    return false;
}

acl_rule *get_denied_hosts(const struct monitor_store *store)
{
    return store->denied_hosts;
}

acl_rule *get_denied_ips(const struct monitor_store *store)
{
    return store->denied_addresses;
}

const char *acl_rule_to_string(const acl_rule *rule)
{
    if (rule == NULL)
        return "NULL";

    if (rule->type == ACL_DENIED_HOST)
        return rule->host;

    static char buf[INET6_ADDRSTRLEN];

    if (inet_ntop(rule->is_v4 ? AF_INET : AF_INET6,
                  rule->is_v4 ? (const void *)&rule->ipv4
                              : (const void *)&rule->ipv6,
                  buf,
                  sizeof(buf)) == NULL)
    {
        return "?";
    }

    return buf;
}