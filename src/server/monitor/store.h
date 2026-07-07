#ifndef MONITOR_STORE_H
#define MONITOR_STORE_H

/*
 * store.h — estado compartido entre SOCKS y el puerto de monitoreo:
 * usuarios, métricas, access log, config y sesiones activas.
 *
 * Un solo hilo (selector) accede al store; no requiere locks.
 *
 * Ciclo de vida de una sesión SOCKS (socks.c llama en este orden):
 *
 *   store_session_begin()       → métricas + slot en sessions[]
 *   store_session_set_user()    → username en sesión activa
 *   store_session_set_phase()   → AUTH / CONNECTING / RELAY
 *   store_session_set_dest()    → crea entrada CONNECTED en access log
 *   store_session_add_bytes()   → actualiza métricas + log en curso
 *   store_session_end()         → log CLOSED
 *   store_session_mark_failed() → log FAILED (entrada nueva, sin log_id previo)
 *
 * Ver también el bloque "Integración con monitor_store" en socks.c.
 */

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define STORE_MAX_USERS 256
#define STORE_MAX_USERNAME 64
#define STORE_MAX_PASSWORD 255
#define STORE_LOG_CAPACITY 4096
#define STORE_MAX_DEST_HOST 255

typedef enum
{
    STORE_ROLE_USER,  /* solo puede usar el proxy SOCKS */
    STORE_ROLE_ADMIN, /* puede usar SOCKS y el puerto de monitoreo */
} store_role;

typedef enum
{
    STORE_AUTH_OK,        /* login admin correcto (monitor AUTH) */
    STORE_AUTH_INVALID,   /* usuario o contraseña incorrectos */
    STORE_AUTH_NOT_ADMIN, /* credenciales OK pero el rol es user, no admin */
} store_auth_result;

typedef enum
{
    STORE_USER_OK,
    STORE_USER_EXISTS,
    STORE_USER_NOT_FOUND,
    STORE_USER_TABLE_FULL,
    STORE_USER_LAST_ADMIN, /* no se puede borrar al único admin */
} store_user_result;

typedef enum
{
    STORE_CFG_TIMEOUT,         /* segundos de inactividad */
    STORE_CFG_MAX_CONNECTIONS, /* tope de clientes SOCKS simultáneos */
    STORE_CFG_IO_BUFFER_SIZE,  /* tamaño de buffer para sesiones nuevas */
} store_config_key;

typedef enum
{
    STORE_CFG_OK,
    STORE_CFG_UNKNOWN_KEY,
    STORE_CFG_INVALID_VALUE,
} store_config_result;

typedef enum
{
    STORE_LOG_CONNECTED, /* CONNECT al destino exitoso, sesión en curso */
    STORE_LOG_CLOSED,    /* sesión terminó normalmente */
    STORE_LOG_FAILED,    /* no se pudo conectar al destino */
} store_log_state;

typedef enum
{
    STORE_SESSION_AUTH,       /*  autenticando SOCKS */
    STORE_SESSION_CONNECTING, /* resolviendo DNS o conectando al origen */
    STORE_SESSION_RELAY,      /* tunel activo cliente - destino */
    STORE_SESSION_DONE,
} store_session_phase;

typedef uint32_t store_session_id;
typedef uint32_t store_log_id;

#define STORE_SESSION_INVALID ((store_session_id)0)
#define STORE_LOG_INVALID ((store_log_id)0)

typedef struct store_metrics
{
    uint64_t total_connections;      /* cantidad de conexiones histórica desde el arranque */
    uint64_t concurrent_connections; /* cantidad de conexiones abiertas ahora mismo */
    uint64_t bytes_up;               /* bytes totales cliente → destino */
    uint64_t bytes_down;             /* bytes totales destino → cliente */
} store_metrics;

typedef struct store_log_entry
{
    store_log_id id;
    char username[STORE_MAX_USERNAME + 1];
    char host[STORE_MAX_DEST_HOST + 1];
    uint16_t port;
    char timestamp[21]; /* "2026-06-29T14:22:01Z" */
    store_log_state state;
    uint64_t bytes_up;
    uint64_t bytes_down;
} store_log_entry;

typedef struct store_active_session
{
    store_session_id id;
    char username[STORE_MAX_USERNAME + 1];
    char host[STORE_MAX_DEST_HOST + 1];
    uint16_t port;
    store_session_phase phase;
    uint64_t bytes_up;
    uint64_t bytes_down;
} store_active_session;

struct monitor_store;

/* Crea el store con defaults y usuario bootstrap admin/admin. */
struct monitor_store *store_create(void);
/* Libera sessions[] y el struct monitor_store. */
void store_destroy(struct monitor_store *store);

/* Valida credenciales SOCKS. Llamar desde socks_auth_validate(). */
bool store_user_validate(const struct monitor_store *store,
                         const char *username,
                         const char *password);

/* Valida credenciales del comando monitor AUTH; requiere rol admin. */
store_auth_result store_admin_authenticate(const struct monitor_store *store,
                                           const char *username,
                                           const char *password);

/* Agrega usuario a la tabla; is_admin define rol admin o user. */
store_user_result store_user_add(struct monitor_store *store,
                                 const char *username,
                                 const char *password,
                                 bool is_admin);

/* Elimina usuario por nombre; falla si es el único admin. */
store_user_result store_user_delete(struct monitor_store *store,
                                    const char *username);

/* Reemplaza la contraseña de un usuario existente. */
store_user_result store_user_set_password(struct monitor_store *store,
                                          const char *username,
                                          const char *new_password);

/* Lee un parámetro de config runtime por clave enum. */
bool store_config_get(const struct monitor_store *store,
                      store_config_key key,
                      uint32_t *out_value);

/* Escribe un parámetro de config; valida rangos por clave. */
store_config_result store_config_set(struct monitor_store *store,
                                     store_config_key key,
                                     uint32_t value);

/* Mapea nombre de texto (CONFIG) a store_config_key. */
bool store_config_key_from_name(const char *param, store_config_key *out_key);

/* Copia el snapshot actual de métricas globales. */
void store_metrics_get(const struct monitor_store *store, store_metrics *out);

/* --- Sesiones SOCKS (llamadas desde socks.c) --- */

/* accept() de un cliente SOCKS: incrementa total_connections y concurrent. */
store_session_id store_session_begin(struct monitor_store *store);

/* Auth OK: guarda el username en la sesión activa (CONNECTIONS, USERS). */
void store_session_set_user(struct monitor_store *store,
                            store_session_id id,
                            const char *username);

/* CONNECT exitoso: fija destino, fase RELAY y crea entrada CONNECTED en el log. */
store_log_id store_session_set_dest(struct monitor_store *store,
                                    store_session_id id,
                                    const char *host,
                                    uint16_t port);

/* Actualiza la fase visible en CONNECTIONS (AUTH, CONNECTING, RELAY). */
void store_session_set_phase(struct monitor_store *store,
                             store_session_id id,
                             store_session_phase phase);

/* Relay: suma bytes a la sesión, métricas globales y al log abierto. */
void store_session_add_bytes(struct monitor_store *store,
                             store_session_id id,
                             uint64_t up,
                             uint64_t down);

/* Fallo de conexión al destino: nueva entrada FAILED y libera el slot. */
void store_session_mark_failed(struct monitor_store *store, store_session_id id);

/* Cierre normal: marca log CLOSED y libera el slot. */
void store_session_end(struct monitor_store *store, store_session_id id);

/* Iteradores usados por monitor_commands (CONNECTIONS, USERS, ACCESS_LOG). */
void store_sessions_foreach(const struct monitor_store *store,
                            bool (*fn)(const store_active_session *session, void *ctx),
                            void *ctx);

void store_active_usernames_foreach(const struct monitor_store *store,
                                    bool (*fn)(const char *username, void *ctx),
                                    void *ctx);

/* Recorre el log de más reciente a más antiguo; filter=NULL = todos. */
void store_log_foreach(const struct monitor_store *store,
                       const char *username_filter,
                       bool (*fn)(const store_log_entry *entry, void *ctx),
                       void *ctx);

/* true si el username existe en la tabla de usuarios. */
bool store_user_exists(const struct monitor_store *store, const char *username);

/* Itera sobre todos los usuarios registrados, devuelve username, role, ctx */
void store_users_foreach(const struct monitor_store *store, bool (*fn)(const char *username, store_role role, void *ctx), void *ctx);

/* Devuelve etiqueta textual del estado de una entrada de log. */
const char *store_log_state_str(store_log_state state);

/* Devuelve etiqueta textual de la fase de una sesión SOCKS activa. */
const char *store_session_phase_str(store_session_phase phase);

#endif
