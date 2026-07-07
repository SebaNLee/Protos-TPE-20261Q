/*
 * socks.c — Servidor proxy SOCKS5 (esqueleto, paso 1).
 *
 * Arquitectura (misma base que echo.c, extendida para el proxy):
 *
 *   socks_server
 *        │
 *        ├── listen_fd  (socks_passive_handler → accept)
 *        │
 *        └── socks_session[]  (uno por browser conectado)
 *                 ├── client_fd  (socks_client_handler)
 *                 ├── origin_fd  (socket al destino; -1 hasta CONNECT exitoso)
 *                 ├── c2o / o2c  (dos buffers cruzados)
 *                 └── stm        (estados del protocolo SOCKS)
 *
 * Paso 2: greeting SOCKS5 (method negotiation).
 * Paso 3: autenticación RFC 1929 (username/password).
 * Paso 4: CONNECT request, DNS, conexión al origen y relay.
 */
#include "socks.h"

#include <arpa/inet.h>
#include <errno.h>
#include <netdb.h>
#include <netinet/in.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

/* ==========================================================================
 * Máquina de estados (STM)
 * ========================================================================== */

static unsigned socks_stub_stay(struct selector_key *key);
static unsigned socks_on_read_greeting(struct selector_key *key);
static unsigned socks_on_read_auth(struct selector_key *key);
static unsigned socks_on_read_request(struct selector_key *key);
static unsigned socks_on_block_resolving(struct selector_key *key);
static void socks_unregister_session(struct selector_key *key);
static void socks_origin_read(struct selector_key *key);
static void socks_origin_write(struct selector_key *key);
static void socks_origin_close(struct selector_key *key);
static fd_interest socks_origin_interest(struct socks_session *session);
static unsigned socks_begin_origin_connect(struct selector_key *key);
static void socks_free_dns(struct socks_session *session);
static bool socks_send_connect_reply(struct socks_session *session, uint8_t rep);
static void socks_fail_request(struct selector_key *key, uint8_t rep);
static void socks_session_close_from_origin(struct socks_session *session);
static void socks_session_destroy_origin(struct socks_session *session);

static void socks_session_record_dest(struct socks_session *session);
static void socks_check_idle_timeout(struct socks_session *session,
                                     struct selector_key *key);
static void socks_auth_store_user(struct socks_session *session);

/* ==========================================================================
 * Integración con monitor_store
 *
 * socks.c avisa al store en cada etapa de la sesión SOCKS para que los
 * comandos del puerto 8080 reflejen la realidad del proxy:
 *
 *   accept()           → store_session_begin()      (CONNECTIONS, STATS)
 *   auth OK            → store_session_set_user()   (ACCESS_LOG, USERS)
 *   pedido CONNECT     → store_session_set_phase()  (CONNECTIONS)
 *   CONNECT exitoso    → store_session_set_dest()   (ACCESS_LOG)
 *   relay c2o/o2c      → store_session_add_bytes()  (STATS, ACCESS_LOG)
 *   cierre / fallo     → store_session_end() / mark_failed()
 *
 * Ver también el diagrama de ciclo de vida en store.h.
 * ========================================================================== */

static bool socks_o2c_append(struct socks_session *session,
                             const uint8_t *data,
                             size_t len)
{
    size_t available = 0;
    uint8_t *ptr = buffer_write_ptr(&session->o2c, &available);

    if (available < len)
    {
        return false;
    }

    memcpy(ptr, data, len);
    buffer_write_adv(&session->o2c, (ssize_t)len);
    return true;
}

/*
 * Paso 2 — Greeting (RFC 1928).
 * El cliente ofrece una lista de métodos:
 * - Si ofrece 0x02 (user:password), entonces encola [05][02] y pasa a auth
 * - Si ofrece 0x00 (no auth required), entonces responde [05][00] y va directo a request
 * - Si no, encola [05][FF] y cierra tras enviar
 */
static unsigned socks_on_read_greeting(struct selector_key *key)
{
    struct socks_session *session = key->data;

    while (buffer_can_read(&session->c2o))
    {
        size_t pending = 0;
        const uint8_t *ptr = buffer_read_ptr(&session->c2o, &pending);

        if (pending == 0)
        {
            break;
        }

        const socks_greeting_status status =
            socks_greeting_parser_feed(&session->greeting, ptr[0]);
        buffer_read_adv(&session->c2o, 1);

        if (status == SOCKS_GREETING_NEED_MORE)
        {
            continue;
        }

        if (status == SOCKS_GREETING_ACCEPT)
        {
            const uint8_t method = socks_greeting_chosen_method(&session->greeting);
            const uint8_t resp[] = {0x05, method};

            if (!socks_o2c_append(session, resp, sizeof(resp)))
            {
                socks_unregister_session(key);
                return SOCKS_ST_DONE;
            }

            if (method == SOCKS_METHOD_USERPASS)
            {
                return SOCKS_ST_AUTH_USERPASS;
            }

            store_session_set_user(session->srv->store, session->store_id, "Anon");
            store_session_set_phase(session->srv->store, session->store_id, STORE_SESSION_AUTH);
            return SOCKS_ST_REQUEST;
        }

        static const uint8_t reject[] = {0x05, 0xFF};

        if (!socks_o2c_append(session, reject, sizeof(reject)))
        {
            socks_unregister_session(key);
            return SOCKS_ST_DONE;
        }

        session->close_after_flush = true;
        return SOCKS_ST_DONE;
    }

    return SOCKS_ST_AUTH_GREETING;
}

/*
 * Paso 3 — Autenticación (RFC 1929).
 *
 * Mismo patrón que socks_on_read_greeting: consume c2o byte a byte,
 * alimenta session->auth, y según el resultado:
 *
 *   PARSED + validate OK  → [01][00] en o2c → SOCKS_ST_REQUEST
 *   PARSED + validate fail → [01][01] en o2c → cierre
 *   REJECT (mal formado)   → [01][01] en o2c → cierre
 *
 * Ejemplo admin/admin en el wire:
 *   01 05 61 64 6d 69 6e 05 61 64 6d 69 6e
 */
static unsigned socks_on_read_auth(struct selector_key *key)
{
    struct socks_session *session = key->data;

    while (buffer_can_read(&session->c2o))
    {
        size_t pending = 0;
        const uint8_t *ptr = buffer_read_ptr(&session->c2o, &pending);

        if (pending == 0)
        {
            break;
        }

        const socks_auth_status status =
            socks_auth_parser_feed(&session->auth, ptr[0]);
        buffer_read_adv(&session->c2o, 1);

        if (status == SOCKS_AUTH_NEED_MORE)
        {
            continue;
        }

        if (status == SOCKS_AUTH_REJECT)
        {
            /* Mensaje mal formado (versión incorrecta, ulen=0, etc.). */
            static const uint8_t reject[] = {0x01, 0x01};

            if (!socks_o2c_append(session, reject, sizeof(reject)))
            {
                socks_unregister_session(key);
                return SOCKS_ST_DONE;
            }

            session->close_after_flush = true;
            return SOCKS_ST_DONE;
        }

        if (socks_auth_validate(&session->auth, session->srv->store))
        {
            socks_auth_store_user(session);
            store_session_set_phase(session->srv->store,
                                    session->store_id,
                                    STORE_SESSION_AUTH);
            static const uint8_t ok[] = {0x01, 0x00};

            if (!socks_o2c_append(session, ok, sizeof(ok)))
            {
                socks_unregister_session(key);
                return SOCKS_ST_DONE;
            }
            return SOCKS_ST_REQUEST;
        }

        /* Mensaje bien formado pero usuario/contraseña incorrectos. */
        static const uint8_t fail[] = {0x01, 0x01};

        if (!socks_o2c_append(session, fail, sizeof(fail)))
        {
            socks_unregister_session(key);
            return SOCKS_ST_DONE;
        }

        session->close_after_flush = true;
        return SOCKS_ST_DONE;
    }

    return SOCKS_ST_AUTH_USERPASS;
}

/* ==========================================================================
 * Paso 4 — CONNECT, DNS, origen y relay
 *
 * Flujo resumido:
 *
 *   REQUEST: parser consume CONNECT desde c2o
 *       ├─ IPv4/IPv6 → connect() directo al destino
 *       └─ FQDN      → thread con getaddrinfo → RESOLVING
 *
 *   ORIGIN_CONNECTING: connect() no bloqueante; al completar → reply [05][00]
 *
 *   RELAY: copia cruzada
 *       client_fd READ  → c2o → origin_fd WRITE
 *       origin_fd READ  → o2c → client_fd WRITE
 * ========================================================================== */

/* Libera la lista enlazada devuelta por getaddrinfo (solo sesiones FQDN). */
static void socks_free_dns(struct socks_session *session)
{
    if (session == NULL || session->dns_result == NULL)
    {
        return;
    }

    freeaddrinfo(session->dns_result);
    session->dns_result = NULL;
    session->dns_cursor = NULL;
}

/*
 * Encola la respuesta al CONNECT en o2c (10 bytes, RFC 1928).
 *
 * Formato: [05][REP][00][ATYP][BND.ADDR][BND.PORT]
 *
 * Por simplicidad usamos ATYP=IPv4 y dirección 0.0.0.0:0.
 * rep=0x00 éxito; otros valores indican error (ver socks_fail_request).
 */
static bool socks_send_connect_reply(struct socks_session *session, uint8_t rep)
{
    static const uint8_t template_reply[] = {
        0x05, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};

    uint8_t reply[sizeof(template_reply)];
    memcpy(reply, template_reply, sizeof(reply));
    reply[1] = rep;

    return socks_o2c_append(session, reply, sizeof(reply));
}

/*
 * Falla el CONNECT: manda reply con código de error y cierra tras vaciar o2c.
 *
 * Códigos REP usados:
 *   0x01 — error general
 *   0x04 — host inalcanzable (DNS falló)
 *   0x05 — conexión rechazada (connect() falló)
 */
static void socks_fail_request(struct selector_key *key, uint8_t rep)
{
    struct socks_session *session = key->data;

    if (session != NULL && session->srv != NULL && session->srv->store != NULL &&
        session->store_id != STORE_SESSION_INVALID)
    {
        store_session_mark_failed(session->srv->store, session->store_id);
        session->store_id = STORE_SESSION_INVALID;
    }

    if (!socks_send_connect_reply(session, rep))
    {
        socks_unregister_session(key);
        return;
    }

    session->close_after_flush = true;
    session->stm.current = session->stm.states + SOCKS_ST_DONE;
    /* Despertar client_fd para enviar el reply (p. ej. tras fallo async en origin). */
    selector_set_interest(key->s, session->client_fd, socks_client_interest(session));
}

/* Argumentos del thread de resolución DNS (vive solo durante getaddrinfo). */
typedef struct socks_dns_ctx
{
    struct socks_session *session;
    fd_selector selector;
    int notify_fd;
    char host[SOCKS_REQUEST_FQDN_MAX + 1];
    char port_str[8];
    int gai_rc;
    struct addrinfo *result;
} socks_dns_ctx;

/*
 * Thread auxiliar: getaddrinfo es bloqueante, no puede correr en el selector.
 *
 * Al terminar escribe dns_gai_rc / dns_result en la sesión y despierta
 * al hilo principal con selector_notify_block(client_fd).
 * El selector ejecutará socks_on_block_resolving vía handle_block.
 */
static void *socks_dns_thread(void *arg)
{
    socks_dns_ctx *ctx = arg;
    struct addrinfo hints;

    memset(&hints, 0, sizeof(hints));
    hints.ai_socktype = SOCK_STREAM;

    ctx->gai_rc = getaddrinfo(ctx->host, ctx->port_str, &hints, &ctx->result);
    ctx->session->dns_resolving = false;
    ctx->session->dns_gai_rc = ctx->gai_rc;
    ctx->session->dns_result = ctx->gai_rc == 0 ? ctx->result : NULL;
    selector_notify_block(ctx->selector, ctx->notify_fd);
    free(ctx);
    return NULL;
}

/*
 * Arranca resolución DNS para un destino FQDN.
 * Transiciona a SOCKS_ST_RESOLVING y espera el evento block.
 */
static unsigned socks_start_dns_resolve(struct selector_key *key)
{
    struct socks_session *session = key->data;
    socks_dns_ctx *ctx = calloc(1, sizeof(*ctx));

    if (ctx == NULL)
    {
        socks_fail_request(key, 0x01);
        return SOCKS_ST_DONE;
    }

    session->dns_resolving = true;
    session->dns_gai_rc = 0;
    session->dns_result = NULL;
    session->dns_cursor = NULL;

    ctx->session = session;
    ctx->selector = key->s;
    ctx->notify_fd = session->client_fd;
    strncpy(ctx->host, socks_request_fqdn(&session->request), sizeof(ctx->host) - 1);
    snprintf(ctx->port_str, sizeof(ctx->port_str), "%u",
             socks_request_dest_port(&session->request));

    pthread_t tid;
    if (pthread_create(&tid, NULL, socks_dns_thread, ctx) != 0)
    {
        free(ctx);
        socks_fail_request(key, 0x01);
        return SOCKS_ST_DONE;
    }
    pthread_detach(tid);

    return SOCKS_ST_RESOLVING;
}

/*
 * Handler del socket hacia el destino (origin_fd).
 * En RELAY: read copia origen→o2c, write copia c2o→origen.
 * Durante ORIGIN_CONNECTING el primer WRITE confirma que connect() terminó.
 */
static const fd_handler socks_origin_handler = {
    .handle_read = socks_origin_read,
    .handle_write = socks_origin_write,
    .handle_block = NULL,
    .handle_close = socks_origin_close,
};

/*
 * Abre socket TCP hacia el destino y lanza connect() no bloqueante.
 *
 * La dirección puede venir de:
 *   - dns_cursor   (FQDN ya resuelto)
 *   - dest_addr    (IPv4/IPv6 parseado del CONNECT)
 *   - request      (fallback; misma info que dest_addr)
 *
 * Si connect() falla de inmediato y hay más entradas en addrinfo, prueba la
 * siguiente (p. ej. IPv6 falla → intenta IPv4).
 *
 * Registra origin_fd en el selector con OP_WRITE: el kernel avisa cuando
 * la conexión async está lista (o falló).
 */
static unsigned socks_begin_origin_connect(struct selector_key *key)
{
    struct socks_session *session = key->data;
    const struct sockaddr *addr = NULL;
    socklen_t addr_len = 0;

    if (session->dns_cursor != NULL)
    {
        addr = session->dns_cursor->ai_addr;
        addr_len = session->dns_cursor->ai_addrlen;
    }
    else if (session->dest_addr_len > 0)
    {
        addr = (const struct sockaddr *)&session->dest_addr;
        addr_len = session->dest_addr_len;
    }
    else
    {
        addr = socks_request_dest_addr(&session->request);
        addr_len = socks_request_dest_addr_len(&session->request);
    }

    if (addr == NULL || addr_len == 0)
    {
        socks_fail_request(key, 0x01);
        return SOCKS_ST_DONE;
    }

    const int fd = socket(addr->sa_family, SOCK_STREAM, 0);
    if (fd < 0)
    {
        socks_fail_request(key, 0x01);
        return SOCKS_ST_DONE;
    }

    if (selector_fd_set_nio(fd) < 0)
    {
        close(fd);
        socks_fail_request(key, 0x01);
        return SOCKS_ST_DONE;
    }

    const int rc = connect(fd, addr, addr_len);
    if (rc < 0 && errno != EINPROGRESS)
    {
        close(fd);
        if (session->dns_cursor != NULL &&
            session->dns_cursor->ai_next != NULL)
        {
            session->dns_cursor = session->dns_cursor->ai_next;
            return socks_begin_origin_connect(key);
        }
        socks_fail_request(key, 0x05);
        return SOCKS_ST_DONE;
    }

    session->origin_fd = fd;

    if (selector_register(key->s,
                          fd,
                          &socks_origin_handler,
                          OP_WRITE,
                          session) != SELECTOR_SUCCESS)
    {
        close(fd);
        session->origin_fd = -1;
        socks_fail_request(key, 0x01);
        return SOCKS_ST_DONE;
    }

    memcpy(&session->dest_addr, addr, addr_len);
    session->dest_addr_len = addr_len;

    return SOCKS_ST_ORIGIN_CONNECTING;
}

/*
 * Paso 4 — CONNECT request (RFC 1928).
 *
 * Mismo patrón que greeting/auth: consume c2o byte a byte, alimenta
 * session->request, y según el resultado:
 *
 *   PARSED_ADDR  → connect directo (IP en el mensaje)
 *   PARSED_FQDN  → getaddrinfo en thread
 *   REJECT       → reply REP=0x01 y cierre
 */
static unsigned socks_on_read_request(struct selector_key *key)
{
    struct socks_session *session = key->data;

    while (buffer_can_read(&session->c2o))
    {
        size_t pending = 0;
        const uint8_t *ptr = buffer_read_ptr(&session->c2o, &pending);

        if (pending == 0)
        {
            break;
        }

        const socks_request_status status =
            socks_request_parser_feed(&session->request, ptr[0]);
        buffer_read_adv(&session->c2o, 1);

        if (status == SOCKS_REQUEST_NEED_MORE)
        {
            continue;
        }

        if (status == SOCKS_REQUEST_REJECT)
        {
            socks_fail_request(key, 0x01);
            return SOCKS_ST_DONE;
        }

        if (status == SOCKS_REQUEST_PARSED_FQDN)
        {
            store_session_set_phase(session->srv->store,
                                    session->store_id,
                                    STORE_SESSION_CONNECTING);
            return socks_start_dns_resolve(key);
        }

        if (status == SOCKS_REQUEST_PARSED_ADDR)
        {
            store_session_set_phase(session->srv->store,
                                    session->store_id,
                                    STORE_SESSION_CONNECTING);
            session->dest_addr_len =
                socks_request_dest_addr_len(&session->request);
            memcpy(&session->dest_addr,
                   socks_request_dest_addr(&session->request),
                   session->dest_addr_len);
            return socks_begin_origin_connect(key);
        }
    }

    return SOCKS_ST_REQUEST;
}

/*
 * Evento block en RESOLVING: el thread de DNS terminó.
 * Si getaddrinfo OK → connect al primer addrinfo; si no → REP=0x04.
 */
static unsigned socks_on_block_resolving(struct selector_key *key)
{
    struct socks_session *session = key->data;

    if (session->dns_resolving)
    {
        return SOCKS_ST_RESOLVING;
    }

    if (session->dns_gai_rc != 0 || session->dns_result == NULL)
    {
        socks_fail_request(key, 0x04);
        return SOCKS_ST_DONE;
    }

    session->dns_cursor = session->dns_result;
    return socks_begin_origin_connect(key);
}

/* El origen cerró: desregistramos al cliente (él hará cleanup en handle_close). */
static void socks_session_close_from_origin(struct socks_session *session)
{
    if (session == NULL)
    {
        return;
    }

    selector_unregister_fd(session->srv->selector, session->client_fd);
}

/*
 * connect() async terminó (nos despertó OP_WRITE en origin_fd).
 *
 * getsockopt(SO_ERROR) distingue éxito de fallo. En éxito:
 *   1. Encola [05][00]... en o2c (el cliente puede empezar a mandar datos)
 *   2. Pasa a RELAY y ajusta intereses de ambos sockets
 */
static void socks_origin_connect_complete(struct selector_key *key)
{
    struct socks_session *session = key->data;
    int err = 0;
    socklen_t err_len = sizeof(err);

    if (getsockopt(key->fd, SOL_SOCKET, SO_ERROR, &err, &err_len) < 0)
    {
        err = errno;
    }

    if (err != 0)
    {
        socks_session_destroy_origin(session);

        if (session->dns_cursor != NULL &&
            session->dns_cursor->ai_next != NULL)
        {
            session->dns_cursor = session->dns_cursor->ai_next;
            const unsigned next = socks_begin_origin_connect(key);
            session->stm.current = session->stm.states + next;
            return;
        }

        socks_fail_request(key, 0x05);
        return;
    }

    if (!socks_send_connect_reply(session, 0x00))
    {
        socks_unregister_session(key);
        return;
    }

    socks_session_record_dest(session);

    session->stm.current = session->stm.states + SOCKS_ST_RELAY;
    selector_set_interest(key->s, session->origin_fd, socks_origin_interest(session));
    selector_set_interest(key->s, session->client_fd, socks_client_interest(session));
}

/*
 * Intereses del origin_fd (espejo de socks_client_interest, cruzado):
 *
 *   o2c con espacio  → OP_READ  (leer del destino hacia el cliente)
 *   c2o con datos    → OP_WRITE (enviar al destino lo que mandó el cliente)
 */
fd_interest socks_origin_interest(struct socks_session *session)
{
    fd_interest interest = OP_NOOP;

    if (buffer_can_write(&session->o2c))
    {
        interest |= OP_READ;
    }
    if (buffer_can_read(&session->c2o))
    {
        interest |= OP_WRITE;
    }

    return interest;
}

/* RELAY: origen → o2c → cliente */
static void socks_origin_read(struct selector_key *key)
{
    struct socks_session *session = key->data;
    size_t available = 0;
    uint8_t *ptr = buffer_write_ptr(&session->o2c, &available);

    if (available == 0)
    {
        selector_set_interest_key(key, socks_origin_interest(session));
        return;
    }

    const ssize_t n = read(key->fd, ptr, available);
    if (n == 0)
    {
        socks_session_close_from_origin(session);
        return;
    }
    if (n < 0)
    {
        if (errno == EAGAIN || errno == EWOULDBLOCK)
        {
            selector_set_interest_key(key, socks_origin_interest(session));
            return;
        }
        socks_session_close_from_origin(session);
        return;
    }

    buffer_write_adv(&session->o2c, n);
    if (session->srv != NULL && session->srv->store != NULL &&
        session->store_id != STORE_SESSION_INVALID)
    {
        store_session_add_bytes(session->srv->store,
                                session->store_id,
                                0,
                                (uint64_t)n);
    }
    selector_set_interest(key->s, session->client_fd, socks_client_interest(session));
    selector_set_interest_key(key, socks_origin_interest(session));
}

/*
 * ORIGIN_CONNECTING: primer WRITE confirma connect().
 * RELAY: drena c2o hacia el socket del destino.
 */
static void socks_origin_write(struct selector_key *key)
{
    struct socks_session *session = key->data;

    if (stm_state(&session->stm) == SOCKS_ST_ORIGIN_CONNECTING)
    {
        socks_origin_connect_complete(key);
        return;
    }

    size_t pending = 0;
    uint8_t *ptr = buffer_read_ptr(&session->c2o, &pending);

    if (pending == 0)
    {
        selector_set_interest_key(key, socks_origin_interest(session));
        return;
    }

    const ssize_t n = write(key->fd, ptr, pending);
    if (n < 0)
    {
        if (errno == EAGAIN || errno == EWOULDBLOCK)
        {
            selector_set_interest_key(key, socks_origin_interest(session));
            return;
        }
        socks_session_close_from_origin(session);
        return;
    }

    buffer_read_adv(&session->c2o, n);
    buffer_compact(&session->c2o);
    if (session->srv != NULL && session->srv->store != NULL &&
        session->store_id != STORE_SESSION_INVALID)
    {
        store_session_add_bytes(session->srv->store,
                                session->store_id,
                                (uint64_t)n,
                                0);
    }
    selector_set_interest_key(key, socks_origin_interest(session));
    selector_set_interest(key->s, session->client_fd, socks_client_interest(session));
}

static void socks_origin_close(struct selector_key *key)
{
    struct socks_session *session = key->data;

    if (session != NULL)
    {
        session->origin_fd = -1;
    }

    if (key->fd >= 0)
    {
        close(key->fd);
    }
}

/*
 * Stub: devuelve el estado actual sin transicionar.
 * El STM exige on_read_ready/on_write_ready no nulos; esto cumple la interfaz
 * sin lógica de protocolo todavía.
 */
static unsigned socks_stub_stay(struct selector_key *key)
{
    struct socks_session *session = key->data;
    return stm_state(&session->stm);
}

/* Tabla de estados: el orden del array DEBE coincidir con enum socks_state. */
static const struct state_definition socks_state_table[] = {
    {
        .state = SOCKS_ST_AUTH_GREETING,
        .on_read_ready = socks_on_read_greeting,
        .on_write_ready = socks_stub_stay,
    },
    {
        .state = SOCKS_ST_AUTH_USERPASS,
        .on_read_ready = socks_on_read_auth,
        .on_write_ready = socks_stub_stay,
    },
    {
        .state = SOCKS_ST_REQUEST,
        .on_read_ready = socks_on_read_request,
        .on_write_ready = socks_stub_stay,
    },
    {
        /* Esperando getaddrinfo; on_block_ready corre cuando el thread avisa */
        .state = SOCKS_ST_RESOLVING,
        .on_read_ready = socks_stub_stay,
        .on_write_ready = socks_stub_stay,
        .on_block_ready = socks_on_block_resolving,
    },
    {
        /* connect() async en curso; la lógica vive en socks_origin_write */
        .state = SOCKS_ST_ORIGIN_CONNECTING,
        .on_read_ready = socks_stub_stay,
        .on_write_ready = socks_stub_stay,
    },
    {
        /* Túnel transparente: los handlers de client/origin mueven los buffers */
        .state = SOCKS_ST_RELAY,
        .on_read_ready = socks_stub_stay,
        .on_write_ready = socks_stub_stay,
    },
    {
        .state = SOCKS_ST_DONE,
        .on_read_ready = socks_stub_stay,
        .on_write_ready = socks_stub_stay,
    },
};

static void socks_session_stm_init(struct socks_session *session)
{
    session->stm.initial = SOCKS_ST_AUTH_GREETING;
    session->stm.states = socks_state_table;
    session->stm.max_state = SOCKS_ST_DONE;
    stm_init(&session->stm);
}

/*
 * Tras auth SOCKS exitosa: copia el username parseado al store.
 * Se llama desde socks_on_read_auth() antes de pasar a REQUEST.
 */
static void socks_auth_store_user(struct socks_session *session)
{
    char username[SOCKS_AUTH_MAX_LEN + 1];
    const size_t len = socks_auth_username_len(&session->auth);

    if (session->srv == NULL || session->srv->store == NULL ||
        session->store_id == STORE_SESSION_INVALID || len == 0 ||
        len > SOCKS_AUTH_MAX_LEN)
    {
        return;
    }

    memcpy(username, socks_auth_username(&session->auth), len);
    username[len] = '\0';
    store_session_set_user(session->srv->store, session->store_id, username);
}

/*
 * Tras CONNECT exitoso al origen: registra host:port en el store
 * y crea una entrada CONNECTED en el access log.
 */
static void socks_session_record_dest(struct socks_session *session)
{
    char host[STORE_MAX_DEST_HOST + 1];
    const char *fqdn = socks_request_fqdn(&session->request);

    if (session->dest_recorded || session->srv == NULL ||
        session->srv->store == NULL ||
        session->store_id == STORE_SESSION_INVALID)
    {
        return;
    }

    if (fqdn != NULL && fqdn[0] != '\0')
    {
        strncpy(host, fqdn, STORE_MAX_DEST_HOST);
    }
    else if (session->dest_addr_len > 0)
    {
        const void *addr = NULL;

        if (session->dest_addr.ss_family == AF_INET)
        {
            addr = &((struct sockaddr_in *)&session->dest_addr)->sin_addr;
        }
        else if (session->dest_addr.ss_family == AF_INET6)
        {
            addr = &((struct sockaddr_in6 *)&session->dest_addr)->sin6_addr;
        }

        if (addr == NULL ||
            inet_ntop(session->dest_addr.ss_family,
                      addr,
                      host,
                      sizeof(host)) == NULL)
        {
            strncpy(host, "unknown", sizeof(host) - 1);
        }
    }
    else
    {
        strncpy(host, "unknown", sizeof(host) - 1);
    }

    host[STORE_MAX_DEST_HOST] = '\0';
    store_session_set_dest(session->srv->store,
                           session->store_id,
                           host,
                           socks_request_dest_port(&session->request));
    session->dest_recorded = true;
}

/*
 * CONFIG timeout: si la sesión supera N segundos sin tráfico, la cerramos.
 * timeout=0 (default) desactiva esta comprobación.
 */
static void socks_check_idle_timeout(struct socks_session *session,
                                     struct selector_key *key)
{
    uint32_t timeout = 0;

    if (session == NULL || session->srv == NULL ||
        session->srv->store == NULL || session->store_id == STORE_SESSION_INVALID)
    {
        return;
    }

    if (!store_config_get(session->srv->store, STORE_CFG_TIMEOUT, &timeout) ||
        timeout == 0)
    {
        return;
    }

    if (time(NULL) - session->last_activity >= (time_t)timeout)
    {
        socks_unregister_session(key);
    }
}

static size_t socks_session_buffer_size(const struct socks_server *srv)
{
    uint32_t size = SOCKS_BUFFER_SIZE_DEFAULT;

    if (srv != NULL && srv->store != NULL &&
        store_config_get(srv->store, STORE_CFG_IO_BUFFER_SIZE, &size))
    {
        return (size_t)size;
    }

    return SOCKS_BUFFER_SIZE_DEFAULT;
}

static void socks_session_destroy_buffers(struct socks_session *session)
{
    if (session == NULL)
    {
        return;
    }

    free(session->c2o_backing);
    free(session->o2c_backing);
    session->c2o_backing = NULL;
    session->o2c_backing = NULL;
}

static bool socks_session_init_buffers(struct socks_session *session)
{
    const size_t buf_size = socks_session_buffer_size(session->srv);

    session->c2o_backing = malloc(buf_size);
    session->o2c_backing = malloc(buf_size);
    if (session->c2o_backing == NULL || session->o2c_backing == NULL)
    {
        socks_session_destroy_buffers(session);
        return false;
    }

    buffer_init(&session->c2o, buf_size, session->c2o_backing);
    buffer_init(&session->o2c, buf_size, session->o2c_backing);
    return true;
}

/* Inicializa una sesión recién aceptada. origin_fd queda en -1 (sin destino). */
static bool socks_session_init(struct socks_session *session,
                               struct socks_server *srv,
                               int client_fd)
{
    session->srv = srv;
    session->client_fd = client_fd;
    session->origin_fd = -1;
    session->dest_addr_len = 0;
    session->c2o_backing = NULL;
    session->o2c_backing = NULL;

    if (!socks_session_init_buffers(session))
    {
        return false;
    }

    socks_greeting_parser_init(&session->greeting);
    socks_auth_parser_init(&session->auth);
    socks_request_parser_init(&session->request);
    session->dns_result = NULL;
    session->dns_cursor = NULL;
    session->dns_gai_rc = 0;
    session->dns_resolving = false;
    session->close_after_flush = false;
    session->store_id = STORE_SESSION_INVALID;
    session->last_activity = time(NULL);
    session->dest_recorded = false;

    socks_session_stm_init(session);
    return true;
}

/* ==========================================================================
 * Handlers del selector
 * ========================================================================== */

static void socks_client_read(struct selector_key *key);
static void socks_client_write(struct selector_key *key);
static void socks_client_block(struct selector_key *key);
static void socks_client_close(struct selector_key *key);
static void socks_passive_read(struct selector_key *key);
static void socks_passive_close(struct selector_key *key);

/*
 * Handler del socket del browser.
 * handle_block se usará cuando un thread de DNS llame selector_notify_block.
 */
static const fd_handler socks_client_handler = {
    .handle_read = socks_client_read,
    .handle_write = socks_client_write,
    .handle_block = socks_client_block,
    .handle_close = socks_client_close,
};

/* Handler del socket pasivo: solo accept, sin write ni block. */
static const fd_handler socks_passive_handler = {
    .handle_read = socks_passive_read,
    .handle_write = NULL,
    .handle_block = NULL,
    .handle_close = socks_passive_close,
};

/*
 * Intereses del client_fd (misma idea que echo_client_interest, con dos buffers):
 *
 *   c2o con espacio  → OP_READ  (leer más bytes del browser)
 *   o2c con datos    → OP_WRITE (enviar respuesta SOCKS o datos del relay)
 */
fd_interest socks_client_interest(struct socks_session *session)
{
    fd_interest interest = OP_NOOP;

    if (buffer_can_write(&session->c2o))
    {
        interest |= OP_READ;
    }
    if (buffer_can_read(&session->o2c))
    {
        interest |= OP_WRITE;
    }

    return interest;
}

static void socks_unregister_session(struct selector_key *key)
{
    selector_unregister_fd(key->s, key->fd);
}

/*
 * READ del browser: socket → c2o.
 *
 * Antes de RELAY: stm_handler_read consume c2o (greeting, auth, CONNECT).
 * En RELAY: solo acumulamos bytes en c2o y despertamos origin_fd para que
 * escriba hacia el destino (no pasamos por el STM).
 */
static void socks_client_read(struct selector_key *key)
{
    struct socks_session *session = key->data;

    socks_check_idle_timeout(session, key);
    if (session == NULL)
    {
        return;
    }

    size_t available = 0;
    uint8_t *ptr = buffer_write_ptr(&session->c2o, &available);

    if (available == 0)
    {
        selector_set_interest_key(key, socks_client_interest(session));
        return;
    }

    const ssize_t n = read(key->fd, ptr, available);
    if (n == 0)
    {
        socks_unregister_session(key);
        return;
    }
    if (n < 0)
    {
        if (errno == EAGAIN || errno == EWOULDBLOCK)
        {
            selector_set_interest_key(key, socks_client_interest(session));
            return;
        }
        socks_unregister_session(key);
        return;
    }

    buffer_write_adv(&session->c2o, n);
    session->last_activity = time(NULL);

    if (stm_state(&session->stm) == SOCKS_ST_RELAY)
    {
        /* c2o tiene datos nuevos → avisar al origen que puede escribir */
        if (session->origin_fd >= 0)
        {
            selector_set_interest(session->srv->selector,
                                  session->origin_fd,
                                  socks_origin_interest(session));
        }
    }
    else
    {
        stm_handler_read(&session->stm, key);
    }

    selector_set_interest_key(key, socks_client_interest(session));
}

/*
 * WRITE hacia el browser: o2c → socket.
 *
 * Aquí se enviarán las respuestas SOCKS ([05][02], [01][00], reply CONNECT)
 * y luego los bytes del relay en la fase RELAY.
 */
static void socks_client_write(struct selector_key *key)
{
    struct socks_session *session = key->data;
    size_t pending = 0;
    uint8_t *ptr = buffer_read_ptr(&session->o2c, &pending);

    if (pending == 0)
    {
        selector_set_interest_key(key, socks_client_interest(session));
        return;
    }

    const ssize_t n = write(key->fd, ptr, pending);
    if (n < 0)
    {
        if (errno == EAGAIN || errno == EWOULDBLOCK)
        {
            selector_set_interest_key(key, socks_client_interest(session));
            return;
        }
        socks_unregister_session(key);
        return;
    }

    buffer_read_adv(&session->o2c, n);
    buffer_compact(&session->o2c);
    stm_handler_write(&session->stm, key);

    if (session->close_after_flush && !buffer_can_read(&session->o2c))
    {
        socks_unregister_session(key);
        return;
    }

    selector_set_interest_key(key, socks_client_interest(session));
}

/* Despacha el evento block del STM (resolución DNS terminada). */
static void socks_client_block(struct selector_key *key)
{
    struct socks_session *session = key->data;
    stm_handler_block(&session->stm, key);
    selector_set_interest_key(key, socks_client_interest(session));
}

/* Cierra origin_fd si ya se había conectado al destino. */
static void socks_session_destroy_origin(struct socks_session *session)
{
    if (session == NULL || session->origin_fd < 0)
    {
        return;
    }

    selector_unregister_fd(session->srv->selector, session->origin_fd);
    session->origin_fd = -1;
}

/*
 * CLOSE del browser: limpia STM, origen (si existe), contador y memoria.
 * El selector no cierra el fd; lo hacemos nosotros.
 */
static void socks_client_close(struct selector_key *key)
{
    struct socks_session *session = key->data;
    struct socks_server *srv = session != NULL ? session->srv : NULL;

    if (session != NULL)
    {
        if (session->srv != NULL && session->srv->store != NULL &&
            session->store_id != STORE_SESSION_INVALID)
        {
            store_session_end(session->srv->store, session->store_id);
            session->store_id = STORE_SESSION_INVALID;
        }

        stm_handler_close(&session->stm, key);
        socks_session_destroy_origin(session);
        socks_free_dns(session);
    }

    if (srv != NULL && srv->active_sessions > 0)
    {
        srv->active_sessions--;
    }

    if (key->fd >= 0)
    {
        close(key->fd);
    }

    socks_session_destroy_buffers(session);
    free(session);
}

/*
 * READ del listen socket: acepta todas las conexiones pendientes.
 * Por cada browser nuevo crea una socks_session y la registra en el selector.
 */
static void socks_passive_read(struct selector_key *key)
{
    struct socks_server *srv = key->data;

    while (true)
    {
        struct sockaddr_storage addr;
        socklen_t addr_len = sizeof(addr);
        const int client_fd =
            accept(key->fd, (struct sockaddr *)&addr, &addr_len);

        if (client_fd < 0)
        {
            if (errno == EAGAIN || errno == EWOULDBLOCK)
            {
                return;
            }
            return;
        }

        if (selector_fd_set_nio(client_fd) < 0)
        {
            close(client_fd);
            continue;
        }

        /* CONFIG max_connections: si el store no tiene cupo, rechazamos el accept */
        store_session_id store_id = STORE_SESSION_INVALID;
        if (srv->store != NULL)
        {
            store_id = store_session_begin(srv->store);
            if (store_id == STORE_SESSION_INVALID)
            {
                close(client_fd);
                continue;
            }
        }

        struct socks_session *session = calloc(1, sizeof(*session));
        if (session == NULL)
        {
            if (srv->store != NULL && store_id != STORE_SESSION_INVALID)
            {
                store_session_end(srv->store, store_id);
            }
            close(client_fd);
            continue;
        }

        if (!socks_session_init(session, srv, client_fd))
        {
            if (srv->store != NULL && store_id != STORE_SESSION_INVALID)
            {
                store_session_end(srv->store, store_id);
            }
            free(session);
            close(client_fd);
            continue;
        }
        session->store_id = store_id;

        if (selector_register(key->s,
                              client_fd,
                              &socks_client_handler,
                              OP_READ,
                              session) != SELECTOR_SUCCESS)
        {
            if (srv->store != NULL && store_id != STORE_SESSION_INVALID)
            {
                store_session_end(srv->store, store_id);
            }
            socks_session_destroy_buffers(session);
            free(session);
            close(client_fd);
            continue;
        }

        srv->active_sessions++;
    }
}

static void socks_passive_close(struct selector_key *key)
{
    struct socks_server *srv = key->data;

    if (srv != NULL)
    {
        srv->listen_fd = -1;
    }

    if (key->fd >= 0)
    {
        close(key->fd);
    }
}

/*
 * Socket de escucha IPv6 dual-stack (acepta IPv4 e IPv6).
 */
// TODO: Idéntico al de echo.c; podría extraerse a netutils en el futuro.
static int create_listen_socket(uint16_t port, uint16_t *bound_port)
{
    const int fd = socket(AF_INET6, SOCK_STREAM, 0);
    if (fd < 0)
    {
        return -1;
    }

    const int reuse = 1;
    if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse)) < 0)
    {
        close(fd);
        return -1;
    }

    const int v6only = 0;
    if (setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, &v6only, sizeof(v6only)) < 0)
    {
        close(fd);
        return -1;
    }

    struct sockaddr_in6 addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin6_family = AF_INET6;
    addr.sin6_addr = in6addr_any;
    addr.sin6_port = htons(port);

    if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0)
    {
        close(fd);
        return -1;
    }

    if (listen(fd, SOMAXCONN) < 0)
    {
        close(fd);
        return -1;
    }

    if (bound_port != NULL)
    {
        struct sockaddr_in6 bound_addr;
        socklen_t bound_len = sizeof(bound_addr);
        if (getsockname(fd, (struct sockaddr *)&bound_addr, &bound_len) == 0)
        {
            *bound_port = ntohs(bound_addr.sin6_port);
        }
    }

    if (selector_fd_set_nio(fd) < 0)
    {
        close(fd);
        return -1;
    }

    return fd;
}

/* ==========================================================================
 * API pública (misma forma que echo_server_* para facilitar el cambio en main)
 * ========================================================================== */

selector_status socks_server_init(fd_selector s,
                                  uint16_t port,
                                  volatile bool *stop,
                                  struct monitor_store *store,
                                  struct socks_server **out)
{
    if (s == NULL || out == NULL)
    {
        return SELECTOR_IARGS;
    }

    struct socks_server *srv = calloc(1, sizeof(*srv));
    if (srv == NULL)
    {
        return SELECTOR_ENOMEM;
    }

    uint16_t bound_port = port;
    srv->listen_fd = create_listen_socket(port, &bound_port);
    if (srv->listen_fd < 0)
    {
        free(srv);
        return SELECTOR_IO;
    }

    srv->port = bound_port;
    srv->selector = s;
    srv->stop = stop;
    srv->store = store;

    const selector_status status =
        selector_register(s,
                          srv->listen_fd,
                          &socks_passive_handler,
                          OP_READ,
                          srv);
    if (status != SELECTOR_SUCCESS)
    {
        close(srv->listen_fd);
        free(srv);
        return status;
    }

    *out = srv;
    return SELECTOR_SUCCESS;
}

void socks_server_destroy(struct socks_server *srv)
{
    if (srv == NULL)
    {
        return;
    }

    if (srv->listen_fd >= 0)
    {
        selector_unregister_fd(srv->selector, srv->listen_fd);
        srv->listen_fd = -1;
    }

    free(srv);
}

/* Graceful shutdown fase 1: dejar de aceptar browsers nuevos. */
void socks_server_stop_accepting(struct socks_server *srv)
{
    if (srv == NULL || srv->listen_fd < 0)
    {
        return;
    }

    selector_unregister_fd(srv->selector, srv->listen_fd);
    srv->listen_fd = -1;
}

selector_status socks_server_run_once(struct socks_server *srv)
{
    if (srv == NULL)
    {
        return SELECTOR_IARGS;
    }

    if (srv->stop != NULL && *srv->stop && srv->listen_fd >= 0)
    {
        socks_server_stop_accepting(srv);
    }

    return selector_select(srv->selector);
}

bool socks_server_is_empty(const struct socks_server *srv)
{
    if (srv == NULL)
    {
        return true;
    }

    return srv->listen_fd < 0 && srv->active_sessions == 0;
}

uint16_t socks_server_port(const struct socks_server *srv)
{
    if (srv == NULL)
    {
        return 0;
    }

    return srv->port;
}
