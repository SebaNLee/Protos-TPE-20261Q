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
 *                 ├── origin_fd  (-1 por ahora; segundo socket al destino)
 *                 ├── c2o / o2c  (dos buffers en cruz)
 *                 └── stm        (estados del protocolo SOCKS)
 *
 * Paso 2: greeting SOCKS5 (method negotiation).
 * Paso 3: autenticación RFC 1929 (username/password).
 * Pendiente: CONNECT, connect al origen, relay.
 */
#include "socks.h"

#include <errno.h>
#include <netinet/in.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

/* ==========================================================================
 * Máquina de estados (STM)
 * ========================================================================== */

static unsigned socks_stub_stay(struct selector_key *key);
static unsigned socks_on_read_greeting(struct selector_key *key);
static unsigned socks_on_read_auth(struct selector_key *key);
static void socks_unregister_session(struct selector_key *key);

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
 * Si el mensaje es válido y ofrece username/password, encola [05][02] en o2c
 * y pasa a AUTH_USERPASS. Si no, encola [05][FF] y cierra tras enviar.
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
            static const uint8_t resp[] = {0x05, 0x02};

            if (!socks_o2c_append(session, resp, sizeof(resp)))
            {
                socks_unregister_session(key);
                return SOCKS_ST_DONE;
            }
            return SOCKS_ST_AUTH_USERPASS;
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

        if (socks_auth_validate(&session->auth))
        {
            /* Credenciales correctas: el browser puede mandar el CONNECT. */
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
        .on_read_ready = socks_stub_stay,
        .on_write_ready = socks_stub_stay,
    },
    {
        .state = SOCKS_ST_RESOLVING,
        .on_read_ready = socks_stub_stay,
        .on_write_ready = socks_stub_stay,
        .on_block_ready = socks_stub_stay, /* Se usará cuando getaddrinfo termine */
    },
    {
        .state = SOCKS_ST_ORIGIN_CONNECTING,
        .on_read_ready = socks_stub_stay,
        .on_write_ready = socks_stub_stay,
    },
    {
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

/* Inicializa una sesión recién aceptada. origin_fd queda en -1 (sin destino). */
static void socks_session_init(struct socks_session *session,
                               struct socks_server *srv,
                               int client_fd)
{
    session->srv = srv;
    session->client_fd = client_fd;
    session->origin_fd = -1;
    session->dest_addr_len = 0;

    buffer_init(&session->c2o, SOCKS_BUFFER_SIZE, session->c2o_backing);
    buffer_init(&session->o2c, SOCKS_BUFFER_SIZE, session->o2c_backing);

    socks_greeting_parser_init(&session->greeting);
    socks_auth_parser_init(&session->auth);
    session->close_after_flush = false;

    socks_session_stm_init(session);
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
 * READ del browser: socket → c2o → stm_handler_read.
 *
 * Los bytes quedan en c2o; el STM (greeting) los consume y puede encolar
 * la respuesta en o2c.
 */
static void socks_client_read(struct selector_key *key)
{
    struct socks_session *session = key->data;
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
    stm_handler_read(&session->stm, key);
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
        stm_handler_close(&session->stm, key);
        socks_session_destroy_origin(session);
    }

    if (srv != NULL && srv->active_sessions > 0)
    {
        srv->active_sessions--;
    }

    if (key->fd >= 0)
    {
        close(key->fd);
    }

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

        struct socks_session *session = calloc(1, sizeof(*session));
        if (session == NULL)
        {
            close(client_fd);
            continue;
        }

        socks_session_init(session, srv, client_fd);

        if (selector_register(key->s,
                              client_fd,
                              &socks_client_handler,
                              OP_READ,
                              session) != SELECTOR_SUCCESS)
        {
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
