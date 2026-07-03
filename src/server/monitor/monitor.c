#include "monitor.h"

/*
 * monitor.c — I/O de red del puerto de administración
 *
 * Arquitectura (misma base que echo.c / socks.c):
 *
 *   monitor_server
 *        │
 *        ├── listen_fd  (monitor_passive_handler → accept)
 *        │
 *        └── monitor_session[]  (uno por cliente admin)
 *                 ├── rb           (bytes entrantes del socket)
 *                 ├── commands     (monitor_commands_session: líneas + wb)
 *                 └── client_fd    (monitor_client_handler read/write)
 *
 * Comparte fd_selector y monitor_store con SOCKS (puerto por defecto 8080).
 * Los comandos se delegan a monitor_commands.c; los datos viven en store.c.
 */

#include "monitor_commands.h"
#include "shared/buffer.h"

#include <errno.h>
#include <netinet/in.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

/* rb = entrada del socket; commands = protocolo + respuestas pendientes */
struct monitor_session
{
    struct monitor_server *srv;
    buffer rb;
    uint8_t rb_backing[MONITOR_BUFFER_SIZE];
    struct monitor_commands_session commands;
};

static void monitor_client_read(struct selector_key *key);
static void monitor_client_write(struct selector_key *key);
static void monitor_client_close(struct selector_key *key);
static void monitor_passive_read(struct selector_key *key);
static void monitor_passive_close(struct selector_key *key);

static const fd_handler monitor_client_handler = {
    .handle_read = monitor_client_read,
    .handle_write = monitor_client_write,
    .handle_block = NULL,
    .handle_close = monitor_client_close,
};

static const fd_handler monitor_passive_handler = {
    .handle_read = monitor_passive_read,
    .handle_write = NULL,
    .handle_block = NULL,
    .handle_close = monitor_passive_close,
};

/* Intereses de lectura/escritura según espacio en rb y datos en wb */
static fd_interest monitor_client_interest(struct monitor_session *session)
{
    fd_interest interest = OP_NOOP;

    if (buffer_can_write(&session->rb))
    {
        interest |= OP_READ;
    }
    if (buffer_can_read(&session->commands.wb))
    {
        interest |= OP_WRITE;
    }

    return interest;
}

/* Desregistra el fd del selector (el cierre real ocurre en handle_close). */
static void monitor_unregister_session(struct selector_key *key)
{
    selector_unregister_fd(key->s, key->fd);
}

/* Pipelining: vacía rb alimentando monitor_commands_feed byte a byte */
static void feed_rb_to_commands(struct monitor_session *session)
{
    while (buffer_can_read(&session->rb))
    {
        size_t pending = 0;
        const uint8_t *ptr = buffer_read_ptr(&session->rb, &pending);

        monitor_commands_feed(&session->commands, ptr, pending);
        buffer_read_adv(&session->rb, (ssize_t)pending);
        buffer_compact(&session->rb);
    }
}

/* ==========================================================================
 * Handlers del selector (cliente y socket pasivo)
 * ========================================================================== */

/*
 * Half-close (requisito del TPE):
 *   EOF → drenar rb → flush_on_eof → mantener fd si wb tiene respuestas.
 */
static void monitor_client_read(struct selector_key *key)
{
    struct monitor_session *session = key->data;
    size_t available = 0;
    uint8_t *ptr = buffer_write_ptr(&session->rb, &available);

    if (available == 0)
    {
        selector_set_interest_key(key, monitor_client_interest(session));
        return;
    }

    const ssize_t n = read(key->fd, ptr, available);
    if (n == 0)
    {
        feed_rb_to_commands(session);
        monitor_commands_flush_on_eof(&session->commands);

        if (buffer_can_read(&session->commands.wb))
        {
            selector_set_interest_key(key, monitor_client_interest(session));
            return;
        }

        monitor_unregister_session(key);
        return;
    }
    if (n < 0)
    {
        if (errno == EAGAIN || errno == EWOULDBLOCK)
        {
            selector_set_interest_key(key, monitor_client_interest(session));
            return;
        }
        monitor_unregister_session(key);
        return;
    }

    buffer_write_adv(&session->rb, n);
    feed_rb_to_commands(session);
    selector_set_interest_key(key, monitor_client_interest(session));
}

/* QUIT: tras vaciar wb, monitor_commands_should_close() → unregister */
static void monitor_client_write(struct selector_key *key)
{
    struct monitor_session *session = key->data;
    size_t pending = 0;
    uint8_t *ptr = buffer_read_ptr(&session->commands.wb, &pending);

    if (pending == 0)
    {
        selector_set_interest_key(key, monitor_client_interest(session));
        return;
    }

    const ssize_t n = write(key->fd, ptr, pending);
    if (n < 0)
    {
        if (errno == EAGAIN || errno == EWOULDBLOCK)
        {
            selector_set_interest_key(key, monitor_client_interest(session));
            return;
        }
        monitor_unregister_session(key);
        return;
    }

    buffer_read_adv(&session->commands.wb, n);
    buffer_compact(&session->commands.wb);

    if (monitor_commands_should_close(&session->commands))
    {
        monitor_unregister_session(key);
        return;
    }

    selector_set_interest_key(key, monitor_client_interest(session));
}

/* Libera la sesión: decrementa active_sessions, cierra fd y free(). */
static void monitor_client_close(struct selector_key *key)
{
    struct monitor_session *session = key->data;
    struct monitor_server *srv = session != NULL ? session->srv : NULL;

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

/* Inicializa buffers, protocolo y encola el greeting al conectar. */
static void monitor_session_init(struct monitor_session *session,
                                 struct monitor_server *srv,
                                 int client_fd)
{
    session->srv = srv;
    buffer_init(&session->rb, MONITOR_BUFFER_SIZE, session->rb_backing);
    monitor_commands_session_init(&session->commands, srv->store);
    monitor_commands_queue_greeting(&session->commands);
    (void)client_fd;
}

/* Bucle accept no bloqueante; incrementa active_sessions por cada cliente */
static void monitor_passive_read(struct selector_key *key)
{
    struct monitor_server *srv = key->data;

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

        struct monitor_session *session = calloc(1, sizeof(*session));
        if (session == NULL)
        {
            close(client_fd);
            continue;
        }

        monitor_session_init(session, srv, client_fd);

        const fd_interest interest = monitor_client_interest(session);
        if (selector_register(key->s,
                              client_fd,
                              &monitor_client_handler,
                              interest,
                              session) != SELECTOR_SUCCESS)
        {
            free(session);
            close(client_fd);
            continue;
        }

        srv->active_sessions++;
    }
}

/* Cierre del socket pasivo: marca listen_fd inválido y cierra el fd. */
static void monitor_passive_close(struct selector_key *key)
{
    struct monitor_server *srv = key->data;

    if (srv != NULL)
    {
        srv->listen_fd = -1;
    }

    if (key->fd >= 0)
    {
        close(key->fd);
    }
}

/* ==========================================================================
 * Socket pasivo y ciclo de vida del servidor
 * ========================================================================== */

/*
 * IPv6 dual-stack (IPV6_V6ONLY=0), SO_REUSEADDR.
 * port==0  getsockname devuelve el puerto asignado por el kernel.
 */
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

/* Crea listen socket, registra el pasivo en el selector y devuelve el servidor. */
selector_status monitor_server_init(fd_selector s,
                                    uint16_t port,
                                    volatile bool *stop,
                                    struct monitor_store *store,
                                    struct monitor_server **out)
{
    if (s == NULL || out == NULL)
    {
        return SELECTOR_IARGS;
    }

    struct monitor_server *srv = calloc(1, sizeof(*srv));
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
                          &monitor_passive_handler,
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

/* Desregistra el socket pasivo y libera monitor_server. */
void monitor_server_destroy(struct monitor_server *srv)
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

/* Graceful shutdown fase 1: dejar de aceptar clientes admin nuevos. */
void monitor_server_stop_accepting(struct monitor_server *srv)
{
    if (srv == NULL || srv->listen_fd < 0)
    {
        return;
    }

    selector_unregister_fd(srv->selector, srv->listen_fd);
    srv->listen_fd = -1;
}

/* Una vuelta del selector; revisa *stop antes de select. */
selector_status monitor_server_run_once(struct monitor_server *srv)
{
    if (srv == NULL)
    {
        return SELECTOR_IARGS;
    }

    if (srv->stop != NULL && *srv->stop && srv->listen_fd >= 0)
    {
        monitor_server_stop_accepting(srv);
    }

    return selector_select(srv->selector);
}

/* true cuando no queda listen_fd ni sesiones admin activas. */
bool monitor_server_is_empty(const struct monitor_server *srv)
{
    if (srv == NULL)
    {
        return true;
    }

    return srv->listen_fd < 0 && srv->active_sessions == 0;
}

/* Devuelve el puerto en el que escucha  */
uint16_t monitor_server_port(const struct monitor_server *srv)
{
    if (srv == NULL)
    {
        return 0;
    }

    return srv->port;
}
