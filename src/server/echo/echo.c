/*
 * echo.c — Servidor TCP de eco concurrente sobre el selector.
 *
 * Arquitectura:
 *   - Un socket pasivo (listen) acepta conexiones entrantes.
 *   - Cada cliente activo tiene su propio fd_handler y un buffer circular.
 *   - Flujo por cliente: read(socket) -> buffer -> write(socket)  (eco).
 *
 * Este módulo es el andamiaje del proxy SOCKS: el relay futuro reutiliza
 * el mismo patrón de buffers + intereses OP_READ/OP_WRITE, pero con dos
 * sockets (cliente y origen) en lugar de devolver bytes al mismo cliente.
 */
#include "echo.h"

#include <errno.h>
#include <netinet/in.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

/* --- Declaraciones anticipadas de callbacks del selector --- */

static void echo_client_read(struct selector_key *key);
static void echo_client_write(struct selector_key *key);
static void echo_client_close(struct selector_key *key);
static void echo_passive_read(struct selector_key *key);
static void echo_passive_close(struct selector_key *key);

/*
 * Handler para sockets de clientes ya aceptados.
 * handle_block es NULL porque este módulo no hace trabajo bloqueante (DNS).
 */
static const fd_handler echo_client_handler = {
    .handle_read = echo_client_read,
    .handle_write = echo_client_write,
    .handle_block = NULL,
    .handle_close = echo_client_close,
};

/*
 * Handler para el socket pasivo (listen).
 * Solo nos interesa READ: el kernel avisa cuando hay conexiones pendientes
 * de accept(). No escribimos nunca en el listen socket.
 */
static const fd_handler echo_passive_handler = {
    .handle_read = echo_passive_read,
    .handle_write = NULL,
    .handle_block = NULL,
    .handle_close = echo_passive_close,
};

/*
 * Calcula qué eventos debe suscribir el selector para un cliente.
 *
 * Regla del eco:
 *   - Si el buffer tiene espacio libre  -> queremos READ  (leer del socket).
 *   - Si el buffer tiene datos pendientes -> queremos WRITE (devolverlos).
 *
 * Pueden coexistir ambos (pipelining): el cliente manda más datos mientras
 * todavía estamos escribiendo los anteriores.
 */
fd_interest echo_client_interest(struct echo_client *c)
{
    fd_interest interest = OP_NOOP;

    if (buffer_can_write(&c->rb))
    {
        interest |= OP_READ;
    }
    if (buffer_can_read(&c->rb))
    {
        interest |= OP_WRITE;
    }

    return interest;
}

/* Desregistra el fd del selector; eso dispara echo_client_close. */
static void echo_unregister_client(struct selector_key *key)
{
    selector_unregister_fd(key->s, key->fd);
}

/*
 * READ handler del cliente: lee bytes del socket hacia el buffer.
 *
 * Casos:
 *   n == 0  -> peer cerró (EOF); desregistrar.
 *   n < 0   -> EAGAIN/EWOULDBLOCK: no hay datos ahora; re-suscribir intereses.
 *             otro error: desregistrar.
 *   n > 0   -> avanzar puntero de escritura del buffer y actualizar intereses.
 */
static void echo_client_read(struct selector_key *key)
{
    struct echo_client *client = key->data;
    size_t available = 0;
    uint8_t *ptr = buffer_write_ptr(&client->rb, &available);

    if (available == 0)
    {
        /* Buffer lleno: dejamos de pedir READ hasta que write drene datos. */
        selector_set_interest_key(key, echo_client_interest(client));
        return;
    }

    const ssize_t n = read(key->fd, ptr, available);
    if (n == 0)
    {
        echo_unregister_client(key);
        return;
    }
    if (n < 0)
    {
        if (errno == EAGAIN || errno == EWOULDBLOCK)
        {
            selector_set_interest_key(key, echo_client_interest(client));
            return;
        }
        echo_unregister_client(key);
        return;
    }

    buffer_write_adv(&client->rb, n);
    selector_set_interest_key(key, echo_client_interest(client));
}

/*
 * WRITE handler del cliente: escribe bytes del buffer de vuelta al socket.
 *
 * Tras escribir, compacta el buffer para liberar espacio al inicio.
 * Las escrituras pueden ser parciales (n < pending): buffer_read_adv solo
 * consume lo efectivamente enviado.
 */
static void echo_client_write(struct selector_key *key)
{
    struct echo_client *client = key->data;
    size_t pending = 0;
    uint8_t *ptr = buffer_read_ptr(&client->rb, &pending);

    if (pending == 0)
    {
        selector_set_interest_key(key, echo_client_interest(client));
        return;
    }

    const ssize_t n = write(key->fd, ptr, pending);
    if (n < 0)
    {
        if (errno == EAGAIN || errno == EWOULDBLOCK)
        {
            selector_set_interest_key(key, echo_client_interest(client));
            return;
        }
        echo_unregister_client(key);
        return;
    }

    buffer_read_adv(&client->rb, n);
    buffer_compact(&client->rb);
    selector_set_interest_key(key, echo_client_interest(client));
}

/*
 * CLOSE handler del cliente: limpieza al desregistrar el fd.
 *
 * El selector NO cierra el fd automáticamente; somos responsables de
 * close() y free(). También decrementamos el contador global de clientes
 * activos (usado para graceful shutdown en main.c).
 */
static void echo_client_close(struct selector_key *key)
{
    struct echo_client *client = key->data;
    struct echo_server *srv = client != NULL ? client->srv : NULL;

    if (srv != NULL && srv->active_clients > 0)
    {
        srv->active_clients--;
    }

    if (key->fd >= 0)
    {
        close(key->fd);
    }

    free(client);
}

/*
 * READ handler del socket pasivo: acepta todas las conexiones pendientes.
 *
 * El while(true) drena la cola de accept() en una sola pasada del selector,
 * evitando dejar clientes esperando si muchos conectan a la vez.
 *
 * Por cada cliente nuevo:
 *   1. O_NONBLOCK en el fd
 *   2. calloc + init del buffer
 *   3. selector_register con OP_READ inicial
 */
static void echo_passive_read(struct selector_key *key)
{
    struct echo_server *srv = key->data;

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
                /* No hay más conexiones pendientes en este momento. */
                return;
            }
            return;
        }

        if (selector_fd_set_nio(client_fd) < 0)
        {
            close(client_fd);
            continue;
        }

        struct echo_client *client = calloc(1, sizeof(*client));
        if (client == NULL)
        {
            close(client_fd);
            continue;
        }

        client->srv = srv;
        buffer_init(&client->rb, ECHO_BUFFER_SIZE, client->backing);

        if (selector_register(key->s,
                              client_fd,
                              &echo_client_handler,
                              OP_READ,
                              client) != SELECTOR_SUCCESS)
        {
            free(client);
            close(client_fd);
            continue;
        }

        srv->active_clients++;
    }
}

/*
 * CLOSE handler del socket pasivo: se invoca al desregistrar el listen fd
 * (graceful shutdown). Marca listen_fd como cerrado en echo_server.
 */
static void echo_passive_close(struct selector_key *key)
{
    struct echo_server *srv = key->data;

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
 * Crea y configura el socket de escucha:
 *   - AF_INET6 con IPV6_V6ONLY=0  -> dual-stack (acepta IPv4 e IPv6)
 *   - SO_REUSEADDR                -> reutilizar puerto tras reinicio
 *   - listen(SOMAXCONN)             -> cola de conexiones pendientes
 *   - O_NONBLOCK                  -> accept no bloqueante
 *
 * Si port == 0, el SO asigna un puerto libre; bound_port devuelve el real.
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

/*
 * Inicializa el echo server: crea listen socket y lo registra en el selector.
 * stop apunta a un flag externo (main.c) para graceful shutdown.
 */
selector_status echo_server_init(fd_selector s,
                                 uint16_t port,
                                 volatile bool *stop,
                                 struct echo_server **out)
{
    if (s == NULL || out == NULL)
    {
        return SELECTOR_IARGS;
    }

    struct echo_server *srv = calloc(1, sizeof(*srv));
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
                          &echo_passive_handler,
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

/*
 * Destruye la estructura echo_server.
 * Si el listen fd sigue activo, lo desregistra (dispara echo_passive_close).
 * Los clientes ya aceptados deben haberse cerrado antes (via selector).
 */
void echo_server_destroy(struct echo_server *srv)
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

/*
 * Graceful shutdown — fase 1: dejar de aceptar conexiones nuevas.
 * Desregistra el listen fd; los clientes existentes siguen atendidos.
 */
void echo_server_stop_accepting(struct echo_server *srv)
{
    if (srv == NULL || srv->listen_fd < 0)
    {
        return;
    }

    selector_unregister_fd(srv->selector, srv->listen_fd);
    srv->listen_fd = -1;
}

/*
 * Una iteración del event loop: si *stop es true, cierra el listen socket
 * y luego delega en selector_select() para despachar I/O pendiente.
 */
selector_status echo_server_run_once(struct echo_server *srv)
{
    if (srv == NULL)
    {
        return SELECTOR_IARGS;
    }

    if (srv->stop != NULL && *srv->stop && srv->listen_fd >= 0)
    {
        echo_server_stop_accepting(srv);
    }

    return selector_select(srv->selector);
}

/* true cuando no queda listen socket ni clientes activos (servidor vacío). */
bool echo_server_is_empty(const struct echo_server *srv)
{
    if (srv == NULL)
    {
        return true;
    }

    return srv->listen_fd < 0 && srv->active_clients == 0;
}

uint16_t echo_server_port(const struct echo_server *srv)
{
    if (srv == NULL)
    {
        return 0;
    }

    return srv->port;
}
