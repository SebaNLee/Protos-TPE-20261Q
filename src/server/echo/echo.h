#ifndef ECHO_H
#define ECHO_H

#include <stdbool.h>
#include <stdint.h>

#include "shared/buffer.h"
#include "shared/selector.h"

#define ECHO_BUFFER_SIZE 4096

/* IDEA:
 * Cada cliente tiene un buffer. Lo que llega por read se guarda ahí y se
 * devuelve en el write_handler cuando el socket está listo para escribir
 */

struct echo_client
{
    struct echo_server *srv;
    buffer rb;
    uint8_t backing[ECHO_BUFFER_SIZE];
};

struct echo_server
{
    fd_selector selector;
    int listen_fd;
    uint16_t port;
    size_t active_clients;
    volatile bool *stop;
};

selector_status echo_server_init(fd_selector s,
                                 uint16_t port,
                                 volatile bool *stop,
                                 struct echo_server **out);

// determina si el selector debe esperar read,write o ambas dado un cliente
fd_interest echo_client_interest(struct echo_client *c);

// destruye el echo server
// las conexiones ya aceptadas siguen activas. Se tienen que cerrar antes via el selector.
void echo_server_destroy(struct echo_server *srv);

// Ejecuta una sola iteración del selector
selector_status echo_server_run_once(struct echo_server *srv);

// devuelve true si no hay socket pasivo ni clientes activos
bool echo_server_is_empty(const struct echo_server *srv);

// Deja de aceptar conexiones nuevas cerrando el socket pasivo en el selector
// Las conexiones ya aceptadas siguen activas
void echo_server_stop_accepting(struct echo_server *srv);

// Devuelve el puerto en el que escucha el servidor
uint16_t echo_server_port(const struct echo_server *srv);

#endif
