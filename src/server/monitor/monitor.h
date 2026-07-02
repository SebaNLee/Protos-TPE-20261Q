#ifndef MONITOR_H
#define MONITOR_H

/*
 * monitor.h — servidor de administración en el puerto de monitoreo.
 * Comparte selector y store con SOCKS; los cambios aplican al instante.
 */

#include <stdbool.h>
#include <stdint.h>

#include "server/monitor/store.h"
#include "shared/selector.h"

#define MONITOR_BUFFER_SIZE 4096
#define MONITOR_LINE_MAX 512

/*
 * Estado global del puerto de administración (segundo socket pasivo).
 *
 *   listen_fd        — socket pasivo (monitor_passive_handler)
 *   active_sessions  — clientes admin conectados (para drain en shutdown)
 *   stop             — puntero a flag SIGINT/SIGTERM (main.c)
 *   store            — estado compartido con SOCKS
 */
struct monitor_server
{
    fd_selector selector;
    int listen_fd;
    uint16_t port;
    size_t active_sessions;
    volatile bool *stop;
    struct monitor_store *store;
};

/* Registra el socket pasivo en el selector compartido con SOCKS. */
selector_status monitor_server_init(fd_selector s,
                                    uint16_t port,
                                    volatile bool *stop,
                                    struct monitor_store *store,
                                    struct monitor_server **out);

/* Desregistra el socket pasivo y libera monitor_server. */
void monitor_server_destroy(struct monitor_server *srv);

/* Una iteración del selector; si stop=true deja de aceptar antes de select. */
selector_status monitor_server_run_once(struct monitor_server *srv);

/* true cuando no quedan clientes admin ni socket pasivo (drain completo). */
bool monitor_server_is_empty(const struct monitor_server *srv);

/* Cierra el listen_fd sin esperar a que terminen las sesiones activas. */
void monitor_server_stop_accepting(struct monitor_server *srv);

/* Devuelve el puerto en el que escucha */
uint16_t monitor_server_port(const struct monitor_server *srv);

#endif
