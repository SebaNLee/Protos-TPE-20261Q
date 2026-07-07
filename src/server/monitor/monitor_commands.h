#ifndef MONITOR_COMMANDS_H
#define MONITOR_COMMANDS_H

/*
 * monitor_commands.h — parseo y ejecución de comandos ChugusMonitor.
 * Sin sockets: recibe bytes, arma líneas y escribe respuestas en wb.
 */

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "server/monitor/monitor.h"
#include "server/monitor/store.h"
#include "shared/buffer.h"

#define MONITOR_COMMANDS_GREETING "+OK ChugusMonitor v1.0\n"

/*
 * Estados de autenticación por sesión admin.
 *
 *   AWAIT_AUTH      → AUTH y HELP; resto → -ERR not authenticated
 *   AUTHENTICATED   → todos los comandos excepto AUTH repetido
 */
typedef enum
{
    MONITOR_ST_AWAIT_AUTH = 0,
    MONITOR_ST_AUTHENTICATED,
} monitor_commands_state;

/*
 * Estado del protocolo por conexión admin (sin sockets).
 *
 *   line_buf / line_len — acumulador hasta '\n'
 *   wb                  — respuestas pendientes de enviar
 *   close_after_flush   — QUIT: cerrar cuando wb quede vacío
 */
struct monitor_commands_session
{
    monitor_commands_state state;
    struct monitor_store *store;
    buffer wb;
    uint8_t wb_backing[MONITOR_BUFFER_SIZE];
    char line_buf[MONITOR_LINE_MAX + 1];
    size_t line_len;
    bool close_after_flush;
};

/* Resetea estado de auth, línea y buffer de salida para una sesión nueva. */
void monitor_commands_session_init(struct monitor_commands_session *session, struct monitor_store *store);

/* Encola el greeting automático al conectar (monitor.c lo llama en accept). */
void monitor_commands_queue_greeting(struct monitor_commands_session *session);

/* Alimenta bytes del socket; monitor.c drena rb con esta función. */
void monitor_commands_feed(struct monitor_commands_session *session, const uint8_t *data, size_t len);

/* Half-close: procesa la última línea aunque no termine en '\n'. */
void monitor_commands_flush_on_eof(struct monitor_commands_session *session);

/* Lee respuestas de wb para escribir al socket (monitor_client_write). */
size_t monitor_commands_wb_read(struct monitor_commands_session *session, uint8_t *out, size_t max);

/* true tras QUIT cuando wb ya se vació (monitor.c cierra el fd). */
bool monitor_commands_should_close(const struct monitor_commands_session *session);

#endif
