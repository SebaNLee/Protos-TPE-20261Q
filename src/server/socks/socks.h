#ifndef SOCKS_H
#define SOCKS_H

#include <stdbool.h>
#include <stdint.h>

#include <netinet/in.h>

#include "shared/buffer.h"
#include "shared/selector.h"
#include "shared/stm.h"

#include "server/monitor/store.h"
#include "server/socks/auth/auth.h"
#include "server/socks/greeting/greeting.h"
#include "server/socks/request/request.h"

#define SOCKS_BUFFER_SIZE 4096

/*
 * Estados de la máquina de estados por sesión.
 *
 * El id numérico DEBE coincidir con el índice en socks_state_table[] (stm.c
 * lo verifica en stm_init). El flujo previsto es:
 *
 *   AUTH_GREETING → AUTH_USERPASS → REQUEST → RESOLVING (solo FQDN)
 *        → ORIGIN_CONNECTING → RELAY → DONE
 */
enum socks_state
{
    SOCKS_ST_AUTH_GREETING = 0, /* Cliente manda [05][nmethods][methods...] */
    SOCKS_ST_AUTH_USERPASS,     /* Cliente manda credenciales (RFC 1929) */
    SOCKS_ST_REQUEST,           /* Cliente manda CONNECT con destino */
    SOCKS_ST_RESOLVING,         /* getaddrinfo en thread (FQDN) */
    SOCKS_ST_ORIGIN_CONNECTING, /* connect() no bloqueante al destino */
    SOCKS_ST_RELAY,             /* Copia bytes cliente ↔ origen */
    SOCKS_ST_DONE,              /* Sesión terminada */
};

/*
 * Una sesión SOCKS: representa un browser conectado al proxy.
 *
 * A diferencia del echo (1 socket, 1 buffer), acá hay dos extremos:
 *
 *   client_fd  — socket hacia el browser
 *   origin_fd  — socket hacia el destino (-1 hasta que CONNECT tenga éxito)
 *
 * Buffers:
 *   c2o  — bytes que vienen del cliente (parser SOCKS o relay hacia origen)
 *   o2c  — bytes que van hacia el cliente (respuestas SOCKS o relay desde origen)
 *
 * En fases tempranas (greeting, auth, request) solo se usa client_fd;
 * c2o acumula lo que manda el browser y o2c las respuestas del proxy.
 * En RELAY, c2o y o2c canalizan tráfico hacia/desde origin_fd.
 */
struct socks_session
{
    struct socks_server *srv;
    int client_fd;
    int origin_fd;

    buffer c2o;
    buffer o2c;
    uint8_t c2o_backing[SOCKS_BUFFER_SIZE];
    uint8_t o2c_backing[SOCKS_BUFFER_SIZE];

    struct state_machine stm;
    socks_greeting_parser greeting; /* Parser paso 2: method negotiation */
    socks_auth_parser auth;         /* Parser paso 3: username/password */
    socks_request_parser request;   /* Parser paso 4: CONNECT */

    struct addrinfo *dns_result; /* Lista de getaddrinfo (liberar con freeaddrinfo) */
    struct addrinfo *dns_cursor; /* Entrada actual al reintentar connect() */
    int dns_gai_rc;              /* Código de retorno de getaddrinfo (0 = OK) */
    bool dns_resolving;          /* true mientras el thread de DNS está activo */

    /* Cierra la sesión una vez que o2c quedó vacío (p. ej. tras rechazar greeting). */
    bool close_after_flush;

    /* Dirección de destino parseada del CONNECT (IPv4/IPv6) o resuelta por DNS */
    struct sockaddr_storage dest_addr;
    socklen_t dest_addr_len;

    /* Integración con store: métricas, access log, max_connections */
    store_session_id store_id;
    time_t last_activity; /* para CONFIG timeout (idle) */
    bool dest_recorded;
};

/* Estado global del servidor proxy (equivalente a echo_server). */
struct socks_server
{
    fd_selector selector;
    int listen_fd;
    uint16_t port;
    size_t active_sessions;
    volatile bool *stop;         /* Apunta al flag de shutdown en main.c */
    struct monitor_store *store; /* usuarios + métricas + log compartidos con monitor */
};

selector_status socks_server_init(fd_selector s,
                                  uint16_t port,
                                  volatile bool *stop,
                                  struct monitor_store *store,
                                  struct socks_server **out);

/* Calcula OP_READ/OP_WRITE del client_fd según espacio en c2o y datos en o2c */
fd_interest socks_client_interest(struct socks_session *session);

void socks_server_destroy(struct socks_server *srv);

selector_status socks_server_run_once(struct socks_server *srv);

bool socks_server_is_empty(const struct socks_server *srv);

void socks_server_stop_accepting(struct socks_server *srv);

uint16_t socks_server_port(const struct socks_server *srv);

#endif
