#ifndef SOCKS5_REQUEST_H
#define SOCKS5_REQUEST_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include <netinet/in.h>

#define SOCKS_REQUEST_FQDN_MAX 255

/*
 * Resultado de alimentar el parser byte a byte.
 *
 *   NEED_MORE     — mensaje incompleto; seguir leyendo de c2o
 *   PARSED_ADDR   — IPv4 o IPv6 listos en dest_addr (sin DNS)
 *   PARSED_FQDN   — hostname en fqdn + dest_port; socks.c debe resolver DNS
 *   REJECT        — versión/CMD/ATYP inválidos
 */
typedef enum
{
    SOCKS_REQUEST_NEED_MORE,
    SOCKS_REQUEST_PARSED_ADDR, /* dest_addr listo (IPv4 o IPv6) */
    SOCKS_REQUEST_PARSED_FQDN, /* hostname + dest_port; requiere DNS */
    SOCKS_REQUEST_REJECT,
} socks_request_status;

/*
 * Estado interno del parser CONNECT (RFC 1928 §4).
 *
 * Ejemplo IPv4 a 1.1.1.1:80:
 *   05 01 00 01 01 01 01 01 00 50
 *   │  │  │  │  └─ 4 bytes IP ─┘ └── puerto big-endian
 *   │  │  │  └── ATYP=IPv4
 *   │  │  └── RSV=0
 *   │  └── CMD=CONNECT
 *   └── VER=5
 *
 * Ejemplo FQDN a example.com:80:
 *   05 01 00 03 0b 65 78 61 6d 70 6c 65 2e 63 6f 6d 00 50
 *                  │  └──── hostname (11 bytes) ────┘ └── 80
 *                  └── longitud del nombre
 */
typedef struct socks_request_parser
{
    unsigned state;
    uint8_t cmd;
    uint8_t atyp;
    uint8_t addr_remaining;   /* bytes de IP que faltan (4 o 16) */
    uint8_t fqdn_len;
    uint8_t fqdn_remaining;
    char fqdn[SOCKS_REQUEST_FQDN_MAX + 1];
    uint8_t port_hi;
    struct sockaddr_storage dest_addr; /* IPv4/IPv6 ya con sin_family */
    socklen_t dest_addr_len;
    uint16_t dest_port; /* host byte order; se convierte al armar sockaddr */
} socks_request_parser;

void socks_request_parser_init(socks_request_parser *parser);

socks_request_status socks_request_parser_feed(socks_request_parser *parser,
                                               uint8_t byte);

uint16_t socks_request_dest_port(const socks_request_parser *parser);

const struct sockaddr *socks_request_dest_addr(const socks_request_parser *parser);

socklen_t socks_request_dest_addr_len(const socks_request_parser *parser);

const char *socks_request_fqdn(const socks_request_parser *parser);

#endif
