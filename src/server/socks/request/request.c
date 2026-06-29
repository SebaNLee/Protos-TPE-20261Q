/*
 * socks5_request.c — Parser del CONNECT request (RFC 1928 Section 4).
 *
 * Este mensaje va DESPUÉS de autenticarse (paso 3).
 *
 * Cliente manda:
 *   VER(1) | CMD(1) | RSV(1) | ATYP(1) | DST.ADDR | DST.PORT(2)
 *
 * Servidor responde (lo hace socks.c, no este módulo):
 *   VER(1) | REP(1) | RSV(1) | ATYP(1) | BND.ADDR | BND.PORT(2)
 *
 * Soporta ATYP 0x01 (IPv4), 0x03 (FQDN), 0x04 (IPv6).
 * Solo CMD 0x01 (CONNECT); BIND y UDP ASSOCIATE se rechazan.
 *
 * Mismo patrón que greeting/auth: feed() procesa un byte y devuelve
 * NEED_MORE hasta tener el mensaje completo.
 */
#include "request.h"

#include <arpa/inet.h>
#include <string.h>

#define SOCKS_VERSION 0x05
#define SOCKS_CMD_CONNECT 0x01
#define SOCKS_ATYP_IPV4 0x01
#define SOCKS_ATYP_FQDN 0x03
#define SOCKS_ATYP_IPV6 0x04

enum request_state
{
    REQ_VER = 0,   /* Espera 0x05 */
    REQ_CMD,       /* Espera 0x01 (CONNECT) */
    REQ_RSV,       /* Espera 0x00 */
    REQ_ATYP,      /* Elige rama IPv4 / FQDN / IPv6 */
    REQ_ADDR_IPV4, /* 4 bytes de dirección */
    REQ_ADDR_IPV6, /* 16 bytes de dirección */
    REQ_FQDN_LEN,  /* 1 byte: longitud del hostname */
    REQ_FQDN,      /* N bytes del hostname */
    REQ_PORT_HI,   /* byte alto del puerto (big-endian) */
    REQ_PORT_LO,   /* byte bajo → mensaje completo */
};

void socks_request_parser_init(socks_request_parser *parser)
{
    parser->state = REQ_VER;
    parser->cmd = 0;
    parser->atyp = 0;
    parser->addr_remaining = 0;
    parser->fqdn_len = 0;
    parser->fqdn_remaining = 0;
    parser->fqdn[0] = '\0';
    parser->port_hi = 0;
    parser->dest_addr_len = 0;
    parser->dest_port = 0;
    memset(&parser->dest_addr, 0, sizeof(parser->dest_addr));
}

uint16_t socks_request_dest_port(const socks_request_parser *parser)
{
    return parser != NULL ? parser->dest_port : 0;
}

const struct sockaddr *socks_request_dest_addr(const socks_request_parser *parser)
{
    if (parser == NULL || parser->dest_addr_len == 0)
    {
        return NULL;
    }
    return (const struct sockaddr *)&parser->dest_addr;
}

socklen_t socks_request_dest_addr_len(const socks_request_parser *parser)
{
    return parser != NULL ? parser->dest_addr_len : 0;
}

const char *socks_request_fqdn(const socks_request_parser *parser)
{
    return parser != NULL ? parser->fqdn : NULL;
}

socks_request_status socks_request_parser_feed(socks_request_parser *parser,
                                               uint8_t byte)
{
    switch (parser->state)
    {
    case REQ_VER:
        if (byte != SOCKS_VERSION)
        {
            return SOCKS_REQUEST_REJECT;
        }
        parser->state = REQ_CMD;
        return SOCKS_REQUEST_NEED_MORE;

    case REQ_CMD:
        if (byte != SOCKS_CMD_CONNECT)
        {
            return SOCKS_REQUEST_REJECT;
        }
        parser->cmd = byte;
        parser->state = REQ_RSV;
        return SOCKS_REQUEST_NEED_MORE;

    case REQ_RSV:
        if (byte != 0x00)
        {
            return SOCKS_REQUEST_REJECT;
        }
        parser->state = REQ_ATYP;
        return SOCKS_REQUEST_NEED_MORE;

    case REQ_ATYP:
        parser->atyp = byte;
        if (byte == SOCKS_ATYP_IPV4)
        {
            /* Armamos sockaddr_in de a poco; el puerto se agrega al final */
            parser->addr_remaining = 4;
            memset(&parser->dest_addr, 0, sizeof(parser->dest_addr));
            struct sockaddr_in *addr =
                (struct sockaddr_in *)&parser->dest_addr;
            addr->sin_family = AF_INET;
            parser->dest_addr_len = sizeof(*addr);
            parser->state = REQ_ADDR_IPV4;
            return SOCKS_REQUEST_NEED_MORE;
        }
        if (byte == SOCKS_ATYP_IPV6)
        {
            parser->addr_remaining = 16;
            memset(&parser->dest_addr, 0, sizeof(parser->dest_addr));
            struct sockaddr_in6 *addr =
                (struct sockaddr_in6 *)&parser->dest_addr;
            addr->sin6_family = AF_INET6;
            parser->dest_addr_len = sizeof(*addr);
            parser->state = REQ_ADDR_IPV6;
            return SOCKS_REQUEST_NEED_MORE;
        }
        if (byte == SOCKS_ATYP_FQDN)
        {
            parser->state = REQ_FQDN_LEN;
            return SOCKS_REQUEST_NEED_MORE;
        }
        return SOCKS_REQUEST_REJECT;

    case REQ_ADDR_IPV4:
    {
        struct sockaddr_in *addr = (struct sockaddr_in *)&parser->dest_addr;
        const size_t idx = 4 - parser->addr_remaining;
        ((uint8_t *)&addr->sin_addr)[idx] = byte;
        parser->addr_remaining--;
        if (parser->addr_remaining > 0)
        {
            return SOCKS_REQUEST_NEED_MORE;
        }
        parser->state = REQ_PORT_HI;
        return SOCKS_REQUEST_NEED_MORE;
    }

    case REQ_ADDR_IPV6:
    {
        struct sockaddr_in6 *addr = (struct sockaddr_in6 *)&parser->dest_addr;
        const size_t idx = 16 - parser->addr_remaining;
        addr->sin6_addr.s6_addr[idx] = byte;
        parser->addr_remaining--;
        if (parser->addr_remaining > 0)
        {
            return SOCKS_REQUEST_NEED_MORE;
        }
        parser->state = REQ_PORT_HI;
        return SOCKS_REQUEST_NEED_MORE;
    }

    case REQ_FQDN_LEN:
        if (byte == 0)
        {
            return SOCKS_REQUEST_REJECT;
        }
        parser->fqdn_len = byte;
        parser->fqdn_remaining = byte;
        parser->state = REQ_FQDN;
        return SOCKS_REQUEST_NEED_MORE;

    case REQ_FQDN:
        parser->fqdn[parser->fqdn_len - parser->fqdn_remaining] = (char)byte;
        parser->fqdn_remaining--;
        if (parser->fqdn_remaining > 0)
        {
            return SOCKS_REQUEST_NEED_MORE;
        }
        parser->fqdn[parser->fqdn_len] = '\0';
        parser->state = REQ_PORT_HI;
        return SOCKS_REQUEST_NEED_MORE;

    case REQ_PORT_HI:
        parser->port_hi = byte;
        parser->state = REQ_PORT_LO;
        return SOCKS_REQUEST_NEED_MORE;

    case REQ_PORT_LO:
        parser->dest_port = (uint16_t)((parser->port_hi << 8) | byte);
        if (parser->atyp == SOCKS_ATYP_FQDN)
        {
            /* FQDN: no hay IP todavía; socks.c llamará getaddrinfo */
            return SOCKS_REQUEST_PARSED_FQDN;
        }
        /* IPv4/IPv6: copiar puerto al sockaddr y listo para connect() */
        if (parser->dest_addr.ss_family == AF_INET)
        {
            struct sockaddr_in *addr = (struct sockaddr_in *)&parser->dest_addr;
            addr->sin_port = htons(parser->dest_port);
        }
        else if (parser->dest_addr.ss_family == AF_INET6)
        {
            struct sockaddr_in6 *addr =
                (struct sockaddr_in6 *)&parser->dest_addr;
            addr->sin6_port = htons(parser->dest_port);
        }
        return SOCKS_REQUEST_PARSED_ADDR;

    default:
        return SOCKS_REQUEST_REJECT;
    }
}
