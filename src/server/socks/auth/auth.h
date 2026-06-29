#ifndef SOCKS5_AUTH_H
#define SOCKS5_AUTH_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* RFC 1929: usuario y contraseña de hasta 255 bytes cada uno. */
#define SOCKS_AUTH_MAX_LEN 255

/*
 * Resultado de alimentar el parser byte a byte.
 *
 * NEED_MORE — mensaje incompleto, faltan bytes.
 * PARSED    — mensaje completo (user + pass en el parser).
 * REJECT    — versión inválida o longitudes en 0.
 */
typedef enum
{
    SOCKS_AUTH_NEED_MORE,
    SOCKS_AUTH_PARSED,
    SOCKS_AUTH_REJECT,
} socks_auth_status;

/*
 * Estado interno del parser de autenticación.
 *
 * Ejemplo de mensaje del cliente para admin/admin:
 *   [01][05]['a']['d']['m']['i']['n'][05]['a']['d']['m']['i']['n']
 *    ↑   ↑   └──── 5 bytes ────┘      ↑   └──── 5 bytes ────┘
 *   ver  ulen                        plen
 */
typedef struct socks_auth_parser
{
    unsigned state;
    uint8_t uname_len;        /* Longitud total del usuario (ULEN) */
    uint8_t passwd_len;       /* Longitud total de la contraseña (PLEN) */
    uint8_t uname_remaining;  /* Bytes de usuario que faltan leer */
    uint8_t passwd_remaining; /* Bytes de contraseña que faltan leer */
    uint8_t uname[SOCKS_AUTH_MAX_LEN];
    uint8_t passwd[SOCKS_AUTH_MAX_LEN];
} socks_auth_parser;

void socks_auth_parser_init(socks_auth_parser *parser);

/* Procesa un byte del mensaje de auth. Llamar en orden hasta PARSED o REJECT. */
socks_auth_status socks_auth_parser_feed(socks_auth_parser *parser, uint8_t byte);

size_t socks_auth_username_len(const socks_auth_parser *parser);

size_t socks_auth_password_len(const socks_auth_parser *parser);

const uint8_t *socks_auth_username(const socks_auth_parser *parser);

const uint8_t *socks_auth_password(const socks_auth_parser *parser);

struct monitor_store;

/*
 * Compara credenciales ya parseadas contra monitor_store.
 * Llamar desde socks.c cuando feed() devuelve PARSED.
 */
bool socks_auth_validate(const socks_auth_parser *parser,
                         struct monitor_store *store);

#endif
