/*
 * socks5_auth.c — Autenticación username/password (RFC 1929).
 *
 * Este mensaje va DESPUÉS del greeting (cuando el servidor eligió método 0x02).
 *
 * Cliente manda:
 *   VER(1) | ULEN(1) | UNAME(1..255) | PLEN(1) | PASSWD(1..255)
 *
 * Servidor responde:
 *   VER(1) | STATUS(1)     STATUS=0x00 ok, 0x01 fallo
 *
 * El parser es una máquina de estados byte-a-byte (igual que socks5_greeting).
 * socks.c consume c2o, llama a feed(), y según el resultado encola la
 * respuesta en o2c.
 */
#include "socks5_auth.h"

#include <string.h>

#define AUTH_VERSION 0x01

/* Estados del parser (orden del mensaje en el wire). */
enum auth_state
{
    AUTH_VER = 0,   /* Espera 0x01 */
    AUTH_ULEN,      /* Lee longitud del usuario */
    AUTH_UNAME,     /* Lee ULEN bytes de nombre */
    AUTH_PLEN,      /* Lee longitud de la contraseña */
    AUTH_PASSWD,    /* Lee PLEN bytes de contraseña */
};

void socks_auth_parser_init(socks_auth_parser *parser)
{
    parser->state = AUTH_VER;
    parser->uname_len = 0;
    parser->passwd_len = 0;
    parser->uname_remaining = 0;
    parser->passwd_remaining = 0;
}

size_t socks_auth_username_len(const socks_auth_parser *parser)
{
    return parser != NULL ? parser->uname_len : 0;
}

size_t socks_auth_password_len(const socks_auth_parser *parser)
{
    return parser != NULL ? parser->passwd_len : 0;
}

const uint8_t *socks_auth_username(const socks_auth_parser *parser)
{
    return parser != NULL ? parser->uname : NULL;
}

const uint8_t *socks_auth_password(const socks_auth_parser *parser)
{
    return parser != NULL ? parser->passwd : NULL;
}

/*
 * Valida usuario/contraseña contra la lista del servidor.
 */
 // TODO: reemplazar por tabla de usuarios del protocolo de monitoreo del TP.
bool socks_auth_validate(const socks_auth_parser *parser)
{
    static const char valid_user[] = "admin";
    static const char valid_pass[] = "admin";

    if (parser == NULL)
    {
        return false;
    }

    if (parser->uname_len != strlen(valid_user) ||
        parser->passwd_len != strlen(valid_pass))
    {
        return false;
    }

    return memcmp(parser->uname, valid_user, parser->uname_len) == 0 &&
           memcmp(parser->passwd, valid_pass, parser->passwd_len) == 0;
}

/*
 * Procesa un byte. Retorna:
 *   NEED_MORE — seguir leyendo del cliente.
 *   PARSED    — mensaje completo; socks.c debe llamar socks_auth_validate().
 *   REJECT    — mensaje mal formado (versión ≠ 1, ulen=0, plen=0).
 */
socks_auth_status socks_auth_parser_feed(socks_auth_parser *parser, uint8_t byte)
{
    switch (parser->state)
    {
    case AUTH_VER:
        if (byte != AUTH_VERSION)
        {
            return SOCKS_AUTH_REJECT;
        }
        parser->state = AUTH_ULEN;
        return SOCKS_AUTH_NEED_MORE;

    case AUTH_ULEN:
        if (byte == 0)
        {
            return SOCKS_AUTH_REJECT;
        }
        parser->uname_len = byte;
        parser->uname_remaining = byte;
        parser->state = AUTH_UNAME;
        return SOCKS_AUTH_NEED_MORE;

    case AUTH_UNAME:
        /* Guarda cada carácter del usuario y cuenta hacia atrás. */
        parser->uname[parser->uname_len - parser->uname_remaining] = byte;
        parser->uname_remaining--;
        if (parser->uname_remaining > 0)
        {
            return SOCKS_AUTH_NEED_MORE;
        }
        parser->state = AUTH_PLEN;
        return SOCKS_AUTH_NEED_MORE;

    case AUTH_PLEN:
        if (byte == 0)
        {
            return SOCKS_AUTH_REJECT;
        }
        parser->passwd_len = byte;
        parser->passwd_remaining = byte;
        parser->state = AUTH_PASSWD;
        return SOCKS_AUTH_NEED_MORE;

    case AUTH_PASSWD:
        parser->passwd[parser->passwd_len - parser->passwd_remaining] = byte;
        parser->passwd_remaining--;
        if (parser->passwd_remaining > 0)
        {
            return SOCKS_AUTH_NEED_MORE;
        }
        return SOCKS_AUTH_PARSED;

    default:
        return SOCKS_AUTH_REJECT;
    }
}
