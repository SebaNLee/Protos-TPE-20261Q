/*
 * auth.c — Autenticación username/password de SOCKS5 (RFC 1929).
 *
 * Este mensaje va DESPUÉS del greeting, cuando el servidor eligió método 0x02.
 *
 * Formato en el wire (cliente → servidor):
 *   VER(1) | ULEN(1) | UNAME(1..255) | PLEN(1) | PASSWD(1..255)
 *
 * Respuesta del servidor:
 *   VER(1) | STATUS(1)     STATUS=0x00 ok, 0x01 fallo
 *
 * El parser avanza byte a byte (igual que greeting/request).
 * socks.c lee de c2o, llama feed(), y según el resultado encola la respuesta en o2c.
 *
 * Las credenciales se validan contra monitor_store (misma tabla que ADD_USER).
 */
#include "auth.h"

#include "server/monitor/store.h"

#include <string.h>

#define AUTH_VERSION 0x01

/* Estados del parser (orden del mensaje en el wire). */
enum auth_state
{
    AUTH_VER = 0, /* Espera 0x01 */
    AUTH_ULEN,    /* Lee longitud del usuario */
    AUTH_UNAME,   /* Lee ULEN bytes de nombre */
    AUTH_PLEN,    /* Lee longitud de la contraseña */
    AUTH_PASSWD,  /* Lee PLEN bytes de contraseña */
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

bool socks_auth_validate(const socks_auth_parser *parser,
                         struct monitor_store *store)
{
    char username[SOCKS_AUTH_MAX_LEN + 1];
    char password[SOCKS_AUTH_MAX_LEN + 1];

    /*
     * Compara user+pass contra la tabla compartida del store.
     * Cualquier rol (user o admin) puede autenticarse en SOCKS.
     * El rol admin solo importa para el puerto de monitoreo (8080).
     */
    if (parser == NULL || store == NULL)
    {
        return false;
    }

    if (parser->uname_len == 0 || parser->uname_len > SOCKS_AUTH_MAX_LEN ||
        parser->passwd_len == 0 || parser->passwd_len > SOCKS_AUTH_MAX_LEN)
    {
        return false;
    }

    memcpy(username, parser->uname, parser->uname_len);
    username[parser->uname_len] = '\0';
    memcpy(password, parser->passwd, parser->passwd_len);
    password[parser->passwd_len] = '\0';

    return store_user_validate(store, username, password);
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
