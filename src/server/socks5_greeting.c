/*
 * socks5_greeting.c — Parser del method negotiation (RFC 1928 Section 3).
 *
 * Cliente:  VER | NMETHODS | METHODS[1..NMETHODS]
 * Servidor: VER | METHOD   (0x02 = username/password, 0xFF = rechazo)
 */
#include "socks5_greeting.h"

#define SOCKS_VERSION 0x05
#define SOCKS_METHOD_USERPASS 0x02

enum greeting_state
{
    GREETING_VER = 0,
    GREETING_NMETHODS,
    GREETING_METHODS,
};

void socks_greeting_parser_init(socks_greeting_parser *parser)
{
    parser->state = GREETING_VER;
    parser->methods_remaining = 0;
    parser->has_userpass = false;
}

socks_greeting_status socks_greeting_parser_feed(socks_greeting_parser *parser,
                                                 uint8_t byte)
{
    switch (parser->state)
    {
    case GREETING_VER:
        if (byte != SOCKS_VERSION)
        {
            return SOCKS_GREETING_REJECT;
        }
        parser->state = GREETING_NMETHODS;
        return SOCKS_GREETING_NEED_MORE;

    case GREETING_NMETHODS:
        if (byte == 0)
        {
            return SOCKS_GREETING_REJECT;
        }
        parser->methods_remaining = byte;
        parser->state = GREETING_METHODS;
        return SOCKS_GREETING_NEED_MORE;

    case GREETING_METHODS:
        if (byte == SOCKS_METHOD_USERPASS)
        {
            parser->has_userpass = true;
        }
        parser->methods_remaining--;
        if (parser->methods_remaining > 0)
        {
            return SOCKS_GREETING_NEED_MORE;
        }
        return parser->has_userpass ? SOCKS_GREETING_ACCEPT
                                    : SOCKS_GREETING_REJECT;

    default:
        return SOCKS_GREETING_REJECT;
    }
}
