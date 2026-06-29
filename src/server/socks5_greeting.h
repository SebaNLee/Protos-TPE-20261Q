#ifndef SOCKS5_GREETING_H
#define SOCKS5_GREETING_H

#include <stdbool.h>
#include <stdint.h>

typedef enum
{
    SOCKS_GREETING_NEED_MORE,
    SOCKS_GREETING_ACCEPT,
    SOCKS_GREETING_REJECT,
} socks_greeting_status;

typedef struct socks_greeting_parser
{
    unsigned state;
    uint8_t methods_remaining;
    bool has_userpass;
} socks_greeting_parser;

void socks_greeting_parser_init(socks_greeting_parser *parser);

socks_greeting_status socks_greeting_parser_feed(socks_greeting_parser *parser,
                                                 uint8_t byte);

#endif
