#ifndef SOCKS5_GREETING_H
#define SOCKS5_GREETING_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define SOCKS_METHOD_USERPASS 0x02
#define SOCKS_METHOD_NOAUTH 0x00

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
    bool has_noauth;
    uint8_t chosen_method; // 0x00 o 0x02, post ACCEPT
} socks_greeting_parser;

void socks_greeting_parser_init(socks_greeting_parser *parser);

socks_greeting_status socks_greeting_parser_feed(socks_greeting_parser *parser, uint8_t byte);

uint8_t socks_greeting_chosen_method(const socks_greeting_parser *parser);

#endif
