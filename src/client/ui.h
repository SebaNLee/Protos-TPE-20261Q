#ifndef CLIENT_UI_H
#define CLIENT_UI_H

#include <stddef.h>
#include <stdint.h>

#include "client/protocol.h"

#define MAX_INPUT_LEN 200

typedef enum
{
    KEY_NONE = 0,
    KEY_UP,
    KEY_DOWN,
    KEY_ENTER,
    KEY_ESC,
} key_code;

void term_enter_raw(void);
void term_exit_raw(void);
int term_getkey(void);

void input_line(const char *prompt, char *buf, size_t max);
void input_password(const char *prompt, char *buf, size_t max);
long input_number(const char *prompt, long min, long max);
void wait_enter(void);

int select_menu(const char *items[], int count, const char *quit_label);

const char *fmt_bytes(uint64_t bytes);
void show_lines(const char *title, char lines[][MAX_RESP_LINE_LEN], int count, int skip);

#endif
