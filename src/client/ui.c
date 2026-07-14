#include "client/ui.h"

#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <termios.h>
#include <unistd.h>

static struct termios saved_term;
static bool raw_active = false;

static void sigint_handler(int sig)
{
    (void)sig;
    write(STDOUT_FILENO, "\033[?25h", 6);
    tcsetattr(STDIN_FILENO, TCSANOW, &saved_term);
    _exit(1);
}

void term_enter_raw(void)
{
    struct termios raw;
    tcgetattr(STDIN_FILENO, &saved_term);
    raw = saved_term;
    raw.c_lflag &= ~(ICANON | ECHO);
    raw.c_cc[VMIN] = 1;
    raw.c_cc[VTIME] = 0;
    tcsetattr(STDIN_FILENO, TCSAFLUSH, &raw);
    raw_active = true;
    signal(SIGINT, sigint_handler);
}

void term_exit_raw(void)
{
    if (raw_active)
    {
        tcsetattr(STDIN_FILENO, TCSANOW, &saved_term);
        raw_active = false;
    }
}

int term_getkey(void)
{
    char c;
    if (read(STDIN_FILENO, &c, 1) != 1)
        return KEY_NONE;
    if (c == '\033')
    {
        char seq[2];
        if (read(STDIN_FILENO, &seq[0], 1) != 1)
            return KEY_ESC;
        if (read(STDIN_FILENO, &seq[1], 1) != 1)
            return KEY_ESC;
        if (seq[0] == '[')
        {
            if (seq[1] == 'A')
                return KEY_UP;
            if (seq[1] == 'B')
                return KEY_DOWN;
        }
        return KEY_ESC;
    }
    if (c == '\n' || c == '\r')
        return KEY_ENTER;
    return (unsigned char)c;
}

void input_line(const char *prompt, char *buf, size_t max)
{
    printf("%s", prompt);
    fflush(stdout);
    if (fgets(buf, (int)max, stdin) == NULL)
    {
        buf[0] = '\0';
        return;
    }
    size_t len = strlen(buf);
    while (len > 0 && (buf[len - 1] == '\n' || buf[len - 1] == '\r'))
        buf[--len] = '\0';
}

void input_password(const char *prompt, char *buf, size_t max)
{
    struct termios old, noecho;
    tcgetattr(STDIN_FILENO, &old);
    saved_term = old;
    signal(SIGINT, sigint_handler);
    noecho = old;
    noecho.c_lflag &= ~ECHO;
    tcsetattr(STDIN_FILENO, TCSAFLUSH, &noecho);

    printf("%s", prompt);
    fflush(stdout);
    if (fgets(buf, (int)max, stdin) == NULL)
        buf[0] = '\0';

    tcsetattr(STDIN_FILENO, TCSAFLUSH, &old);

    size_t len = strlen(buf);
    while (len > 0 && (buf[len - 1] == '\n' || buf[len - 1] == '\r'))
        buf[--len] = '\0';
    printf("\n");
}

long input_number(const char *prompt, long min, long max)
{
    char buf[64];
    while (1)
    {
        input_line(prompt, buf, sizeof(buf));
        char *end = NULL;
        long val = strtol(buf, &end, 10);
        if (*end == '\0' && val >= min && val <= max)
            return val;
        printf("  Invalid (range %ld-%ld)\n", min, max);
    }
}

void wait_enter(void)
{
    printf("\nPress Enter to continue...");
    fflush(stdout);
    char buf[64];
    fgets(buf, sizeof(buf), stdin);
}

int select_menu(const char *items[], int count, const char *quit_label)
{
    int sel = 0;

    printf("\n");
    for (int i = 0; i < count; i++)
        printf("%c %s\n", i == sel ? '>' : ' ', items[i]);
    printf("\n[Enter] Select  [\xe2\x86\x91\xe2\x86\x93] Navigate  [q] %s\n", quit_label);

    term_enter_raw();

    while (1)
    {
        int key = term_getkey();

        if (key == KEY_UP)
        {
            sel = (sel - 1 + count) % count;
        }
        else if (key == KEY_DOWN)
        {
            sel = (sel + 1) % count;
        }
        else if (key == KEY_ENTER)
        {
            term_exit_raw();
            return sel;
        }
        else if (key == KEY_ESC || key == 'q')
        {
            term_exit_raw();
            return count - 1;
        }
        else
        {
            continue;
        }

        int n = count + 3;
        printf("\033[%dA", n);
        printf("\r\033[K\n");
        for (int i = 0; i < count; i++)
            printf("\r\033[K%c %s\n", i == sel ? '>' : ' ', items[i]);
        printf("\r\033[K\n");
        printf("\r\033[K[Enter] Select  [\xe2\x86\x91\xe2\x86\x93] Navigate  [q] %s\n", quit_label);
    }
}

const char *fmt_bytes(uint64_t bytes)
{
    static char buf[32];
    if (bytes >= 1073741824ULL)
        snprintf(buf, sizeof(buf), "%.1f GiB", (double)bytes / 1073741824.0);
    else if (bytes >= 1048576)
        snprintf(buf, sizeof(buf), "%.1f MiB", (double)bytes / 1048576.0);
    else if (bytes >= 1024)
        snprintf(buf, sizeof(buf), "%.1f KiB", (double)bytes / 1024.0);
    else
        snprintf(buf, sizeof(buf), "%llu B", (unsigned long long)bytes);
    return buf;
}

void show_lines(const char *title, char lines[][MAX_RESP_LINE_LEN], int count, int skip)
{
    printf("\n%s\n", title);
    for (int i = skip; i < count; i++)
    {
        const char *line = lines[i];
        if (strncmp(line, "+OK ", 4) == 0)
            line += 4;
        printf("  %s\n", line);
    }
}
