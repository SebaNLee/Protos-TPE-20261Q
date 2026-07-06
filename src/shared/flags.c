#include "flags.h"
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define MAX_FLAG_REPEATS 256

static char *values[256] = {0};
static int initialized = 0;
static int flag_counts[256] = {0};
static char *flag_values[256][MAX_FLAG_REPEATS];

int setup_flags(int argc, char **argv, char *flag_ids)
{
    if (initialized)
        return -1;

    int opt;
    while ((opt = getopt(argc, argv, flag_ids)) != -1)
    {
        if (opt == '?' || opt == ':')
            continue;

        char *p = strchr(flag_ids, opt);
        int idx = (unsigned char)opt;
        char *value;

        if (p && p[1] == ':')
        {
            value = optarg;
        }
        else
        {
            value = "";
        }

        values[idx] = value;
        if (flag_counts[idx] < MAX_FLAG_REPEATS)
        {
            flag_values[idx][flag_counts[idx]] = value;
        }

        flag_counts[idx]++;
    }

    initialized = 1;
    return 0;
}

long get_flag_long(char flag)
{
    char *value = values[(unsigned char)flag];
    if (!value)
        return 0;
    return strtol(value, NULL, 10);
}

char *get_flag_str(char flag)
{
    return values[(unsigned char)flag];
}

char *get_flag_str_nth(char flag, int n)
{
    int idx = (unsigned char)flag;

    if (n < 0 || n >= flag_counts[idx] || n >= MAX_FLAG_REPEATS)
    {
        return NULL;
    }

    return flag_values[idx][n];
}

int has_flag(char flag)
{
    return get_flag_str(flag) != NULL;
}

int get_flag_count(char flag)
{
    return flag_counts[(unsigned char)flag];
}
