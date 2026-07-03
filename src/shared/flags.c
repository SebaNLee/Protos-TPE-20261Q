#include "flags.h"
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static char *values[256] = {0};
static int initialized = 0;

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
        if (p && p[1] == ':')
        {
            values[(unsigned char)opt] = optarg;
        }
        else
        {
            values[(unsigned char)opt] = "";
        }
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

int has_flag(char flag)
{
    return get_flag_str(flag) != NULL;
}