#ifndef FLAGS_H
#define FLAGS_H

#include <stdint.h>

/* Inicializa el sistema de flags. El formato de flag_ids es el mismo que el parámetro __shortopts de getopt */
int setup_flags(int argc, char **argv, char *flag_ids);

/* Obtiene el argumento de una flag, interpretándolo como long */
long get_flag_long(char flag);

/* Obtiene directamente el argumento de una flag como string */
char *get_flag_str(char flag);

/* Retorna 1 si la flag esta presente, 0 si no */
int has_flag(char flag);

#endif