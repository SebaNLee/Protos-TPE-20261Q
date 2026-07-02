#ifndef FLAGS_H
#define FLAGS_H

#include <stdint.h>

/* Inicializa el sistema de flags. El formato de flag_ids es el mismo que el parámetro __shortopts de getopt */
void setup_flags(int argc, char **argv, char *flag_ids);

/* Obtiene el valor de una flag, interpretándolo como unsigned long */
uint64_t get_flag_u64(char flag);

/* Obtiene directamente el valor de una flag */
char *get_flag_str(char flag);

#endif