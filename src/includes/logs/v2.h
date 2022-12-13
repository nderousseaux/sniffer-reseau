// Fonctions d'afficage des logs, pour le verbose = 2

#ifndef LOGS_V2_H
#define LOGS_V2_H

#include "pck.h"

/* Affiche le log */
void logger_print_2(struct logger_info_t * logger_info, struct pck_t *pck);

 /* Affiche une ligne */
void print_line(char * name, char * data, int color);

/* Initialise le printer */
void logger_init_2();

/* On finit le printer */
void logger_end_2();

#endif //LOGS_V2_H