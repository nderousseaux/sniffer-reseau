// Fonctions d'afficage des logs, pour le verbose = 1

#ifndef LOGS_V1_H
#define LOGS_V1_H

#include "pck.h"

#define SIZE_COL_NUM 5 // Taille de la colonne du numéro de paquet
#define SIZE_COL_TIME 14 // Taille de la colonne du temps
#define SIZE_COL_ADDR 20 // Taille de la colonne de la source et de la destination
#define SIZE_COL_PROTO 8 // Taille de la colonne du protocole
#define SIZE_COL_LEN 6 // Taille de la colonne de la longueur
#define SIZE_COL_INFO 101 // Taille de la colonne d'informations

/* Affiche le log */
void logger_print_1(struct logger_info_t * logger_info, struct pck_t *pck);

/* Initialise le printer */
void logger_init_1();

/* On finit le printer */
void logger_end_1();

#endif //LOGS_V1_H