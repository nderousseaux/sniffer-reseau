// Fonctions d'afficage des logs, pour le verbose = 3

#ifndef LOGS_V3_H
#define LOGS_V3_H

#include "pck.h"

#define SIZE_SECONDARY_CASE 90


/* Affiche le log */
void logger_print_3(struct logger_info_t * logger_info, struct pck_t *pck);

/* Crée une strucure log_v3 totale (somme de log_v3 str et log_v3_data)*/
struct log_v3_t * get_log_v3_line(struct pck_t *pck);

/* Crée une structure log_v3, contenant chaque ligne des données */
struct log_v3_t * get_log_v3_str(struct pck_t *pck);

/* Remplit la strucuture log_v3, pour une couche entière */
void add_layer_log_v3(struct log_v3_t ** log_v3, char * name, struct log_v3_t * data, char * log, int color);

/* Crée une strucutre log_v3, contenant chaque ligne la version hexa du paquet */
struct log_v3_t * get_log_v3_data(struct pck_t *pck);

/* Enregistre l'entête d'une couche dans log_v3 */
void add_header_log_v3(struct log_v3_t ** log_v3, char * title, char * data, int color);

/* Enregistre une ligne d'une couche dans log_v3 */
void add_line_log_v3(struct log_v3_t ** dst, char * src);

/* Renvoie une version printable du paquet */
char * printable_pck(struct pck_t * pck);

// Met dans color la nouvelle couleur à utiliser, et dans offset_next l'offset de la prochaine couche
void choose_color(int x, struct pck_t *pck, int * color, int * offset_next);

/* Initialise le printer */
void logger_init_3();

/* On finit le printer */
void logger_end_3();

#endif //LOGS_V3_H