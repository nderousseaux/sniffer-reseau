// Contient les fonctions du logger
#ifndef H_GL_LOGGER
#define H_GL_LOGGER

#include "pck.h"

#define SIZE_TERM 175 // Taille de la ligne de terminal

#define COLOR_LL 1
#define COLOR_NL 2
#define COLOR_TL 3
#define COLOR_DATA 9

// Structure contenant les informations globales du logger
struct logger_info_t
{
    int             verbose_lvl;  // Niveau de verbosité
    int             nb_pck;       // Nombre de paquets traités
    struct timeval  *start_time;  // Heure du premier paquet traité
} logger_info;


/* Initialise le printer */
void logger_init(int verbose);

/* Renvoie un titre (v2 et v3) */
char * logger_title(struct pck_t *pck, struct logger_info_t * logger_info);

/* renvoie le titre de protocole (v2 et v3) */
char * logger_proto_title(char * name, char * data, int color);

/* Affiche le log */
void logger_print(struct pck_t *pck);

/* On finit le printer */
void logger_end();
  

#endif //H_GL_LOGGER