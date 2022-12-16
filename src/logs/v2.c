// Fonctions d'afficage des logs, pour le verbose = 2
#include "../includes/includes.h"

/* Affiche le log */
void logger_print_2(struct logger_info_t * logger_info, struct pck_t *pck)
{
    char * title = logger_title(pck, logger_info);

    //On affiche l'entête du paquet
    printf("╔══ %s ", title);
    for(unsigned int i = 0; i < SIZE_TERM - strlen(title) + 1; i++) printf("═");
    printf("═╗\n");

    
    //On affiche une ligne vide
    printf("║");
    for(unsigned int i = 0; i < SIZE_TERM - 2; i++) printf(" ");
    printf("║\n");

    //On affche la couche liaison
    if(pck->log->ll != NULL && pck->log->ll->log != NULL && strlen(pck->log->ll->log) > 0)
        print_line("Link layer", pck->log->ll->log, 1);

    //On affche la couche réseau
    if(pck->log->nl != NULL && pck->log->nl->log != NULL && strlen(pck->log->nl->log) > 0)
        print_line("Net layer", pck->log->nl->log, 2);
    
    //On affche la couche transport
    if(pck->log->tl != NULL && pck->log->tl->log != NULL && strlen(pck->log->tl->log) > 0)
        print_line("Transport layer", pck->log->tl->log, 3);

    //On affiche une ligne vide
    printf("║");
    for(unsigned int i = 0; i < SIZE_TERM - 2; i++) printf(" ");
    printf("║\n");

    //On affiche le footer
    printf("╚");
    for(unsigned int i = 0; i < SIZE_TERM - 2; i++) printf("═");
    printf("╝\n");

    printf("\n");
    free(title);
}

/* Affiche une ligne */
void print_line(char * name, char * data, int color)
{
    char * line = logger_proto_title(name, data, color);
    
    //On affiche la ligne
    printf("║ %s ║\n", str_exact_len(line, SIZE_TERM-4));

    free(line);
}

/* Initialise le printer */
void logger_init_2()
{
}

/* On finit le printer */
void logger_end_2()
{
}