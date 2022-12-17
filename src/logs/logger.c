// Contient les fonctions du logger
#include "../includes/includes.h"

struct logger_info_t logger_info;

/* Initialise le printer */
void logger_init(int verbose)
{
    logger_info.verbose_lvl = verbose;
    logger_info.nb_pck = 0;
    logger_info.start_time = NULL;

    switch (logger_info.verbose_lvl)
    {
    case 1:
        logger_init_1();
        break;
    case 2:
        logger_init_2();
        break;
    case 3:
        logger_init_3();
        break;
    default:
        break;
    }
}

/* Renvoie un titre (v2 et v3) */
char * logger_title(struct pck_t *pck, struct logger_info_t * logger_info)
{
    char * title;
    char * time = interval(logger_info->start_time, &pck->meta->ts);
    CHECK(title = calloc(SIZE_TERM, sizeof(char)));
    sprintf(
        title,
        "\033[1mFrame %d (at %s): %d bytes (%d bits), Src: %s, Dst: %s. Protocol: %s\033[0m",
        logger_info->nb_pck,
        time,
        pck->meta->len,
        pck->meta->len * 8,
        pck->log->src,
        pck->log->dst,
        pck->log->proto
    );
    free(time);
    return title;
}

/* renvoie le titre de protocole (v2 et v3) */
char * logger_proto_title(char * name, char * data, int color)
{
    char * line;
    CHECK(line = calloc(1024, sizeof(char)));

    //On affiche le nom de la couche en couleur et les données
    sprintf(
        line,
        "\033[3%dm%s\033[0m: %s",
        color,
        name,
        data
    );
    
    return line;
}

/* Affiche le log */
void logger_print(struct pck_t *pck)
{
    logger_info.nb_pck++;

    //Si c'est le premier paquet, on initialise le temps de départ
    if (logger_info.nb_pck == 1)
    {
        logger_info.start_time = malloc(sizeof(struct timeval));
        logger_info.start_time->tv_sec = pck->meta->ts.tv_sec;
        logger_info.start_time->tv_usec = pck->meta->ts.tv_usec;
    }

    switch (logger_info.verbose_lvl)
    {
    case 1:
        logger_print_1(&logger_info, pck);
        break;
    case 2:
        logger_print_2(&logger_info, pck);
        break;
    case 3:
        logger_print_3(&logger_info, pck);
        break;
    default:
        break;
    }
}

/* On finit le printer */
void logger_end()
{
    switch (logger_info.verbose_lvl)
    {
    case 1:
        logger_end_1(&logger_info);
        break;
    case 2:
        logger_end_2(&logger_info);
        break;
    case 3:
        logger_end_3(&logger_info);
        break;
    default:
        break;
    }

    printf("Nombre de paquets traités : %d\n", logger_info.nb_pck);

    //On libère la mémoire
    free(logger_info.start_time);
}