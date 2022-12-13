// Fonctions d'afficage des logs, pour le verbose = 1
#include "../includes/includes.h"

/* Affiche le log */
void logger_print_1(struct logger_info_t * logger_info, struct pck_t *pck)
{
    char * num = str_exact_len(
        int_to_str(logger_info->nb_pck),
        SIZE_COL_NUM-2
    );
    char * time = str_exact_len(
        interval(logger_info->start_time, &pck->meta->ts),
        SIZE_COL_TIME-2
    );
    char * src = str_exact_len(pck->log->src, SIZE_COL_ADDR-2);
    char * dst = str_exact_len(pck->log->dst, SIZE_COL_ADDR-2);
    char * proto = str_exact_len(pck->log->proto, SIZE_COL_PROTO-2);
    char * len = str_exact_len(
        int_to_str(pck->meta->len),
        SIZE_COL_LEN-2
    );
    char * log = str_exact_len(pck->log->log, SIZE_COL_INFO-2);

    printf(
        "║ %s │ %s │ %s │ %s │ %s │ %s │ %s ║\n",
        num, time, src, dst, proto, len, log
    );

    free(num);
    free(time);
    free(src);
    free(dst);
    free(proto);
    free(len);
    free(log);
    (void)logger_info;
}

/* Initialise le printer */
void logger_init_1(){
    //On affiche la première ligne
    printf("╔");
    for (int i = 0; i < SIZE_COL_NUM; i++) printf("═");
    printf("╤");
    for (int i = 0; i < SIZE_COL_TIME; i++) printf("═");
    printf("╤");
    for (int i = 0; i < SIZE_COL_ADDR; i++) printf("═");
    printf("╤");
    for (int i = 0; i < SIZE_COL_ADDR; i++) printf("═");
    printf("╤");
    for (int i = 0; i < SIZE_COL_PROTO; i++) printf("═");
    printf("╤");
    for (int i = 0; i < SIZE_COL_LEN; i++) printf("═");
    printf("╤");
    for (int i = 0; i < SIZE_COL_INFO; i++) printf("═");
    printf("╗\n");

    //On affiche la deuxième ligne
    char * no = str_exact_len("No.", SIZE_COL_NUM-2);
    char * time = str_exact_len("Time", SIZE_COL_TIME-2);
    char * src = str_exact_len("Source", SIZE_COL_ADDR-2);
    char * dst = str_exact_len("Destination", SIZE_COL_ADDR-2);
    char * proto = str_exact_len("Proto", SIZE_COL_PROTO-2);
    char * len = str_exact_len("Len", SIZE_COL_LEN-2);
    char * info = str_exact_len("Informations", SIZE_COL_INFO-2);

    printf(
        "║ %s │ %s │ %s │ %s │ %s │ %s │ %s ║\n",
        no, time, src, dst, proto, len, info
    );

    //On affiche la troisième ligne
    printf("╠");
    for (int i = 0; i < SIZE_COL_NUM; i++) printf("═");
    printf("╪");
    for (int i = 0; i < SIZE_COL_TIME; i++) printf("═");
    printf("╪");
    for (int i = 0; i < SIZE_COL_ADDR; i++) printf("═");
    printf("╪");
    for (int i = 0; i < SIZE_COL_ADDR; i++) printf("═");
    printf("╪");
    for (int i = 0; i < SIZE_COL_PROTO; i++) printf("═");
    printf("╪");
    for (int i = 0; i < SIZE_COL_LEN; i++) printf("═");
    printf("╪");
    for (int i = 0; i < SIZE_COL_INFO; i++) printf("═");
    printf("╣\n");

    free(no);
    free(time);
    free(src);
    free(dst);
    free(proto);
    free(len);
    free(info);
}

/* On finit le printer */
void logger_end_1()
{
    //On affiche la dernière ligne
    printf("╚");
    for (int i = 0; i < SIZE_COL_NUM; i++) printf("═");
    printf("╧");
    for (int i = 0; i < SIZE_COL_TIME; i++) printf("═");
    printf("╧");
    for (int i = 0; i < SIZE_COL_ADDR; i++) printf("═");
    printf("╧");
    for (int i = 0; i < SIZE_COL_ADDR; i++) printf("═");
    printf("╧");
    for (int i = 0; i < SIZE_COL_PROTO; i++) printf("═");
    printf("╧");
    for (int i = 0; i < SIZE_COL_LEN; i++) printf("═");
    printf("╧");
    for (int i = 0; i < SIZE_COL_INFO; i++) printf("═");
    printf("╝\n");
}
