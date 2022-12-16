// Contient la structure et les fonctions pour un objet log
#include "../includes/includes.h"

/* Initialise une structure log */
struct log_t *init_log()
{
    struct log_t *log;
    CHECK(log = malloc(sizeof(struct log_t)));
    log->nb_pck = 0;
    CHECK(log->src = calloc(128, sizeof(char)));
    CHECK(log->dst = calloc(128, sizeof(char)));
    log->proto = calloc(128, sizeof(char));
    log->log = calloc(2048, sizeof(char));
    log->ll = NULL;
    log->nl = NULL;
    log->tl = NULL;
    log->al = NULL;
    return log;
}

/* Libère la structure log */
void free_log(struct log_t *log)
{
    if(log == NULL) return;
    if(log->src != NULL)    free(log->src);
    if(log->dst != NULL)    free(log->dst);
    if(log->proto != NULL)  free(log->proto);
    if(log->log != NULL)    free(log->log);
    if(log->ll != NULL)     free_ll(log->ll);
    if(log->nl != NULL)     free_nl(log->nl);
    if(log->tl != NULL)     free_tl(log->tl);
    if(log->al != NULL)     free_al(log->al);
    free(log);
}

/* Ajoute un élément à log_v3 */
void add_log_v3(struct log_v3_t **log_v3, char *log)
{
    struct log_v3_t *tmp;
    CHECK(tmp = malloc(sizeof(struct log_v3_t)));
    CHECK(tmp->log = calloc(2048, sizeof(char)));

    strcpy(tmp->log, log);
    tmp->next = NULL;
    if(*log_v3 == NULL) {
        *log_v3 = tmp;
    } else {
        struct log_v3_t *tmp2 = *log_v3;
        while(tmp2->next != NULL) {
            tmp2 = tmp2->next;
        }
        tmp2->next = tmp;
    }
}

/* Libère la structure log_v3 */
void free_log_v3(struct log_v3_t *log_v3)
{
    if(log_v3 == NULL) return;
    if(log_v3->next != NULL) free_log_v3(log_v3->next);
    free(log_v3);   
}
