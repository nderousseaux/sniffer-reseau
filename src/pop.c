// Gère un paquet pop

#include "includes/includes.h"

/* Traite un paquet pop */
void compute_pop(const u_char **pck, char is_request)
{
    struct pop_t *pop = init_pop();
    pop->is_request = is_request;

    if (pop->is_request)
    {
        CHECK(pop->command = calloc(255, sizeof(char)));
        sscanf((char *) *pck, "%s", pop->command);
        //On avance le pointeur d'autant
        incr_pck(pck, strlen(pop->command) + 1);
        if(**pck == 0x20){ //Alors il y a un paramètre
            incr_pck(pck, 1);
            CHECK(pop->description = calloc(255, sizeof(char)));
            sscanf((char *) *pck, "%s", pop->description);
        }
    }
    else //Si c'est une réponse
    {
        //Si ça commence par un + ou un -, c'est un code de réponse
        if(**pck == '+' || **pck == '-'){
            CHECK(pop->command = calloc(255, sizeof(char)));
            CHECK(pop->description = calloc(255, sizeof(char)));
            sscanf((char *) *pck, "%s %[^\n]%*c", pop->command, pop->description);
            //On avance le pointeur d'autant
            incr_pck(pck, strlen(pop->command) + strlen(pop->description) + 2);
        }
        //On récupère le data
        if(get_remaining_bytes(pck) > 0){
            CHECK(pop->data = calloc(2048, sizeof(char)));
            //On récupère le data
            do{
                sprintf(pop->data, "%s%c", pop->data, **pck);
                incr_pck(pck, 1);
            } while(get_remaining_bytes(pck) > 0);
        }
    }

    //On définit les logs de la couche application
    set_pop_logs(pop);
}

/* Définit les variables du printer pour pop */
void set_pop_logs(struct pop_t *pop)
{
    //On définit les variables
    char * infos;
    struct pop_logs *pop_logs = init_pop_logs();
    struct paquet_info *paquet_info = get_paquet_info();


    //On remplit les infos
    CHECK(infos = calloc(255, sizeof(char)));
    if(pop->is_request)
        sprintf(infos, "C:");
    else
        sprintf(infos, "S:");
    //Si il y a des arguements
    if (pop->command != NULL){
        sprintf(infos, "%s %s", infos, pop->command);
        if(pop->description != NULL)
            sprintf(infos, "%s %s", infos, pop->description);
    }
    //Si il n'y que des données
    else if(pop->data != NULL)
        sprintf(infos, "%s DATA fragment, %ld bytes", infos, strlen(pop->data));

    //On remplit les logs
    pop_logs->pop = pop;
    sprintf(pop_logs->logs, "Post Office Protocol : %s", infos);

    paquet_info->eth->ipv4->tcp->pop = pop_logs;
    strcpy(paquet_info->protocol, "POP");
    strcpy(paquet_info->infos, infos);
    
    //On libère la mémoire
    free(infos);
}


/* Initialise une structure pop_t */
struct pop_t * init_pop()
{
    struct pop_t *pop;
    CHECK(pop = malloc(sizeof(struct pop_t)));
    pop->command = NULL;
    pop->description = NULL;
    pop->data = NULL;
    return pop;
}

/* Initialise une structure pop_logs */
struct pop_logs * init_pop_logs()
{
    struct pop_logs *pop_logs;
    CHECK(pop_logs = malloc(sizeof(struct pop_logs)));
    CHECK(pop_logs->logs = calloc(255, sizeof(char)));
    pop_logs->pop = NULL;
    return pop_logs;
}

/* On libère la mémoire */
void free_pop_logs(struct pop_logs *pop_logs)
{
    if (pop_logs->pop->command != NULL)
        free(pop_logs->pop->command);
    if (pop_logs->pop->description != NULL)
        free(pop_logs->pop->description);
    if (pop_logs->pop->data != NULL)
        free(pop_logs->pop->data);
    free(pop_logs->pop);
    free(pop_logs->logs);
    free(pop_logs);
}