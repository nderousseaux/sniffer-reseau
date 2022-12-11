// Gère un paquet imap

#include "includes/includes.h"

/* Traite un paquet imap */
void compute_imap(const u_char **pck, char is_request)
{    
    struct imap_t * imap = init_imap(is_request);

    //On remplit la structure imap
    if(imap->is_request)
    {
        do{
            struct imap_request_t * imap_request = add_imap_request(imap);
            // On récupère la commande
            sscanf((char *) *pck, "%s", imap_request->tag);
            incr_pck(pck, strlen(imap_request->tag));
            if(**pck == 0x20){ //Alors il y a une commande
                incr_pck(pck, 1);
                imap_request->command = malloc(255* sizeof(char));
                memset(imap_request->command, 0, 255);
                // CHECK(imap_request->command = calloc(255, sizeof(char)));
                sscanf((char *) *pck, "%s", imap_request->command);
                incr_pck(pck, strlen(imap_request->command));
                if(**pck == 0x20){ //Alors il y a des données
                    incr_pck(pck, 1);
                    CHECK(imap_request->data = calloc(255, sizeof(char)));
                    sscanf((char *) *pck, "%[^\r]%*c", imap_request->data);
                    incr_pck(pck, strlen(imap_request->data));
                }
            }
        } while(get_remaining_bytes() > 0 && **pck != 0x0d);
    }
    else //Ou alors c'est une réponse
    {
        do{
            struct imap_response_t * imap_response = add_imap_response(imap);
            //On récupère chaque ligne
            sscanf((char *) *pck, "%[^\r]%*c", imap_response->data);
            incr_pck(pck, strlen(imap_response->data)+1);
        } while(get_remaining_bytes() > 1);
    }
    
    //On définit les logs de la couche application
    set_imap_logs(imap);
}

/* Définit les variables du printer pour imap */
void set_imap_logs(struct imap_t *imap)
{
    //On définit les variables
    char * infos;
    struct imap_logs *imap_logs = init_imap_logs();
    struct paquet_info *paquet_info = get_paquet_info();

    //On remplit les infos
    // CHECK(infos = calloc(255, sizeof(char)));
    infos = malloc(255* sizeof(char));
    memset(infos, 0, 255);

    if(imap->is_request){
        sprintf(infos, "Request :");
        struct imap_request_t * imap_request = imap->list_request;
        while (imap_request != NULL)
        {
            sprintf(infos, "%s %s", infos, imap_request->tag);
            if(imap_request->command != NULL)
                sprintf(infos, "%s %s", infos, imap_request->command);
            if(imap_request->data != NULL)
                sprintf(infos, "%s %s", infos, imap_request->data);
            imap_request = imap_request->next;
        }
    }
    else{

        sprintf(infos, "Response :");
        struct imap_response_t * imap_response = imap->list_response;
        while (imap_response != NULL)
        {
            if(strlen(infos) + strlen(imap_response->data) > 225)
                break;
            strcat(infos, imap_response->data);
            imap_response = imap_response->next;
        }
    }

    //On remplit les logs
    imap_logs->imap = imap;
    sprintf(imap_logs->logs, "Internet Message Access Protocol %s", infos);

    //On définit les logs du paquet
    paquet_info->eth->ipv4->tcp->imap = imap_logs;
    strcpy(paquet_info->protocol, "IMAP");
    strcpy(paquet_info->infos, infos);

    //On libère la mémoire
    free(infos);
}


/*** Fonctions utiles aux structures ***/

/* Initialise une structure imap_t */
struct imap_t * init_imap(char is_request)
{
    struct imap_t * imap;
    CHECK(imap = malloc(sizeof(struct imap_t)));

    imap->is_request = is_request;
    imap->list_request = NULL;
    imap->list_response = NULL;

    return imap;
}

/* Ajoute une requête à la liste des requêtes */
struct imap_request_t * add_imap_request(struct imap_t * imap)
{
    // On ajoute la requête à la liste des requêtes
    struct imap_request_t *imap_request;
    CHECK(imap_request = malloc(sizeof(struct imap_request_t)));
    CHECK(imap_request->tag = calloc(255, sizeof(char)));
    imap_request->command = NULL;
    imap_request->data = NULL;
    imap_request->next = NULL;

    if(imap->list_request == NULL){
        imap->list_request = imap_request;
    }
    else
    {
        struct imap_request_t *imap_request_tmp = imap->list_request;
        while(imap_request_tmp->next != NULL)
            imap_request_tmp = imap_request_tmp->next;
        imap_request_tmp->next = imap_request;
    }
    return imap_request;
}

/* Ajoute une réponse à la liste des réponses */
struct imap_response_t * add_imap_response(struct imap_t * imap)
{
    // On ajoute la réponse à la liste des réponses
    struct imap_response_t *imap_response;
    CHECK(imap_response = malloc(sizeof(struct imap_response_t)));
    CHECK(imap_response->data = calloc(255, sizeof(char)));
    imap_response->next = NULL;

    if(imap->list_response == NULL)
        imap->list_response = imap_response;
    else
    {
        struct imap_response_t *imap_response_tmp = imap->list_response;
        while(imap_response_tmp->next != NULL)
            imap_response_tmp = imap_response_tmp->next;
        imap_response_tmp->next = imap_response;
    }

    return imap_response;
}

/* Initialise une structure imap_logs */
struct imap_logs * init_imap_logs()
{
    struct imap_logs * imap_logs;
    CHECK(imap_logs = malloc(sizeof(struct imap_logs)));
    CHECK(imap_logs->logs = malloc(255* sizeof(char)));
    memset(imap_logs->logs, 0, 255);

    imap_logs->imap = NULL;
    return imap_logs;
}

/* Libère une structure imap_t */
void free_imap(struct imap_t * imap)
{
    if(imap->list_request != NULL){
        // On libère récursivement la liste des requêtes
        struct imap_request_t *imap_request_tmp = imap->list_request;
        struct imap_request_t *imap_request_tmp2;
        while(imap_request_tmp != NULL)
        {
            imap_request_tmp2 = imap_request_tmp->next;
            free(imap_request_tmp->tag);
            free(imap_request_tmp->command);
            free(imap_request_tmp->data);
            free(imap_request_tmp);
            imap_request_tmp = imap_request_tmp2;
        }
    }
    if(imap->list_response != NULL){
        // On libère récursivement la liste des réponses
        struct imap_response_t *imap_response_tmp = imap->list_response;
        struct imap_response_t *imap_response_tmp2;
        while(imap_response_tmp != NULL)
        {
            imap_response_tmp2 = imap_response_tmp->next;
            free(imap_response_tmp->data);
            free(imap_response_tmp);
            imap_response_tmp = imap_response_tmp2;
        }
    }
    free(imap);
}

/* Libère une structure imap_logs */
void free_imap_logs(struct imap_logs * imap_logs)
{
    free(imap_logs->logs);
    free_imap(imap_logs->imap);
    free(imap_logs);
}