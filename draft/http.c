// Gère un paquet http
#include "includes/includes.h"

//TODO: Tenir une liste de connection ouverte, et définir le paquet "imprimable" en fonction de la connection.
char printable_http_data = 1; // Indique si on doit afficher les données du paquet

/* Traite un paquet http */
void compute_http(const u_char **pck, char is_request)
{
    printf("%d\n", (int) printable_http_data);
    struct http_t * http = init_http(is_request);

    if(printable_http_data != 0){ 
        //On remplit la structure http
        do {
            char * data = add_http_data(http);
            sscanf((char *) *pck, "%[^\r]%*c", data);
            incr_pck(pck, strlen(data)+1);
            printf("%s\n", data);
            //Si le paquet est non-imprimable (commence par un Content-Type: image/...)
            if(
                strncmp(data, "\nContent-Type: image/", 20) == 0 ||
                strncmp(data, "\nContent-Type: audio/", 20) == 0 ||
                strncmp(data, "\nContent-Type: video/", 20) == 0 ||
                strncmp(data, "\nContent-Type: application/", 26) == 0
            ){
                //On désactive l'affichage du paquet
                printable_http_data = 0;
            }
            
        } while (get_remaining_bytes() > 0 && printable_http_data);
    }


    printf("%d\n", (int) printable_http_data);

    //On définit les logs de la couche application
    set_http_logs(http);
}

/* Définit les variables du printer pour http */
void set_http_logs(struct http_t *http)
{
    //On définit les variables
    char * infos;
    struct http_logs *http_logs = init_http_logs();
    struct paquet_info *paquet_info = get_paquet_info();

    //On remplit les infos
    CHECK(infos = calloc(255, sizeof(char)));
    if (http->is_request)
        sprintf(infos, "Request :");
    else
        sprintf(infos, "Response :");
    
    struct http_data_t * data = http->data;
    while (data != NULL)
    {
        sprintf(infos, "%s %s", infos, data->data);
        data = data->next;
    }

    //On définit les logs
    http_logs->http = http;
    sprintf(http_logs->logs, "Hyper Text Transfer Protocol %s", infos);

    //On définit les logs du paquet
    paquet_info->eth->ipv4->tcp->http = http_logs;
    strcpy(paquet_info->protocol, "HTTP");
    strcpy(paquet_info->infos, infos);

    // On libère la mémoire
    free(infos);
}


/*** Fonctions utiles aux structures ***/

/* Initialise une structure http_t */
struct http_t * init_http(char is_request)
{
    struct http_t * http;
    CHECK(http = malloc(sizeof(struct http_t)));
    http->is_request = is_request;
    http->data = NULL;
    return http;
}

/* Ajoute une ligne à la liste des données */
char * add_http_data(struct http_t * http)
{
    struct http_data_t * data;
    CHECK(data = malloc(sizeof(struct http_data_t)));
    CHECK(data->data = calloc(1024, sizeof(char)));
    data->next = NULL;
    if (http->data == NULL)
        http->data = data;
    else
    {
        struct http_data_t * tmp = http->data;
        while (tmp->next != NULL)
            tmp = tmp->next;
        tmp->next = data;
    }
    return data->data;
}

/* Initialise une structure http_logs */
struct http_logs * init_http_logs()
{
    struct http_logs * http_logs;
    CHECK(http_logs = malloc(sizeof(struct http_logs)));
    CHECK(http_logs->logs = calloc(1024, sizeof(char)));
    http_logs->http = NULL;
    return http_logs;
}

/* Libère une structure http_t */
void free_http(struct http_t * http)
{
    if (http != NULL)
    {
        if (http->data != NULL)
        {
            struct http_data_t * tmp = http->data;
            while (tmp != NULL)
            {
                struct http_data_t * tmp2 = tmp->next;
                free(tmp->data);
                free(tmp);
                tmp = tmp2;
            }
        }
        free(http);
    }
}

/* Libère une structure http_logs */
void free_http_logs(struct http_logs *http_logs)
{
    if (http_logs != NULL)
    {
        free(http_logs->logs);
        free_http(http_logs->http);
        free(http_logs);
    }
}
