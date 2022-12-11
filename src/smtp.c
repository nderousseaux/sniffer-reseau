// Gère un paquet smtp
#include "includes/includes.h"

/* Traite un paquet smtp */
void compute_smtp(const u_char **pck, char is_request)
{
    struct smtp_t * smtp = init_smtp(is_request);

    //On remplit la structure smtp
    do {
        char * data = add_smtp_data(smtp);
        sscanf((char *) *pck, "%[^\r]%*c", data);
        incr_pck(pck, strlen(data)+1);
    } while (get_remaining_bytes() > 0);

    //On définit les logs de la couche application
    set_smtp_logs(smtp);
}

/* Définit les variables du printer pour smtp */
void set_smtp_logs(struct smtp_t *smtp)
{
    //On définit les variables
    char * infos;
    struct smtp_logs *smtp_logs = init_smtp_logs();
    struct paquet_info *paquet_info = get_paquet_info();

    //On remplit les infos
    CHECK(infos = calloc(255, sizeof(char)));
    if (smtp->is_request)
        sprintf(infos, "Request :");
    else
        sprintf(infos, "Response :");
    
    struct smtp_data_t * data = smtp->data;
    while (data != NULL)
    {
        sprintf(infos, "%s %s", infos, data->data);
        data = data->next;
    }

    //On définit les logs
    smtp_logs->smtp = smtp;
    sprintf(smtp_logs->logs, "Simple Mail Transfer Protocol %s", infos);

    //On définit les logs du paquet
    paquet_info->eth->ipv4->tcp->smtp = smtp_logs;
    strcpy(paquet_info->protocol, "SMTP");
    strcpy(paquet_info->infos, infos);

    // On libère la mémoire
    free(infos);
}


/*** Fonctions utiles aux structures ***/

/* Initialise une structure smtp_t */
struct smtp_t * init_smtp(char is_request)
{
    struct smtp_t * smtp;
    CHECK(smtp = malloc(sizeof(struct smtp_t)));
    smtp->is_request = is_request;
    smtp->data = NULL;
    return smtp;
}

/* Ajoute une ligne à la liste des données */
char * add_smtp_data(struct smtp_t * smtp)
{
    struct smtp_data_t * data;
    CHECK(data = malloc(sizeof(struct smtp_data_t)));
    CHECK(data->data = calloc(1024, sizeof(char)));
    data->next = NULL;
    if (smtp->data == NULL)
        smtp->data = data;
    else
    {
        struct smtp_data_t * tmp = smtp->data;
        while (tmp->next != NULL)
            tmp = tmp->next;
        tmp->next = data;
    }
    return data->data;
}

/* Initialise une structure smtp_logs */
struct smtp_logs * init_smtp_logs()
{
    struct smtp_logs * smtp_logs;
    CHECK(smtp_logs = malloc(sizeof(struct smtp_logs)));
    CHECK(smtp_logs->logs = calloc(1024, sizeof(char)));
    smtp_logs->smtp = NULL;
    return smtp_logs;
}

/* Libère une structure smtp_t */
void free_smtp(struct smtp_t * smtp)
{
    if (smtp != NULL)
    {
        if (smtp->data != NULL)
        {
            struct smtp_data_t * tmp = smtp->data;
            while (tmp != NULL)
            {
                struct smtp_data_t * tmp2 = tmp->next;
                free(tmp->data);
                free(tmp);
                tmp = tmp2;
            }
        }
        free(smtp);
    }
}

/* Libère une structure smtp_logs */
void free_smtp_logs(struct smtp_logs *smtp_logs)
{
    if (smtp_logs != NULL)
    {
        free(smtp_logs->logs);
        free_smtp(smtp_logs->smtp);
        free(smtp_logs);
    }
}
