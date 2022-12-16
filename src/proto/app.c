// Analyse de la couche application

#include "../includes/includes.h"

/* Analyse la couche application */
void compute_app(struct pck_t * pck)
{
    // On initialise la structure app_layer
    pck->log->al = init_al();

    // On détermine le type d'application
    determine_app_type(pck);

    // On appelle la fonction de la couche transport correspondante
    switch (pck->log->al->type)
    {
        case HTTP:
            // compute_http(pck);
            break;
        case FTP:
            // compute_ftp(pck);
            break;
        case SMTP:
            // compute_smtp(pck);
            break;
        case POP3:
            // compute_pop3(pck);
            break;
        case IMAP:
            // compute_imap(pck);
            break;
        case DNS:
            // compute_dns(pck);
            break;
        case TELNET:
            // compute_telnet(pck);
            break;
        case BOOTP:
            compute_bootp(pck);
            break;
        default:
            break;
    }

    // On met à jour le log de la couche application
    set_app_log(pck, pck->log->al);
}

/* Détermine le type d'application */
void determine_app_type(struct pck_t * pck)
{
    if (pck->log->tl->type == UDP)
    {
        // On récupère le port source et le port destination
        int src_port = ntohs(pck->log->tl->udp->uh_sport);
        int dst_port = ntohs(pck->log->tl->udp->uh_dport);
        // On détermine le type d'application
        if (src_port == 53 || dst_port == 53)
            pck->log->al->type = DNS;
        else if (src_port == 67 || dst_port == 67)
            pck->log->al->type = BOOTP;
    }

    else if (pck->log->tl->type == TCP)
    {
        // On récupère le port source et le port destination
        int src_port = ntohs(pck->log->tl->tcp->th_sport);
        int dst_port = ntohs(pck->log->tl->tcp->th_dport);

        // On détermine le type d'application
        if (src_port == 80 || dst_port == 80)
            pck->log->al->type = HTTP;
        else if (src_port == 21 || dst_port == 21)
            pck->log->al->type = FTP;
        else if (src_port == 25 || dst_port == 25)
            pck->log->al->type = SMTP;
        else if (src_port == 110 || dst_port == 110)
            pck->log->al->type = POP3;
        else if (src_port == 143 || dst_port == 143)
            pck->log->al->type = IMAP;
        else if (src_port == 23 || dst_port == 23)
            pck->log->al->type = TELNET;
    }
}

/* Met à jour le log de la couche application */
void set_app_log(struct pck_t * pck, struct app_layer_t * al)
{
    al->offset = pck->nb_incr;
}


/* Fonctions propre à la structure app_layer */

/* Initialise une structure app_layer */
struct app_layer_t *init_al()
{
    struct app_layer_t *al;
    CHECK(al = malloc(sizeof(struct app_layer_t)));
    al->type = 0;
    al->offset = 0;
    CHECK(al->log = calloc(1024, sizeof(char)));
    al->bootp = NULL;
    al->log_v3 = NULL;
    return al;
}

/* Libère la structure app_layer */
void free_al(struct app_layer_t * al)
{
    if (al == NULL) return;
    if (al->log != NULL) free(al->log);
    if (al->bootp != NULL) free_bootp(al->bootp);
    if (al->log_v3 != NULL) free_log_v3(al->log_v3);
    free(al);
}