// Analyse de la couche transport

#include "../includes/includes.h"

/* Analyse la couche transport */
void compute_trans(struct pck_t * pck)
{
    //On initialise la strucutre trans_layer
    pck->log->tl = init_tl();

    //On détermine quel type de paquet on a
    determine_trans_type(pck);

    // On appelle la fonction de la couche transport correspondante
    switch (pck->log->tl->type)
    {
        case TCP:
            compute_tcp(pck);
            break;
        case UDP:
            compute_udp(pck);
            break;
        case ICMP:
            compute_icmp(pck);
            break;
        default:
            break;
    }

    //On met à jour le log de la couche transport
    set_trans_log(pck, pck->log->tl);
}

/* Détermine le type de transport */
void determine_trans_type(struct pck_t * pck)
{
    if (pck->log->nl->type == IP)
    {
        //On teste le type de la structure ip header
        switch (pck->log->nl->ip->ip_p)
        {
            case IPPROTO_TCP:
                pck->log->tl->type = TCP;
                break;
            case IPPROTO_UDP:
                pck->log->tl->type = UDP;
                break;
            case IPPROTO_ICMP:
                pck->log->tl->type = ICMP;
                break;
            default:
                break;
        }
    }
    else if (pck->log->nl->type == IPV6)
    {
        //On teste le type de la structure ip6 header
        switch (pck->log->nl->ip6->ip6_nxt)
        {
            case IPPROTO_TCP:
                pck->log->tl->type = TCP;
                break;
            case IPPROTO_UDP:
                pck->log->tl->type = UDP;
                break;
            case IPPROTO_ICMPV6:
                pck->log->tl->type = ICMP;
                break;
            default:
                break;
        }
    }
}

/* Met à jour le log de la couche transport */
void set_trans_log(struct pck_t * pck, struct trans_layer_t * tl)
{
    //On définit l'offset de la couche transport
    tl->offset = pck->nb_incr;
}


/* Fonctions propre à la structure trans_layer */

/* Initialise une structure trans_layer */
struct trans_layer_t *init_tl()
{
    struct trans_layer_t *tl;
    CHECK(tl = malloc(sizeof(struct trans_layer_t)));
    tl->type = 0;
    tl->offset = 0;
    CHECK(tl->log = calloc(1024, sizeof(char)));
    tl->tcp = NULL;
    tl->udp = NULL;
    tl->icmp = NULL;
    tl->log_v3 = NULL;
    return tl;
}

/* Libère la structure trans_layer */
void free_tl(struct trans_layer_t *tl)
{
    if (tl == NULL) return;
    if (tl->log != NULL) free(tl->log);
    if (tl->log_v3 != NULL) free_log_v3(tl->log_v3);
    free(tl);
}