 // Analyse de la couche netWork

#include "../includes/includes.h"

/* Analyse la couche réseau */
void compute_net(struct pck_t * pck)
{
    //On initialise la structure net_layer
    pck->log->nl = init_nl();

    //On détérmine quel type de paquet on a
    determine_net_type(pck);

    // On appelle la fonction de la couche réseau correspondante
    switch (pck->log->nl->type)
    {
        case IP:
            compute_ip(pck);
            break;
        case IPV6:
            compute_ip6(pck);
            break;
        case ARP:
            compute_arp(pck);
            break;
        default:
            break;
    }

    //On met à jour le log de la couche réseau
    set_net_log(pck, pck->log->nl);
}

/* Détermine le type de réseau */
void determine_net_type(struct pck_t * pck)
{
    if (pck->log->ll->type == ETHERNET)
    {
        //On teste le type de la structure ethernet header
        switch (ntohs(pck->log->ll->eth->ether_type))
        {
            case ETHERTYPE_IP:
                pck->log->nl->type = IP;
                break;
            case ETHERTYPE_IPV6:
                pck->log->nl->type = IPV6;
                break;
            case ETHERTYPE_ARP:
                pck->log->nl->type = ARP;
                break;
            default:
                break;
        }
    }

}

/* Met à jour le log de la couche réseau */
void set_net_log(struct pck_t * pck, struct net_layer_t * nl)
{
    //On défini l'offset de la couche réseau
    nl->offset = pck->nb_incr;
}


/* Fonctions propre à la structure net_layer */

/* Initialise une structure net_layer */
struct net_layer_t *init_nl()
{
    struct net_layer_t *nl;
    CHECK(nl = malloc(sizeof(struct net_layer_t)));
    nl->type = 0;
    nl->offset = 0;
    CHECK(nl->log = calloc(1024, sizeof(char)));
    nl->ip = NULL;
    nl->ip6 = NULL;
    nl->arp = NULL;
    nl->log_v3 = NULL;
    return nl;
}

/* Libère la structure net_layer */
void free_nl(struct net_layer_t *nl)
{
    if (nl == NULL) return;
    if (nl->log != NULL) free(nl->log);
    if (nl->log_v3 != NULL) free_log_v3(nl->log_v3);
    free(nl);
}