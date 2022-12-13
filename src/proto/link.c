// Analyse de la couche liaison

#include "../includes/includes.h"

/* Analyse la couche liaison */
void compute_link(struct pck_t * pck)
{
    //On initialise la structure link_layer
    pck->log->ll = init_ll();

    //On détérmine quel type de paquet on a
    determine_link_type(pck);


    // On appelle la fonction de la couche liaison correspondante
    switch (pck->log->ll->type)
    {
        case ETHERNET:
            compute_ether(pck);
            break;
    
        default:
            break;
    }

    //On met à jour le log de la couche liaison
    set_link_log(pck, pck->log->ll);
}

/* Détermine le type de lien */
void determine_link_type(struct pck_t * pck)
{
    //On récupère le premier octet du paquet
    uint8_t first_byte = pck->data[0];

    //On regarde si c'est un paquet ethernet
    if (first_byte == 0xFF) pck->log->ll->type = ETHERNET;
}

/* Met à jour le log de la couche liaison */
void set_link_log(struct pck_t * pck, struct link_layer_t * ll)
{
    //On défini l'offset de la couche liaison
    ll->offset = pck->nb_incr;
}


/* Fonctions propre à la structure link_layer */

/* Initialise une structure link_layer */
struct link_layer_t *init_ll()
{
    struct link_layer_t *ll;
    CHECK(ll = malloc(sizeof(struct link_layer_t)));
    ll->type = 0;
    ll->offset = 0;
    CHECK(ll->log = calloc(1024, sizeof(char)));
    ll->eth = NULL;
    ll->log_v3 = NULL;
    return ll;
}

/* Libère la structure link_layer */
void free_ll(struct link_layer_t *ll)
{
    if(ll == NULL) return;
    if(ll->log != NULL) free(ll->log);
    if(ll->log_v3 != NULL) free_log_v3(ll->log_v3);
    free(ll);
}
