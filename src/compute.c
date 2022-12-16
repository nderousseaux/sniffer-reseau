// Analyse le paquet couche par couche
#include "includes/includes.h"

/* Analyze le paquet */
void compute_pck(struct pck_t * pck)
{
    //On analyse la couche liaison
    compute_link(pck);

    //On analyse la couche réseau
    compute_net(pck);

    //On analyse la couche transport
    compute_trans(pck);

    //On analyse la couche application
    compute_app(pck);
}