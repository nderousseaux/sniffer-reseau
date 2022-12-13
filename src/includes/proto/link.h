// Analyse de la couche liaison
#ifndef LINK_H
#define LINK_H

#include "pck.h"

enum link_type {
    ETHERNET
};

struct link_layer_t {
    enum link_type          type; // Type de lien (Ici, toujours ethernet)
    int                     offset; // Offset du la fin de la couche liaison
    char                    *log; // Log de la couche liaison
    struct ether_header     *eth; // Informations liées à l'ethernet (si type = ETHERNET)
    struct log_v3_t         *log_v3;
};

/* Analyse la couche liaison */
void compute_link(struct pck_t * pck);

/* Détermine le type de lien */
void determine_link_type(struct pck_t * pck);

/* Met à jour le log de la couche liaison */
void set_link_log(struct pck_t * pck, struct link_layer_t * ll);


/* Fonctions propre à la structure link_layer */

/* Initialise une structure link_layer */
struct link_layer_t *init_ll();

/* Libère la structure link_layer */
void free_ll(struct link_layer_t *ll);

#endif