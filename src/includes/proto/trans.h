// Analyse de la couche transport
#ifndef TRANSPORT_H
#define TRANSPORT_H

#include "pck.h"

enum trans_type {
    TCP,
    UDP,
    ICMP
};

struct trans_layer_t {
    enum trans_type         type;   // Type de couche transport
    int                     offset; // Offset du la fin de la couche transport
    char                    *log;   // Log de la couche transport
    struct tcphdr           *tcp;   // Pointeur vers la structure tcp
    struct udphdr           *udp;   // Pointeur vers la structure udp
    struct icmp             *icmp;  // Pointeur vers la structure icmp
    struct log_v3_t         *log_v3;
};

/* Analyse la couche transport */
void compute_trans(struct pck_t * pck);

/* Détermine le type de transport */
void determine_trans_type(struct pck_t * pck);

/* Met à jour le log de la couche transport */
void set_trans_log(struct pck_t * pck, struct trans_layer_t * tl);


/* Fonctions propre à la structure trans_layer */

/* Initialise une structure trans_layer */
struct trans_layer_t *init_tl();

/* Libère la structure trans_layer */
void free_tl(struct trans_layer_t *tl);

#endif /* TRANSPORT_H */