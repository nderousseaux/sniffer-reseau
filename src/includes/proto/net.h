// Analyse de la couche netWork
#ifndef NETWORK_H
#define NETWORK_H

#include "pck.h"

enum net_type {
    IP,
    IPV6,
    ARP
};

struct net_layer_t {
    enum net_type           type;   // Type de couche réseau
    int                     offset; // Offset du la fin de la couche réseau
    char                    *log;   // Log de la couche réseau
    struct ip               *ip;    // Informations liées à l'ip (si type = IP)
    struct ip6_hdr          *ip6;   // Informations liées à l'ip (si type = IPV6)
    struct ether_arp        *arp;   // Informations liées à l'arp (si type = ARP)
    struct log_v3_t         *log_v3;
};

/* Analyse la couche réseau */
void compute_net(struct pck_t * pck);

/* Détermine le type de réseau */
void determine_net_type(struct pck_t * pck);

/* Met à jour le log de la couche réseau */
void set_net_log(struct pck_t * pck, struct net_layer_t * nl);


/* Fonctions propre à la structure net_layer */

/* Initialise une structure net_layer */
struct net_layer_t *init_nl();

/* Libère la structure net_layer */
void free_nl(struct net_layer_t *nl);

#endif /* NETWORK_H */