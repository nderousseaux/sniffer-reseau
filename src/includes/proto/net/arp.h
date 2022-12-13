// Analyse d'un paquet arp
#ifndef ARP_H
#define ARP_H

#include "pck.h"

#define PRINT_ARP "Address Resolution Protocol"
#define PRINT_ARP_SHRT "ARP"

/* Analyse du paquet arp */
void compute_arp(struct pck_t * pck);

/* Remplit la structure arp */
void fill_arp(struct pck_t * pck);

/* Met à jour le log de la couche arp */
void set_arp_log(struct pck_t * pck);

/* Rempli les logs détaillés pour le verbose 3 */
void fill_arp_log_v3(struct pck_t * pck);

#endif /* ARP_H */