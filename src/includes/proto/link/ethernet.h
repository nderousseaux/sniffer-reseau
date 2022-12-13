// Analyse d'un paquet ethernet
#ifndef ETHER_H
#define ETHER_H

#include "pck.h"

#define PRINT_ETH "Ethernet II"
#define PRINT_ETH_SHRT "ETHER"

/* Analyse du paquet ethernet */
void compute_ether(struct pck_t * pck);

/* Remplit la structure ethernet */
void fill_ether(struct pck_t * pck);

/* Met à jour le log de la couche ethernet */
void set_ether_log(struct pck_t * pck);

/* Rempli les logs détaillés pour le verbose 3 */
void fill_ether_log_v3(struct pck_t * pck);

#endif