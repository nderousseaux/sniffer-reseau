// Analyse d'un paquet icmp
#ifndef ICMP_H
#define ICMP_H

#include "pck.h"

#define PRINT_ICMP "Internet Control Message Protocol"
#define PRINT_ICMP_SHRT "ICMP"

/* Analyse du paquet icmp */
void compute_icmp(struct pck_t * pck);

/* Remplit la structure icmp */
void fill_icmp(struct pck_t * pck);

/* Met à jour le log de la couche icmp */
void set_icmp_log(struct pck_t * pck);

/* Rempli les logs détaillés pour le verbose 3 */
void fill_icmp_log_v3(struct pck_t * pck);

#endif /* ICMP_H */