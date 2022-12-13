// Analyse d'un paquet ip
#ifndef IP_H
#define IP_H

#include "pck.h"

#define PRINT_IP "Internet Protocol version 4"
#define PRINT_IP_SHRT "IPV4"

/* Analyse du paquet ip */
void compute_ip(struct pck_t * pck);

/* Remplit la structure ip */
void fill_ip(struct pck_t * pck);

/* Met à jour le log de la couche ip */
void set_ip_log(struct pck_t * pck);

/* Rempli les logs détaillés pour le verbose 3 */
void fill_ip_log_v3(struct pck_t * pck);

#endif /* IP_H */