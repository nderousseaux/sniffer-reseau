// Analyse d'un paquet ip6
#ifndef IP6_H
#define IP6_H

#include "pck.h"

#define PRINT_IP6 "Internet Protocol version 6"
#define PRINT_IP6_SHRT "IPV6"

/* Analyse du paquet ip6 */
void compute_ip6(struct pck_t * pck);

/* Remplit la structure ip6 */
void fill_ip6(struct pck_t * pck);

/* Met à jour le log de la couche ip6 */
void set_ip6_log(struct pck_t * pck);

/* Rempli les logs détaillés pour le verbose 3 */
void fill_ip6_log_v3(struct pck_t * pck);

#endif /* IP6_H */