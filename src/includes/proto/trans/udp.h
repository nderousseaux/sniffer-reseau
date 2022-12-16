// Analyse d'un paquet udp
#ifndef UDP_H
#define UDP_H

#include "pck.h"

#define PRINT_UDP "User Datagram Protocol"
#define PRINT_UDP_SHRT "UDP"

/* Analyse du paquet udp */
void compute_udp(struct pck_t * pck);

/* Remplit la structure udp */
void fill_udp(struct pck_t * pck);

/* Met à jour le log de la couche udp */
void set_udp_log(struct pck_t * pck);

/* Rempli les logs détaillés pour le verbose 3 */
void fill_udp_log_v3(struct pck_t * pck);

#endif /* UDP_H */