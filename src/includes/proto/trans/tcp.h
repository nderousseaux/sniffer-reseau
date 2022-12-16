// Analyse d'un paquet tcp
#ifndef TCP_H
#define TCP_H

#include "pck.h"

#define PRINT_TCP "Transmission Control Protocol"
#define PRINT_TCP_SHORT "TCP"

/* Analyse du paquet tcp */
void compute_tcp(struct pck_t * pck);

/* Remplit la structure tcp */
void fill_tcp(struct pck_t * pck);

/* Met à jour le log de la couche tcp */
void set_tcp_log(struct pck_t * pck);

/* Rempli les logs détaillés pour le verbose 3 */
void fill_tcp_log_v3(struct pck_t * pck);

#endif /* TCP_H */