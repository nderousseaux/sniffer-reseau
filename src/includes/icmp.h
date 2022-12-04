// Gère un paquet icmp
#ifndef H_GL_ICMP
#define H_GL_ICMP

#include <netinet/ip_icmp.h>
#include <stdio.h>
#include <stdlib.h>

#include "ipv4.h"
#include "printer.h"
#include "utils.h"

struct icmp_info {
    struct icmp         *icmp;  // Entête icmp
    char                *infos; // Informations résumant le paquet
};

/* Traite un paquet icmp */
void compute_icmp(const u_char **pck);

/* Définit les variables du printer pour icmp */
void set_printer_icmp(struct icmp *icmp);

#endif // H_GL_ICMP