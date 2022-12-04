// Gère un paquet ethernet
#ifndef H_GL_ETH
#define H_GL_ETH

#include <arpa/inet.h>
#include <netinet/ether.h>
#include <stdio.h>
#include <stdlib.h>

#include "arp.h"
#include "ipv4.h"
#include "printer.h"
#include "utils.h"

struct ether_info {
    struct ether_header *eth;   // Entête ethernet
    char                *infos; // Informations résumant le paquet
    struct arp_info     *arp;   // Paquet arp
    struct ipv4_info    *ipv4;  // Paquet ipv4
    // struct ipv6_info    *ipv6;  // Paquet ipv6
};

/* Traite un paquet ethernet */
void compute_ethernet(const u_char **pck);

/* Définit les variables du printer pour ethernet */
void set_printer_ethernet(struct ether_header *eth);

#endif // H_GL_ETH