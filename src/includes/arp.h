// Gère un paquet arp
#ifndef H_GL_ARP
#define H_GL_ARP

#include <arpa/inet.h>
#include <netinet/ether.h>
#include <stdio.h>
#include <stdlib.h>

#include "printer.h"
#include "utils.h"
#include "ethernet.h"

struct arp_info {
    struct ether_arp    *arp;   // Entête arp
    char                *infos; // Informations résumant le paquet
};

/* Traite un paquet arp */
void compute_arp(const u_char **pck);

/* Définit les variables du printer pour arp */
void set_printer_arp(struct ether_arp *arp);

#endif // H_GL_ARP