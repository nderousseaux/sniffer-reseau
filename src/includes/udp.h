// Gère un paquet udp
#ifndef H_GL_UDP
#define H_GL_UDP

#include <netinet/udp.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <stdio.h>
#include <stdlib.h>


#include "dns.h"
#include "ipv4.h"
#include "printer.h"
#include "utils.h"
#include "bootp.h"

struct udp_info {
    struct udphdr       *udp;   //Entête udp
    char                *infos; //Informations résumant le paquet
    struct dns_info     *dns;  //Entête dns
    struct bootp_info   *bootp; //Entête bootp
};

/* Traite un paquet udp */
void compute_udp(const u_char **pck);

/* Définit les variables du printer pour udp */
void set_printer_udp(struct udphdr *udp);

#endif // H_GL_UDP