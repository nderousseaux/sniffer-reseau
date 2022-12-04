// Gère un paquet tcp
#ifndef H_GL_TCP
#define H_GL_TCP

#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <stdio.h>
#include <stdlib.h>

#include "ipv4.h"
#include "printer.h"
#include "utils.h"

struct tcp_info_2 { //Car il existe déjà une structure tcp_info
    struct tcphdr      *tcp;      // Header tcp
    char                *infos;    // Informations sur le paquet
};

/* Traite un paquet tcp */
void compute_tcp(const u_char **pck);

/* Définit les variables du printer pour tcp */
void set_printer_tcp(struct tcphdr *tcp);

#endif // H_GL_TCP
