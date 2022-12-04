//Boucle principale de l'appli, redirige vers les fonctions de traitement de chaque protocole

#ifndef H_GL_SNIFFER
#define H_GL_SNIFFER

#include <pcap.h>

#include "args.h"
#include "ethernet.h"
#include "printer.h"

/* Ouvre un handler de socket pour la capture de paquets */
pcap_t *init_handler(struct args args);

/* Analyse un paquet reçu */
void compute_paquet(struct args *args, const struct pcap_pkthdr *hdr, const u_char *pck);

/* Get le paquet original */
const u_char **get_paquet();

#endif //H_GL_SNIFFER