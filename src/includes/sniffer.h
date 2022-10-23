#ifndef H_GL_SNIFFER
#define H_GL_SNIFFER

#include <errno.h>
#include "args.h"
#include "printer.h"

//Pour x == 0 (parfait pour malloc/calloc) et tout les appels systèmes
#define CHECK(x) \
  do { \
    if (!(x)) { \
      fprintf(stderr, "%s:%d: ", __func__, __LINE__); \
	  if(errno==0) errno=ECANCELED; \
      perror(#x); \
      exit(EXIT_FAILURE); \
    } \
  } while (0)


/* Ouvre un handler de socket pour la capture de paquets */
pcap_t *init_handler(struct args args);

/* Analyse un paquet reçu */
void compute_paquet(struct args *args, const struct pcap_pkthdr *hdr, const u_char *pck);

/* Traite un paquet ethernet */
void compute_ethernet(const u_char **pck, int verbose_level);

/* Traite un paquet ipv4 */
void compute_ipv4(const u_char **pck, int verbose_level);

/* Traite un paquet ipv6 */
void compute_ipv6(const u_char **pck, int verbose_level);

/* Traite un paquet arp */
void compute_arp(const u_char **pck, int verbose_level);

/* Traite un paquet icmp */
void compute_icmp(const u_char **pck, int verbose_level);

/* Traite un paquet tcp */
void compute_tcp(const u_char **pck, int verbose_level);

/* Traite un paquet udp */
void compute_udp(const u_char **pck, int verbose_level);

/* Traite un paquet dns */
void compute_dns(const u_char **pck, int verbose_level);

/* Traite un paquet bootp */
void compute_bootp(const u_char **pck, int verbose_level);

/* Traite la zone vendor specific de bootp (vaut pour le dhcp) */
void compute_vendor_specific(const u_char **pack, int verbose_level);

/* Traite un paquet http */
void compute_http(const u_char **pck, int verbose_level);

/* Traite un paquet https */
void compute_https(const u_char **pck, int verbose_level);

#endif