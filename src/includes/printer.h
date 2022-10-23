#ifndef H_GL_PRINTER
#define H_GL_PRINTER

#include <arpa/inet.h>
#include <netinet/ether.h>
#include <netinet/if_ether.h>
#include <netinet/ip_icmp.h>
#include <netinet/udp.h>
#include <pcap.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "protocols.h"

/* Retourne une chaine avec la version hexa d'une variable */   
char * get_hex(void * var, int size);

/* Affiche l'heure */
void print_time(const struct pcap_pkthdr *meta, int verbose_level);

/* Affiche l'entête ethernet */
void print_ethernet(const struct ether_header *eth, int verbose_level);

/* Affiche l'entête ipv4 */
void print_ipv4(const struct ip *iph, int verbose_level);

/* Affiche l'entête udp */
void print_udp(const struct udphdr *udph, int verbose_level);

/* Affiche l'entête bootp */
void print_bootp(const struct bootp *bootph, int verbose_level);

/* Affiche la zone vendor specific de bootp */
void print_vendor_specific(const struct vendor_specific_t *vendor_specific, int verbose_level);

/* Affiche la zone dhcp */
void print_dhcp(const struct vendor_specific_t *vendor_specific, int verbose_level);

#endif