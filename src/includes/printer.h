#ifndef H_GL_PRINTER
#define H_GL_PRINTER

#include <arpa/inet.h>
#include <netinet/ether.h>
#include <netinet/if_ether.h>
#include <netinet/ip_icmp.h>
#include <netinet/udp.h>
#include <pcap.h>
#include <string.h>
#include <time.h>

#include "protocols.h"

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

#endif