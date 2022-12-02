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

#include "dns.h"
#include "protocols.h"
#include "sniffer.h"
#include "utils.h"

/* Affiche le header */
void print_header(const struct pcap_pkthdr *meta, int vl);

/* Affiche l'entête ethernet */
void print_ethernet(const struct ether_header *eth);

/* Affiche l'entête arp */
void print_arp(const struct ether_arp *arp);

/* Affiche l'entête ipv4 */
void print_ipv4(const struct ip *iph);

/* Affiche l'entête icmp */
void print_icmp(const struct icmp *icmp);

/* Affiche l'entête udp */
void print_udp(const struct udphdr *udph);

/* Affiche l'entête bootp */
void print_bootp(const struct bootp *bootph);

/* Affiche la zone vendor specific de bootp */
void print_vendor_specific(const struct vendor_specific_t *vendor_specific);

/* Affiche la zone dhcp */
void print_dhcp(const struct vendor_specific_t *vendor_specific);

/* Affiche un paquet dns */
void print_dns(const struct dns_t *dns);

/* Affiche le protocole et la taille */
void print_protocol();

#endif