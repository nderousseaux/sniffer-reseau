// Gère un paquet arp

#include "includes/includes.h"

/* Traite un paquet ethernet */
void compute_arp(const u_char **pck)
{
    struct ether_arp *arp = (struct ether_arp *) *pck;

    //On définit la couche réseau
    set_printer_arp(arp);
}

/* Définit les variables du printer pour arp */
void set_printer_arp(struct ether_arp *arp)
{
    //On définit les variables
    char * src;
    char * ip_dst;
    char * ip_src;
    struct arp_info *arp_info;
    struct paquet_info *paquet_info;


    //On définit les variables src et dst
    CHECK(src = malloc(20));
    ether_to_string((struct ether_addr *) arp->arp_sha, src);
    CHECK(ip_dst = malloc(16));
    ip_to_string((struct in_addr *) arp->arp_tpa, ip_dst);
    CHECK(ip_src = malloc(16));
    ip_to_string((struct in_addr *) arp->arp_spa, ip_src);

    //On remplit arp_info
    CHECK(arp_info = malloc(sizeof(struct arp_info)));
    arp_info->arp = arp;
    CHECK(arp_info->infos = malloc(255));
    sprintf(arp_info->infos, "Address resolution protocol (Request)");

    //On remplit paquet_info
    paquet_info = get_paquet_info();
    paquet_info->eth->arp = arp_info;
    
    //On remplit les infos principales
    if(ntohs(arp->ea_hdr.ar_op) == ARPOP_REQUEST)
    {
        sprintf(
            paquet_info->infos,
            "Who has %s? Tell %s",
            ip_dst,
            ip_src
        );
    }
    else if(ntohs(arp->ea_hdr.ar_op) == ARPOP_REPLY)
    {
        sprintf(
            paquet_info->infos,
            "%s is at %s",
            ip_src,
            src
        );
    }
    
}

/* On libère la mémoire */
void free_arp_info(struct arp_info *arp_info)
{
    free(arp_info->infos);
    free(arp_info);
}