// Gère un paquet ethernet
#include "includes/ethernet.h"

/* Traite un paquet ethernet */
void compute_ethernet(const u_char **pck)
{
    struct ether_header *eth = (struct ether_header *) *pck;

    //On définit la couche liaison
    set_printer_ethernet(eth);

    // On saute l'entête ethernet
    *pck += 14;

    //On teste le protocole de la couche réseau
    switch (ntohs(eth->ether_type))
    {
        case ETHERTYPE_IP:
            compute_ipv4(pck);
            break;
        case ETHERTYPE_IPV6:
            //TODO
            break;
        case ETHERTYPE_ARP:
            compute_arp(pck);
            break;
        default:
            break;
    }
}

/* Définit les variables du printer pour ethernet */
void set_printer_ethernet(struct ether_header *eth)
{
    //On définit les variables
    char * src;
    char * dst;
    char * type;
    struct ether_info *eth_info;
    struct paquet_info *paquet_info;

    //On définit les variables src et dst
    CHECK(src = malloc(20));
    ether_to_string((struct ether_addr *) eth->ether_shost, src);
    CHECK(dst = malloc(20));
    ether_to_string((struct ether_addr *) eth->ether_dhost, dst);

    //On définit le type
    CHECK(type = malloc(10));
    switch (ntohs(eth->ether_type))
    {
        case ETHERTYPE_IP:
            type = "IPv4";
            break;
        case ETHERTYPE_IPV6:
            type = "IPv6";
            break;
        case ETHERTYPE_ARP:
            type = "ARP";
            break;
        default:
            type = UNKNOWN;
            break;
    }

    //On remplit ethernet_info
    CHECK(eth_info = malloc(sizeof(struct ether_info)));
    eth_info->eth = eth;
    CHECK(eth_info->infos = malloc(255));
    sprintf(
        eth_info->infos,
        "Ethernet II, Src: %s, Dst: %s",
        src,
        dst
    );

    //On remplit paquet_info
    paquet_info = get_paquet_info();
    paquet_info->src = src;
    paquet_info->dst = dst;
    paquet_info->protocol = type;
    paquet_info->eth = eth_info;
    strcpy(paquet_info->infos, eth_info->infos);

}