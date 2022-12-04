// Gère un paquet ipv4

#include "includes/ipv4.h"

/* Traite un paquet ipv4 */
void compute_ipv4(const u_char **pck){
    struct ip *iph = (struct ip *) *pck;

    //On définit la couche réseau
    set_printer_ipv4(iph);

    //On saute l'entête ipv4
    *pck += iph->ip_hl * 4;

    //On teste le protocole de la couche transport
    switch (iph->ip_p)
    {
        case IPPROTO_TCP:
            compute_tcp(pck);
            break;
        case IPPROTO_UDP:
            compute_udp(pck);
            break;
        case IPPROTO_ICMP:
            compute_icmp(pck);
            break;
        default:
            break;
    }

}

/* Définit les variables du printer pour ipv4 */
void set_printer_ipv4(struct ip *ipv4){
    //On définit les variables
    char * src;
    char * dst;
    char * type;
    struct ipv4_info *ipv4_info;
    struct paquet_info *paquet_info;

    //On définit les variables src et dst
    CHECK(src = malloc(INET_ADDRSTRLEN));
    ip_to_string(&ipv4->ip_src, src);
    CHECK(dst = malloc(INET_ADDRSTRLEN));
    ip_to_string(&ipv4->ip_dst, dst);

    //On définit le type
    CHECK(type = malloc(10));
    switch(ipv4->ip_p)
    {
        case IPPROTO_TCP:
            type = "TCP";
            break;
        case IPPROTO_UDP:
            type = "UDP";
            break;
        case IPPROTO_ICMP:
            type = "ICMP";
            break;
        default:
            type = UNKNOWN;
            break;
    }

    //On remplit ipv4_info
    CHECK(ipv4_info = malloc(sizeof(struct ipv4_info)));
    ipv4_info->ipv4 = ipv4;
    CHECK(ipv4_info->infos = malloc(255));
    sprintf(
        ipv4_info->infos,
        "Internet Protocol Version 4 Src: %s, Dst: %s",
        src,
        dst
    );

    //On remplit paquet_info
    paquet_info = get_paquet_info();
    paquet_info->src = src;
    paquet_info->dst = dst;
    paquet_info->protocol = type;
    paquet_info->eth->ipv4 = ipv4_info;
    sprintf(
        paquet_info->infos,
        "IPv4, Src: %s, Dst: %s",
        src,
        dst
    );
}