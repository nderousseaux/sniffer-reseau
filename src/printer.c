#include "./includes/printer.h"
   
/* Affiche l'heure */
void print_time(const struct pcap_pkthdr *meta, int verbose_level)
{
    time_t timestamp = meta->ts.tv_sec;
    struct tm * s_time = localtime(&timestamp);
    char time[20];
    if(verbose_level == 3)
        strftime( time, 20, "%d/%m/%Y %H:%M:%S", s_time);
    else
        strftime( time, 20, "%H:%M:%S", s_time);

    printf("%s.%06ld", time, meta->ts.tv_usec);
    if(verbose_level == 1)
        printf(" ");
    else
        printf("\n");

}

/* Affiche l'entête ethernet */
void print_ethernet(const struct ether_header *eth, int verbose_level)
{
    char ether_type[5];
    
    //On enregistre le nom du protocole
    switch(ntohs(eth->ether_type))
    {
        case ETHERTYPE_IP:
            strcpy(ether_type, "IPv4");
            break;
        case ETHERTYPE_IPV6:
            strcpy(ether_type, "IPv6");
            break;
        case ETHERTYPE_ARP:
            strcpy(ether_type, "ARP");
            break;
        default:
            strcpy(ether_type, "???");
            break;
    }

    //On affiche l'entête
    switch (verbose_level)
    {
        case 1:
            printf("%s ", ether_type);
            break;
        case 2:
            printf("Ethernet: %s %s > %s\n",
                ether_type,
                ether_ntoa((const struct ether_addr *)&eth->ether_shost),
                ether_ntoa((const struct ether_addr *)&eth->ether_shost)
            );
            break;
        case 3:
            printf(" ├ Trame ethernet\n");
            printf(" | ├ Type: %s\n", ether_type);
            printf(" | ├ Source: %s\n", ether_ntoa((const struct ether_addr *)&eth->ether_shost));
            printf(" | ├ Destination: %s\n", ether_ntoa((const struct ether_addr *)&eth->ether_shost));
            break;
        default:
            break;
    }
}

/* Affiche l'entête ipv4 */
void print_ipv4(const struct ip *iph, int verbose_level){
    char ip_type[5];
    
    //On enregistre le nom du protocole
    switch(iph->ip_p)
    {
        case IPPROTO_TCP:
            strcpy(ip_type, "TCP");
            break;
        case IPPROTO_UDP:
            strcpy(ip_type, "UDP");
            break;
        case IPPROTO_ICMP:
            strcpy(ip_type, "ICMP");
            break;
        default:
            strcpy(ip_type, "???");
            break;
    }

    //On affiche l'entête
    switch (verbose_level)
    {
        case 1:
            printf("%s > %s %s",
                inet_ntoa(iph->ip_src),
                inet_ntoa(iph->ip_dst),
                ip_type    
            );
            break;
        case 2:
            printf("IP: %s %s > %s\n",
                ip_type,
                inet_ntoa(iph->ip_src),
                inet_ntoa(iph->ip_dst)
            );
            break;
        case 3:
            printf(" ├ Trame IPv4\n");
            printf(" | ├ Version: %d\n", iph->ip_v);
            printf(" | ├ Taille de l'entête: %d\n", iph->ip_hl);
            printf(" | ├ Type de service: %d\n", iph->ip_tos);
            printf(" | ├ Taille totale: %d\n", ntohs(iph->ip_len));
            printf(" | ├ Identifiant: %d\n", ntohs(iph->ip_id));
            printf(" | ├ Définition du fragment: %d\n", ntohs(iph->ip_off));
            printf(" | ├ Temps de vie: %d\n", iph->ip_ttl);
            printf(" | ├ Protocole: %s\n", ip_type);
            printf(" | ├ Somme de contrôle: %d\n", ntohs(iph->ip_sum));
            printf(" | ├ Source: %s\n", inet_ntoa(iph->ip_src));
            printf(" | ├ Destination: %s\n", inet_ntoa(iph->ip_dst));
            
            break;
        default:
            break;
    }
}