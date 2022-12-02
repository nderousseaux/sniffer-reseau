#include "./includes/printer.h"

int verbose_level = 1; //Niveau de verbosité
int nb_frames = 0;     // Nombre de frames analysées
struct timeval *ts;    // Heure du premier paquet
char protocol[10] = UNKNOWN; //Protocole en cours d'analyse
int length = 0;        // Taille du paquet en cours d'analyse

/* Affiche le header */
void print_header(const struct pcap_pkthdr *meta, int vl)
{ 
    verbose_level = vl;
    //Si c'est la première frame, on enregistre le temps 0 (secondes et microsecondes)
    if (nb_frames == 0){
        ts = malloc(sizeof(struct timeval));
        ts->tv_sec = meta->ts.tv_sec;
        ts->tv_usec = meta->ts.tv_usec;
    }
    //On soustrait le temps 0 au temps de la frame
    int sec = meta->ts.tv_sec - ts->tv_sec;
    int usec = meta->ts.tv_usec - ts->tv_usec;
    //Si les microsecondes sont négatives, on les ajoute à la seconde
    if (usec < 0) {
        usec += 1000000;
        sec--;
    }
    
    // On affiche l'entête
    switch (verbose_level)
    {
        case 1:
            if (nb_frames == 0)
                printf("No.\tTime\t\tSource\t\t\tDestination\t\tProtocol\tLength\tInfo\n");
            printf("%d\t%d.%06d ",nb_frames, sec, usec);
            break;
        default:
            break;
    }

    length = meta->len;
    nb_frames++;

}

/* Affiche l'entête ethernet */
void print_ethernet(const struct ether_header *eth)
{
    //On enregistre le nom du protocole
    switch(ntohs(eth->ether_type))
    {
        case ETHERTYPE_IP:
            strcpy(protocol, "IPv4");
            break;
        case ETHERTYPE_IPV6:
            strcpy(protocol, "IPv6");
            break;
        case ETHERTYPE_ARP:
            strcpy(protocol, "ARP");
            break;
        default:
            break;
    }

    //On affiche l'entête
    switch (verbose_level)
    {
        default:
            break;
    }
}

/* Affiche l'entête arp */
void print_arp(const struct ether_arp *arp)
{
    //On affiche l'entête
    switch (verbose_level)
    {
        case 1:
            //On affiche la source, la destination, le protocole et la taille
            printf(
                "\t%s\t\t%s\t\tARP\t\t%d",
                ether_ntoa((const struct ether_addr *)&arp->arp_sha),
                ether_ntoa((const struct ether_addr *)&arp->arp_tha),
                length
            );
            //On affiche les informations
            //Si c'est une requete
            if(ntohs(arp->ea_hdr.ar_op) == ARPOP_REQUEST)
                printf(
                    "\tWho has %s? Tell %s",
                    inet_ntoa(*(struct in_addr *)arp->arp_tpa),
                    inet_ntoa(*(struct in_addr *)arp->arp_spa)
                );
            //Si c'est une réponse
            else if(ntohs(arp->ea_hdr.ar_op) == ARPOP_REPLY)
                printf(
                    "\t%s is at %s",
                    inet_ntoa(*(struct in_addr *)arp->arp_spa),
                    ether_ntoa((const struct ether_addr *)&arp->arp_sha)
                );
            break;
        default:
            break;
    }
}

/* Affiche l'entête ipv4 */
void print_ipv4(const struct ip *iph)
{   
    char src[INET_ADDRSTRLEN];
    char dst[INET_ADDRSTRLEN];
    //On enregistre le nom du protocole
    switch(iph->ip_p)
    {
        case IPPROTO_TCP:
            strcpy(protocol, "TCP");
            break;
        case IPPROTO_UDP:
            strcpy(protocol, "UDP");
            break;
        case IPPROTO_ICMP:
            strcpy(protocol, "ICMP");
            break;
        default:
            break;
    }

    //Si c'est 0.0.0.0, on affiche *
    if (iph->ip_src.s_addr == 0)
        strcpy(src, "broadcast");
    else
        strcpy(src, inet_ntoa(iph->ip_src));
    if (iph->ip_dst.s_addr == 0)
        strcpy(dst, "broadcast");
    else
        strcpy(dst, inet_ntoa(iph->ip_dst));

    //On affiche l'entête
    switch (verbose_level)
    {
        case 1:
            //On affiche la source et la destination
            printf("\t%s\t\t", src);
            if(strlen(src) < 8 ) printf("\t");
            printf("%s", dst);
            if(strlen(dst) < 8 ) printf("\t");
            break;
        default:
            break;
    }
}

/* Affiche l'entête icmp */
void print_icmp(const struct icmp *icmp){
    (void)icmp;

    //On affiche l'entête
    switch (verbose_level)
    {
        case 1:
            print_protocol();
            switch (icmp->icmp_type)
            {
                case ICMP_ECHO:
                    printf(
                        "\tEcho (ping) request id=%d, seq=%d",
                        ntohs(icmp->icmp_id),
                        ntohs(icmp->icmp_seq)
                    );
                    break;
                case ICMP_ECHOREPLY:
                     printf(
                        "\tEcho (ping) reply id=%d, seq=%d",
                        ntohs(icmp->icmp_id),
                        ntohs(icmp->icmp_seq)
                    );
                    break;
                case ICMP_UNREACH:
                    printf("\tDestination unreachable");
                    break;
                case ICMP_TIMXCEED:
                    printf("\tTime exceeded");
                    break;
                default:
                    break;
            }
        default:
            break;
    }
}

/* Affiche l'entête udp */
void print_udp(const struct udphdr *udph)
{
    // On enregistre le nom du protocole
    switch(ntohs(udph->dest))
    {
        case 53:
            strcpy(protocol, "DNS");
            break;
        case 67:
            strcpy(protocol, "BOOTP");
            break;
        case 68:
            strcpy(protocol, "BOOTP");
            break;
        default:
            if (ntohs(udph->source) == 53)
                strcpy(protocol, "DNS");
            break;
    }

    //On affiche l'entête
    switch (verbose_level)
    {
        case 1:
            break;
        default:
            break;
    }
}

/* Affiche l'entête bootp */
void print_bootp(const struct bootp *bootph)
{
    (void)bootph;
    switch (verbose_level)
    {
        default:
            break;
    }
}

/* Affiche la zone vendor specific de bootp */
void print_vendor_specific(const struct vendor_specific_t *vendor_specific)
{

    //On détecte si c'est du dhcp
    if(vendor_specific->options[53] != 0){
        print_dhcp(vendor_specific);
        return;
    }
    switch (verbose_level)
    {
        default:
            break;
    }
}

/* Affiche la zone dhcp */
void print_dhcp(const struct vendor_specific_t *vendor_specific)
{
    strcpy(protocol, "DHCP");

    int message_type = vendor_specific->options[53]->value[0];
    char * message_type_str = "Unknown";
    char * ip = "";
    switch (message_type){
        case 1:
            message_type_str = "DHCP Discover";
            break;
        case 2:
            message_type_str = "DHCP Offer";
            break;
        case 3:
            message_type_str = "DHCP Request";
            if(vendor_specific->options[50] != 0){
                ip = inet_ntoa(*(struct in_addr *)vendor_specific->options[50]->value);
            }
            break;
        case 5:
            message_type_str = "DHCP Ack";
            if(vendor_specific->options[50] != 0){
                ip = inet_ntoa(*(struct in_addr *)vendor_specific->options[50]->value);
            }
            break;
        default:
            break;
    }

    //On affiche la zone dhcp
    switch(verbose_level){
        case 1:
            if(!strcmp(ip, ""))
                printf(
                    "\t\t%s\t\t%d\t%s",
                    protocol,
                    length,
                    message_type_str
                );
            else
                printf(
                    "\t\t%s\t\t%d\t%s (%s)",
                    protocol,
                    length,
                    message_type_str,
                    ip
                );
            break;
        default:
            break;
    }
}

/* Affiche un paquet dns */
void print_dns(const struct dns_t *dns)
{   
    switch (verbose_level){
        case 1:
            print_protocol();
            //On teste si c'est une requête ou une réponse
            if(dns->header->qr){
                printf("\tStandart query response");
            }else{
                printf("\tStandart query");
            }
            //On affiche le transaction id en hexa
            printf(" 0x%04x", ntohs(dns->header->id));

            //On affiche toutes les queries
            for(int i = 0; i < ntohs(dns->header->q_count); i++){
                printf(" %s %s", dns->queries[i].type, dns->queries[i].name);
            }
            // On affiche toutes les réponses
            for(int i = 0; i < ntohs(dns->header->ans_count); i++){                
                printf(" %s", dns->answers[i].type);
                printf(" %s", dns->answers[i].name);
                // printf(" %s %s", dns->answers[i].type, dns->answers[i].main_info);
            }
            break;
        default:
            break;
    }
}

/* Affiche le protocole et la longueur */
void print_protocol() {
    switch (verbose_level) {
        case 1:
            printf(
                "\t\t%s\t\t%d",
                protocol,
                length
            );
            break;
        default:
            break;
    }
}
