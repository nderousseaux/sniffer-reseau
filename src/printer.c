#include "./includes/printer.h"

/* Retourne une chaine avec la version hexa d'une variable */   
char * get_hex(void * var, int size)
{
    char * hex = malloc(size * 2 + 1 + 3);
    char * hex_ptr = hex;
    //On ajoute le préfixe 0x
    *hex_ptr = '0';
    hex_ptr++;
    *hex_ptr = 'x';
    hex_ptr++;
    unsigned char * var_ptr = (unsigned char *) var;
    for (int i = 0; i < size; i++)
    {
        sprintf(hex_ptr, "%02x", *var_ptr);
        hex_ptr += 2;
        var_ptr++;
    }
    return hex;
}

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
            printf("%s", ether_type);
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
void print_ipv4(const struct ip *iph, int verbose_level)
{
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
            printf(" %s > %s %s",
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

/* Affiche l'entête arp */
void print_arp(const struct ether_arp *arp, int verbose_level)
{
    char arp_type[10];
    char hardware_type[10];
    char protocol_type[10];
    
    //On enregistre le nom du protocole
    switch(ntohs(arp->arp_op))
    {
        case ARPOP_REQUEST:
            strcpy(arp_type, "Requête");
            break;
        case ARPOP_REPLY:
            strcpy(arp_type, "Réponse");
            break;
        default:
            strcpy(arp_type, "???");
            break;
    }

    //On enregistre le nom du hardware
    switch(ntohs(arp->arp_hrd))
    {
        case ARPHRD_ETHER:
            strcpy(hardware_type, "Ethernet");
            break;
        default:
            strcpy(hardware_type, "???");
            break;
    }

    //On enregistre le nom du protocole
    switch(ntohs(arp->arp_pro))
    {
        case ETHERTYPE_IP:
            strcpy(protocol_type, "IPv4");
            break;
        case ETHERTYPE_IPV6:
            strcpy(protocol_type, "IPv6");
            break;
        default:
            strcpy(protocol_type, "???");
            break;
    }

    //On affiche l'entête
    switch (verbose_level)
    {
        case 1:
            printf(" %s ", inet_ntoa(*(struct in_addr *)arp->arp_spa));
            if(ntohs(arp->arp_op) == ARPOP_REQUEST)
                printf("> %s",inet_ntoa(*(struct in_addr *)arp->arp_tpa));
            else
                printf(": %s",ether_ntoa((const struct ether_addr *)&arp->arp_tha));
            break;
        case 2:
            printf("ARP: %s ", inet_ntoa(*(struct in_addr *)arp->arp_spa));
            //Si le type est une requête
            if(ntohs(arp->arp_op) == ARPOP_REQUEST)
                printf("demande qui est %s\n", inet_ntoa(*(struct in_addr *)arp->arp_tpa));
            else
                printf("est %s\n",ether_ntoa((const struct ether_addr *)arp->arp_sha));
            break;
        case 3:
            printf(" ├ Trame ARP %s ", inet_ntoa(*(struct in_addr *)arp->arp_spa));
            if(ntohs(arp->arp_op) == ARPOP_REQUEST)
                printf("demande qui est %s\n", inet_ntoa(*(struct in_addr *)arp->arp_tpa));
            else
                printf("est %s\n",ether_ntoa((const struct ether_addr *)arp->arp_sha));
            printf(" | ├ Type de hardware: %s\n", hardware_type);
            printf(" | ├ Type du protocole: %s\n", protocol_type);
            printf(" | ├ Taille de l'addresse hardware: %d\n", arp->arp_hln);
            printf(" | ├ Taille de l'addresse protocole: %d\n", arp->arp_pln);
            printf(" | ├ Opéaration: %s\n", arp_type);
            printf(" | ├ MAC source: %s\n", ether_ntoa((const struct ether_addr *)&arp->arp_sha));
            printf(" | ├ IP source: %s\n", inet_ntoa(*(struct in_addr *)arp->arp_spa));
            printf(" | ├ MAC destination: %s\n", ether_ntoa((const struct ether_addr *)&arp->arp_tha));
            printf(" | ├ IP destination: %s\n", inet_ntoa(*(struct in_addr *)arp->arp_tpa));

            break;
        default:
            break;
    }
}

/* Affiche l'entête icmp */
void print_icmp(const struct icmp *icmp, int verbose_level){
    char icmp_type[50]; //TODO Tout vérifier (made in github)
    char icmp_code[50];

    //On enregistre le nom du type
    switch(icmp->icmp_type)
    {
        case ICMP_ECHOREPLY:
            strcpy(icmp_type, "Echo Reply");
            break;
        case ICMP_UNREACH:
            strcpy(icmp_type, "Destination Unreachable");
            break;
        case ICMP_SOURCEQUENCH:
            strcpy(icmp_type, "Source Quench");
            break;
        case ICMP_REDIRECT:
            strcpy(icmp_type, "Redirect");
            break;
        case ICMP_ECHO:
            strcpy(icmp_type, "Echo Request");
            break;
        case ICMP_TIMXCEED:
            strcpy(icmp_type, "Time Exceeded");
            break;
        case ICMP_PARAMPROB:
            strcpy(icmp_type, "Parameter Problem");
            break;
        case ICMP_TSTAMP:
            strcpy(icmp_type, "Timestamp Request");
            break;
        case ICMP_TSTAMPREPLY:
            strcpy(icmp_type, "Timestamp Reply");
            break;
        case ICMP_IREQ:
            strcpy(icmp_type, "Information Request");
            break;
        case ICMP_IREQREPLY:
            strcpy(icmp_type, "Information Reply");
            break;
        case ICMP_MASKREQ:
            strcpy(icmp_type, "Address Mask Request");
            break;
        case ICMP_MASKREPLY:
            strcpy(icmp_type, "Address Mask Reply");
            break;
        default:
            strcpy(icmp_type, "???");
            break;
    }

    //On enregistre le nom du code
    switch(icmp->icmp_code)
    {
        case ICMP_UNREACH_NET:
            strcpy(icmp_code, "Network Unreachable");
            break;
        case ICMP_UNREACH_HOST:
            strcpy(icmp_code, "Host Unreachable");
            break;
        case ICMP_UNREACH_PROTOCOL:
            strcpy(icmp_code, "Protocol Unreachable");
            break;
        case ICMP_UNREACH_PORT:
            strcpy(icmp_code, "Port Unreachable");
            break;
        case ICMP_UNREACH_NEEDFRAG:
            strcpy(icmp_code, "Fragmentation Needed");
            break;
        case ICMP_UNREACH_SRCFAIL:
            strcpy(icmp_code, "Source Route Failed");
            break;
        case ICMP_UNREACH_NET_UNKNOWN:
            strcpy(icmp_code, "Network Unknown");
            break;
        default:
            strcpy(icmp_code, "???");
            break;
    }

    //On affiche l'entête
    switch (verbose_level)
    {
        case 1:
            printf(" %s ", inet_ntoa(*(struct in_addr *)&icmp->icmp_ip.ip_src));
            printf("> %s",inet_ntoa(*(struct in_addr *)&icmp->icmp_ip.ip_dst));
            break;
        case 2:
            printf("ICMP: %s ", inet_ntoa(*(struct in_addr *)&icmp->icmp_ip.ip_src));
            printf("est %s\n", inet_ntoa(*(struct in_addr *)&icmp->icmp_ip.ip_dst));
            break;
        case 3:
            printf(" ├ Trame ICMP %s ", inet_ntoa(*(struct in_addr *)&icmp->icmp_ip.ip_src));
            printf("est %s\n", inet_ntoa(*(struct in_addr *)&icmp->icmp_ip.ip_dst));
            printf(" | ├ Type: %s\n", icmp_type);
            printf(" | ├ Code: %s\n", icmp_code);
            printf(" | ├ Checksum: %d\n", icmp->icmp_cksum);
            printf(" | ├ ID: %d\n", icmp->icmp_id);
            printf(" | ├ Sequence: %d\n", icmp->icmp_seq);
            break;
        default:
            break;
    }
}

/* Affiche l'entête udp */
void print_udp(const struct udphdr *udph, int verbose_level)
{

    //On affiche l'entête
    switch (verbose_level)
    {
        case 1:
            printf(" %d > %d",
                ntohs(udph->uh_sport),
                ntohs(udph->uh_dport)
            );
            break;
        case 2:
            printf("UDP: Port %d to port %d\n",
                ntohs(udph->uh_sport),
                ntohs(udph->uh_dport)
            );
            break;
        case 3:
            printf(" ├ Trame UDP\n");
            printf(" | ├ Port source: %d\n", ntohs(udph->uh_sport));
            printf(" | ├ Port destination: %d\n", ntohs(udph->uh_dport));
            printf(" | ├ Longueur: %d\n", ntohs(udph->uh_ulen));
            printf(" | ├ Somme de contrôle: %d\n", ntohs(udph->uh_sum));
            break;
        default:
            break;
    }
}

/* Affiche l'entête bootp */
void print_bootp(const struct bootp *bootph, int verbose_level)
{
    //On affiche l'entête
    switch (verbose_level)
    {
        case 1:
            printf(" BOOTP");
            break;
        case 2:
            printf("BOOTP: Client %s - Server %s\n",
                inet_ntoa(bootph->bp_ciaddr),
                inet_ntoa(bootph->bp_siaddr)
            );
            break;
        case 3:
            printf(" ├ Trame BOOTP\n");
            printf(" | ├ Code opérationnel: %d\n", bootph->bp_op);
            printf(" | ├ Type de hardware: %d\n", bootph->bp_htype);
            printf(" | ├ Taille de l'adresse hardware: %d\n", bootph->bp_hlen);
            printf(" | ├ Nombre de sauts: %d\n", bootph->bp_hops);
            printf(" | ├ Identifiant de transaction: %d\n", ntohl(bootph->bp_xid));
            printf(" | ├ Temps écoulé: %d\n", ntohs(bootph->bp_secs));
            printf(" | ├ Flags: %d\n", ntohs(bootph->bp_flags));
            printf(" | ├ Adresse IP client: %s\n", inet_ntoa(bootph->bp_ciaddr));
            printf(" | ├ Adresse IP Allouée: %s\n", inet_ntoa(bootph->bp_yiaddr));
            printf(" | ├ Adresse IP serveur: %s\n", inet_ntoa(bootph->bp_siaddr));
            printf(" | ├ Adresse IP Gateway: %s\n", inet_ntoa(bootph->bp_giaddr));
            printf(" | ├ Adresse hardware client: %s\n", ether_ntoa((const struct ether_addr *)&bootph->bp_chaddr));
            printf(" | ├ Nom du serveur: %s\n", bootph->bp_sname);
            printf(" | ├ Nom du fichier de boot: %s\n", bootph->bp_file);
            break;
        default:
            break;            
    }
    
}

/* Affiche la zone vendor specific de bootp */
void print_vendor_specific(const struct vendor_specific_t *vendor_specific, int verbose_level)
{

    //On détecte si c'est du dhcp
    if(vendor_specific->options[53] != 0){
        print_dhcp(vendor_specific, verbose_level);
        return;
    }
    switch (verbose_level)
    {
        case 2:
            printf(" with VENDOR SPECIFIC");
            break;
        case 3:
            printf(" ├ Zone VENDOR SPECIFIC\n");
            for(int i = 0; i < 256; i++){
                if(vendor_specific->options[i] != 0){
                    printf(
                        " | ├ Option %d: %s\n",
                        i,
                        get_hex(
                            vendor_specific->options[i]->value,
                            vendor_specific->options[i]->length
                        )
                    );
                }
            }
            break;
        default:
            break;
    }
}

/* Affiche la zone dhcp */
void print_dhcp(const struct vendor_specific_t *vendor_specific, int verbose_level)
{
    int message_type = vendor_specific->options[53]->value[0];
    char * message_type_str = "Unknown";
    char * ip = "";
    switch (message_type){
        case 1:
            message_type_str = "DHCPDISCOVER";
            break;
        case 2:
            message_type_str = "DHCPOFFER";
            break;
        case 3:
            message_type_str = "DHCPREQUEST";
            if(vendor_specific->options[50] != 0){
                ip = inet_ntoa(*(struct in_addr *)vendor_specific->options[50]->value);
            }
            break;
        case 4:
            message_type_str = "DHCPDECLINE";
            break;
        case 5:
            message_type_str = "DHCPACK";
            if(vendor_specific->options[50] != 0){
                ip = inet_ntoa(*(struct in_addr *)vendor_specific->options[50]->value);
            }
            break;
        case 6:
            message_type_str = "DHCPNAK";
            break;
        case 7:
            message_type_str = "DHCPRELEASE";
            break;
        case 8:
            message_type_str = "DHCPINFORM";
            break;
        default:
            break;
    }

    //On affiche la zone dhcp
    switch(verbose_level){
        case 1:
            if(!strcmp(ip, ""))
                printf(" %s", message_type_str);
            else
                printf(" %s (%s)", message_type_str, ip);
            break;
        case 2:
            if(!strcmp(ip, "")){
                printf("DHCP: %s", message_type_str);
            }else{
                printf("DHCP: %s (%s)", message_type_str, ip);
            }
            break;
        case 3:
            printf(" ├ Zone DHCP\n");
            //Et toutes les options interressantes
            printf(
                " | ├ Message type: %s (%d)\n",
                message_type_str,
                vendor_specific->options[53]->value[0]);

            //Subnet mask
            if(vendor_specific->options[1] != 0){
                printf(
                    " | ├ Subnet mask: %s\n",
                    inet_ntoa(
                        *((struct in_addr *)vendor_specific->options[1]->value)
                    )
                );
            }

            //Router
            if(vendor_specific->options[3] != 0){
                printf(
                    " | ├ Router: %s\n",
                    inet_ntoa(
                        *((struct in_addr *)vendor_specific->options[3]->value)
                    )
                );
            }

            //DNS
            if(vendor_specific->options[6] != 0){
                printf(
                    " | ├ DNS: %s\n",
                    inet_ntoa(
                        *((struct in_addr *)vendor_specific->options[6]->value)
                    )
                );
            }

            //Domain name
            if(vendor_specific->options[15] != 0){
                printf(
                    " | ├ Domain name: %s\n",
                    vendor_specific->options[15]->value
                );
            }

            //Broadcast address
            if(vendor_specific->options[28] != 0){
                printf(
                    " | ├ Broadcast address: %s\n",
                    inet_ntoa(
                        *((struct in_addr *)vendor_specific->options[28]->value)
                    )
                );
            }

            //Requested IP address
            if(vendor_specific->options[50] != 0){
                printf(
                    " | ├ Requested IP address: %s\n",
                    inet_ntoa(
                        *((struct in_addr *)vendor_specific->options[50]->value)
                    )
                );
            }

            //Lease time
            if(vendor_specific->options[51] != 0){
                printf(
                    " | ├ Lease time: %d\n",
                    ntohl(*((uint32_t *)vendor_specific->options[51]->value))
                );
            }

            //Server identifier
            if(vendor_specific->options[54] != 0){
                printf(
                    " | ├ Server identifier: %s\n",
                    inet_ntoa(
                        *((struct in_addr *)vendor_specific->options[54]->value)
                    )
                );
            }

            //Parameter request list
            if(vendor_specific->options[55] != 0){
                printf(" | ├ Parameter request list: ");
                for(int i = 0; i < vendor_specific->options[55]->length; i++){
                    printf("%d ", vendor_specific->options[55]->value[i]);
                }
                printf("\n");
            }

            //Client identifier
            if(vendor_specific->options[61] != 0){
                printf(
                    " | ├ Client identifier: %s\n",
                    get_hex(
                        vendor_specific->options[61]->value,
                        vendor_specific->options[61]->length
                    )
                );
            }

            break;
    }
}