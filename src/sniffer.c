#include "./includes/sniffer.h"

/* Ouvre un handler de socket pour la capture de paquets */
pcap_t *init_handler(struct args args)
{
    char error[PCAP_ERRBUF_SIZE];
    pcap_t *handle;

    if(args.interface != NULL)
        handle = pcap_open_live(args.interface, BUFSIZ, 1, 1000, error);
    else
        handle = pcap_open_offline(args.file, error);
        
    
    if(handle == NULL)
    {
        fprintf(stderr, "Impossible d'ouvrir le handler: %s\n", error);
        exit(EXIT_FAILURE);
    }

    return handle;
}

/* Analyse un paquet reçu */
void compute_paquet(struct args *args, const struct pcap_pkthdr *meta, const u_char *pck)
{
    //On affiche le temps
    print_time(meta, args->verbose);

    //On traite le paquet
    compute_ethernet(&pck, args->verbose);
   
    printf("\n");
}

/* Traite un paquet ethernet */
void compute_ethernet(const u_char **pck, int verbose_level)
{
    struct ether_header *eth = (struct ether_header *) *pck;

    //On affiche la couche liaison
    print_ethernet(eth, verbose_level);

    // On saute l'entête ethernet
    *pck += 14;

    //On teste le protocole de la couche réseau
    switch (ntohs(eth->ether_type))
    {
        case ETHERTYPE_IP:
            compute_ipv4(pck, verbose_level);
            break;
        case ETHERTYPE_IPV6:
            compute_ipv6(pck, verbose_level);
            break;
        case ETHERTYPE_ARP:
            compute_arp(pck, verbose_level);
            break;
        default:
            printf("Protocole de couche réseau inconnu: %d\n", ntohs(eth->ether_type));
            printf("Texte brut: %s", *pck);
            break;
    }
}

/* Traite un paquet ipv4 */
void compute_ipv4(const u_char **pck, int verbose_level)
{
    struct ip *iph = (struct ip *) *pck;

    //On affiche la couche réseau
    print_ipv4(iph, verbose_level);

    //On saute l'entête ipv4
    *pck += iph->ip_hl * 4;

    //On teste le protocole de la couche transport
    switch (iph->ip_p)
    {
        case IPPROTO_TCP:
            compute_tcp(pck, verbose_level);
            break;
        case IPPROTO_UDP:
            compute_udp(pck, verbose_level);
            break;
        case IPPROTO_ICMP:
            compute_icmp(pck, verbose_level);
            break;
        default:
            printf("Protocole de couche transport inconnu: %d\n", iph->ip_p);
            printf("Texte brut: %s", *pck);
            break;
    }
}

/* Traite un paquet ipv6 */
void compute_ipv6(const u_char **pck, int verbose_level)
{
    (void) pck;
    (void) verbose_level; 
    printf(" | Protocole ipv6 non supporté\n");
    //TODO
}

/* Traite un paquet arp */
void compute_arp(const u_char **pck, int verbose_level)
{
    (void) pck;
    (void) verbose_level; 
    printf(" | Protocole arp non supporté\n");
    //TODO
}

/* Traite un paquet icmp */
void compute_icmp(const u_char **pck, int verbose_level)
{
    (void) pck;
    (void) verbose_level; 
    printf(" | Protocole icmp non supporté\n");
    //TODO
}

/* Traite un paquet tcp */
void compute_tcp(const u_char **pck, int verbose_level)
{
    (void) pck;
    (void) verbose_level; 
    printf(" | Protocole tcp non supporté\n");
    //TODO
}

/* Traite un paquet udp */
void compute_udp(const u_char **pck, int verbose_level)
{
    struct udphdr *udph = (struct udphdr *) *pck;

    //On affiche la couche transport
    print_udp(udph, verbose_level);

    //On saute l'entête udp
    *pck += 8;

    //On teste le protocole de la couche application
    switch (ntohs(udph->uh_dport))
    {
        case 53:
            compute_dns(pck, verbose_level);
            break;
        case 67:
            compute_bootp(pck, verbose_level);
            break;
        case 68:
            compute_bootp(pck, verbose_level);
            break;
        case 80:
            compute_http(pck, verbose_level);
            break;
        case 443:
            compute_https(pck, verbose_level);
            break;
        default:
            printf("Protocole de couche application inconnu: %d\n", ntohs(udph->uh_dport));
            printf("Texte brut: %s\n", *pck);
            break;
    }
}

/* Traite un paquet dns */
void compute_dns(const u_char **pck, int verbose_level)
{
    (void) pck;
    (void) verbose_level; 
    printf(" | Protocole dns non supporté\n");
    //TODO
}

/* Traite un paquet bootp */
void compute_bootp(const u_char **pck, int verbose_level)
{
    struct bootp *bootph = (struct bootp *) *pck;

    //On affiche la couche application
    print_bootp(bootph, verbose_level);

    //On saute l'entête bootp
    *pck += 236;

    //On teste le protocole de la couche application
    //TODO
}

/* Traite un paquet http */
void compute_http(const u_char **pck, int verbose_level)
{
    (void) pck;
    (void) verbose_level; 
    printf(" | Protocole http non supporté\n");
    //TODO
}

/* Traite un paquet https */
void compute_https(const u_char **pck, int verbose_level)
{
    (void) pck;
    (void) verbose_level; 
    printf(" | Protocole https non supporté\n");
    //TODO
}

