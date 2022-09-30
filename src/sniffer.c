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
            fprintf(stderr, "Protocole de couche réseau inconnu: %d\n", ntohs(eth->ether_type));
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
            fprintf(stderr, "Protocole de couche transport inconnu: %d", iph->ip_p);
            break;
    }
}

/* Traite un paquet ipv6 */
void compute_ipv6(const u_char **pck, int verbose_level)
{
    (void) pck;
    (void) verbose_level; 
    fprintf(stderr, " | Protocole ipv6 non supporté\n");
    //TODO
}

/* Traite un paquet arp */
void compute_arp(const u_char **pck, int verbose_level)
{
    (void) pck;
    (void) verbose_level; 
    fprintf(stderr, " | Protocole arp non supporté\n");
    //TODO
}

/* Traite un paquet icmp */
void compute_icmp(const u_char **pck, int verbose_level)
{
    (void) pck;
    (void) verbose_level; 
    fprintf(stderr, " | Protocole icmp non supporté\n");
    //TODO
}

/* Traite un paquet tcp */
void compute_tcp(const u_char **pck, int verbose_level)
{
    (void) pck;
    (void) verbose_level; 
    fprintf(stderr, " | Protocole tcp non supporté\n");
    //TODO
}

/* Traite un paquet udp */
void compute_udp(const u_char **pck, int verbose_level)
{
    (void) pck;
    (void) verbose_level; 
    fprintf(stderr, " | Protocole udp non supporté\n");
    //TODO
}
