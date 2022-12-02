#include "./includes/sniffer.h"

const u_char *packet;

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
    packet = pck;

    //On affiche le header
    print_header(meta, args->verbose);

    //On traite le paquet
    compute_ethernet(&pck);
    
    printf("\n");
}

/* Traite un paquet ethernet */
void compute_ethernet(const u_char **pck)
{
    struct ether_header *eth = (struct ether_header *) *pck;

    //On affiche la couche liaison
    print_ethernet(eth);

    // On saute l'entête ethernet
    *pck += 14;

    //On teste le protocole de la couche réseau
    switch (ntohs(eth->ether_type))
    {
        case ETHERTYPE_IP:
            compute_ipv4(pck);
            break;
        case ETHERTYPE_IPV6:
            compute_ipv6(pck);
            break;
        case ETHERTYPE_ARP:
            compute_arp(pck);
            break;
        default:
            print_protocol();
            break;
    }
}

/* Traite un paquet arp */
void compute_arp(const u_char **pck)
{
    struct ether_arp *arp = (struct ether_arp *) *pck;

    //On affiche la couche réseau
    print_arp(arp);
}

/* Traite un paquet ipv4 */
void compute_ipv4(const u_char **pck)
{
    struct ip *iph = (struct ip *) *pck;

    //On affiche la couche réseau
    print_ipv4(iph);

    //On saute l'entête ipv4
    *pck += iph->ip_hl * 4;

    //On teste le protocole de la couche transport
    switch (iph->ip_p)
    {
        case IPPROTO_TCP:
            // compute_tcp(pck);
            break;
        case IPPROTO_UDP:
            compute_udp(pck);
            break;
        case IPPROTO_ICMP:
            compute_icmp(pck);
            break;
        default:
            print_protocol();
            break;
    }
}

/* Traite un paquet ipv6 */
void compute_ipv6(const u_char **pck)
{
    (void) pck;
     
    printf(" | Protocole ipv6 non supporté\n");
    //TODO
}

/* Traite un paquet icmp */
void compute_icmp(const u_char **pck){
    struct icmp *icmp = (struct icmp *) *pck;

    //On affiche la couche transport
    print_icmp(icmp);
}

/* Traite un paquet tcp */
void compute_tcp(const u_char **pck)
{
    (void) pck;
     
    printf(" | Protocole tcp non supporté\n");
    //TODO
}

/* Traite un paquet udp */
void compute_udp(const u_char **pck)
{
    struct udphdr *udph = (struct udphdr *) *pck;

    //On affiche la couche transport
    print_udp(udph);

    //On saute l'entête udp
    *pck += sizeof(struct udphdr);

    //On teste le protocole de la couche application
    switch (ntohs(udph->dest))
    {
        case 53:
            compute_dns(pck);
            break;
        case 67:
            compute_bootp(pck);
            break;
        case 68:
            compute_bootp(pck);
            break;
        default:
            if (ntohs(udph->source) == 53)
                compute_dns(pck);
            else
                print_protocol();
            break;
    }
}

/* Traite un paquet dns */
void compute_dns(const u_char **pck)
{
    struct dns_t *dns = malloc(sizeof(struct dns_t));

    //On récupère l'en-tête dns
    dns->header = (struct dns_header_t *) *pck;
    *pck += sizeof(struct dns_header_t);

    // On stocke chaque query
    dns->queries = malloc(sizeof(struct dns_query_t)*dns->header->q_count);
    for(int i = 0; i < ntohs(dns->header->q_count); i++){
        read_dns_query(&dns->queries[i], pck, &packet);
    }
    //On stocke chaque réponse
    dns->answers = malloc(sizeof(struct dns_answer_t)*dns->header->ans_count);
    for(int i = 0; i < ntohs(dns->header->ans_count); i++){
        read_dns_answer(&dns->answers[i], pck, &packet);
    }
    // //On stocke chaque autorité
    // dns->authorities = malloc(sizeof(struct dns_answer_t)*dns->header->auth_count);
    // for(int i = 0; i < ntohs(dns->header->auth_count); i++){
    //     read_dns_answer(&dns->authorities[i], pck, &packet);
    // }
    // //On stocke chaque additionnel
    // dns->additionals = malloc(sizeof(struct dns_answer_t)*dns->header->add_count);
    // for(int i = 0; i < ntohs(dns->header->add_count); i++){
    //     read_dns_answer(&dns->additionals[i], pck, &packet);
    // }

    //On affiche la couche application
    print_dns(dns);
}

/* Traite un paquet bootp */
void compute_bootp(const u_char **pck)
{
    struct bootp *bootph = (struct bootp *) *pck;

    //On affiche la couche application
    print_bootp(bootph);

    //On saute l'entête bootp
    *pck += 236;

    //Si on détecte le magic cookie, on enregistre la zone vendor specific
    if(**pck == 99 && *(*pck + 1) == 130 && *(*pck + 2) == 83 && *(*pck + 3) == 99)
    {
        *pck += 4;
        compute_vendor_specific(pck);        
    }
    else
        print_protocol();
}

/* Traite la zone vendor specific de bootp (vaut pour le dhcp) */
void compute_vendor_specific(const u_char **pck)
{
    //Pour chaque option, on l'enregistre dans la strucutre
    struct vendor_specific_t vs;
    vs.options = malloc(sizeof(struct vendor_specific_option_t)*255);

    
    (void) pck;
    while(**pck != 0xff)
    {
        int option = **pck;
        *pck += 1;
        vs.options[option] = malloc(sizeof(struct vendor_specific_option_t));
        vs.options[option]->length = **pck;
        *pck += 1;
        vs.options[option]->value = malloc(vs.options[option]->length);
        memcpy(vs.options[option]->value, *pck, vs.options[option]->length);
        *pck += vs.options[option]->length;
    }

    //On affiche la zone vendor specific
    print_vendor_specific(&vs);
}

/* Traite un paquet http */
void compute_http(const u_char **pck)
{
    (void) pck;
     
    printf(" | Protocole http non supporté\n");
    //TODO
}

/* Traite un paquet https */
void compute_https(const u_char **pck)
{
    (void) pck;
     
    printf(" | Protocole https non supporté\n");
    //TODO
}

