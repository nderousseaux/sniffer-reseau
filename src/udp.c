// Gère un paquet udp

#include "includes/includes.h"

/* Traite un paquet udp */
void compute_udp(const u_char **pck){
    struct udphdr *udph = (struct udphdr *) *pck;

    //On définit la couche transport
    set_printer_udp(udph);

    //On saute l'entête udp
    incr_pck(pck, sizeof(struct udphdr)); 

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
            break;
    }
}

/* Définit les variables du printer pour udp */
void set_printer_udp(struct udphdr *udp){
    //On définit les variables
    int src_port;
    int dst_port;
    char * type;
    struct udp_info *udp_info;
    struct paquet_info *paquet_info;

    //On définit les variables src et dst
    src_port = ntohs(udp->source);
    dst_port = ntohs(udp->dest);

    //On définit le type
    CHECK(type = malloc(10));
    switch(dst_port)
    {
        case 53:
            strcpy(type, "DNS");
            break;
        case 67:
            strcpy(type, "BOOTP");
            break;
        case 68:
            strcpy(type, "BOOTP");
            break;
        default:
            if (src_port == 53)
                strcpy(type, "DNS");
            else
                strcpy(type, "UDP");
            break;
    }

    //On remplit udp_info
    CHECK(udp_info = malloc(sizeof(struct udp_info)));
    udp_info->udp = udp;
    CHECK(udp_info->infos = malloc(255));
    sprintf(
        udp_info->infos,
        "User Datagram Protocol, Src Port: %d, Dst Port: %d",
        src_port,
        dst_port
    );

    //On remplit paquet_info
    paquet_info = get_paquet_info();
    paquet_info->eth->ipv4->udp = udp_info;
    strcpy(paquet_info->protocol, type);
    sprintf(
        paquet_info->infos,
        "UDP, Src Port: %d, Dst Port: %d",
        src_port,
        dst_port
    );
    
    free(type);
}

/* On libère la mémoire */
void free_udp_info(struct udp_info *udp){
    // free(udp->infos);
    // if(udp->dns != NULL)
    //     free_dns_info(udp->dns);
    // if(udp->bootp != NULL)
    //     free_bootp_info(udp->bootp);
    free(udp);
}
