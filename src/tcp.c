// Gère un paquet tcp
#include "includes/includes.h"


/* Traite un paquet tcp */
void compute_tcp(const u_char **pck)
{
    struct tcphdr *tcph = (struct tcphdr *) *pck;

    //On définit la couche transport
    set_printer_tcp(tcph);

    //On saute l'entête tcp
    incr_pck(pck,tcph->doff * 4); 

    //Si le paquet est vide, on sort
    if(get_remaining_bytes() == 0){
        get_paquet_info()->eth->ipv4->tcp->type = PURE_TCP;
        return;
    }
        

    //On teste le protocole de la couche application
    switch (ntohs(tcph->dest))
    {
        case 23:
            get_paquet_info()->eth->ipv4->tcp->type = TELNET;
            compute_telnet(pck);
            break;
        case 80:
            //TODO: compute_http(pck);
            break;
        case 443:
            //TODO: compute_https(pck);
            break;
        default:
            break;
    }
    switch (ntohs(tcph->source))
    {
        case 23:
            get_paquet_info()->eth->ipv4->tcp->type = TELNET;
            compute_telnet(pck);
            break;
        case 80:
            //TODO: compute_http(pck);
            break;
        case 443:
            //TODO: compute_https(pck);
            break;
        default:
            break;
    }

}

/* Définit les variables du printer pour tcp */
void set_printer_tcp(struct tcphdr *tcp)
{
    //On définit les variables
    int src_port;
    int dst_port;
    char * drapeaux;
    struct tcp_info_2 *tcp_info;
    struct paquet_info *paquet_info; 

    //On définit les variables src et dst
    src_port = ntohs(tcp->source);
    dst_port = ntohs(tcp->dest);

    //On définit la chaine des drapeaux
    CHECK(drapeaux = malloc(10));
    if (tcp->syn)
        strcat(drapeaux, "SYN ");
    if (tcp->ack)
        strcat(drapeaux, "ACK ");
    if (tcp->fin)
        strcat(drapeaux, "FIN ");
    if (tcp->rst)
        strcat(drapeaux, "RST ");
    if (tcp->psh)
        strcat(drapeaux, "PSH ");
    if (tcp->urg)
        strcat(drapeaux, "URG ");
    //On supprime le dernier espace
    drapeaux[strlen(drapeaux) - 1] = '\0';
    
    //On remplit tcp_info
    CHECK(tcp_info = malloc(sizeof(struct tcp_info)));
    tcp_info->tcp = tcp;
    CHECK(tcp_info->infos = malloc(255));
    sprintf(
        tcp_info->infos,
        "Transmission Control Protocol, Src Port: %d, Dst Port: %d, Seq: 0x%x, Ack: 0x%x, Len: 0x%x, Flags: %s",
        src_port,
        dst_port,
        ntohl(tcp->seq),
        ntohl(tcp->ack_seq),
        tcp->doff * 4,
        drapeaux
    );

    //On remplit paquet_info
    paquet_info = get_paquet_info();
    paquet_info->eth->ipv4->tcp = tcp_info;
    
    //Seq ack, win et len en hexa
    sprintf(
        paquet_info->infos,
        "%d -> %d [%s] Seq: 0x%x, Ack: 0x%x, Win: 0x%x, Len: 0x%x",
        src_port,
        dst_port,
        drapeaux,
        ntohl(tcp->seq),
        ntohl(tcp->ack_seq),
        ntohs(tcp->window),
        tcp->doff * 4
    );
}

/* On libère la mémoire */
void free_tcp_info(struct tcp_info_2 *tcp_info)
{
    free(tcp_info->infos);
    if (tcp_info->type == TELNET)
    {
        free_telnet_info(tcp_info->telnet);
    }

    free(tcp_info);
}