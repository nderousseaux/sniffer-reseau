// Gère un paquet tcp
#include "includes/includes.h"


/* Traite un paquet tcp */
void compute_tcp(const u_char **pck)
{
    struct tcphdr *tcph = (struct tcphdr *) *pck;
    //On définit la couche transport
    set_printer_tcp(tcph);
    get_paquet_info()->eth->ipv4->tcp->type = PURE_TCP;

    //On saute l'entête tcp
    incr_pck(pck,tcph->doff * 4); 

    //Si le paquet est vide, on sort
    if(
        get_remaining_bytes() == 0 ||
        (
            !tcph->psh &&
            ntohs(tcph->source) != 80
        )
    ){
        return;
    }
        

    //On teste le protocole de la couche application
    switch (ntohs(tcph->dest))
    {
        case 21:
            get_paquet_info()->eth->ipv4->tcp->type = FTP;
            compute_ftp(pck, 1);
            break;
        case 23:
            get_paquet_info()->eth->ipv4->tcp->type = TELNET;
            compute_telnet(pck);
            break;
        case 25:
            get_paquet_info()->eth->ipv4->tcp->type = SMTP;
            compute_smtp(pck, 1);
            break;
        case 80:
            get_paquet_info()->eth->ipv4->tcp->type = HTTP;
            compute_http(pck, 1);
            break;
        case 110:
            get_paquet_info()->eth->ipv4->tcp->type = POP;
            compute_pop(pck, 1);
            break;
        case 143:
            get_paquet_info()->eth->ipv4->tcp->type = IMAP;
            compute_imap(pck, 1);
            break;
        case 443:
            //TODO: compute_https(pck);
            break;
        default:
            break;
    }
    switch (ntohs(tcph->source))
    {
        case 21:
            get_paquet_info()->eth->ipv4->tcp->type = FTP;
            compute_ftp(pck, 0);
            break;
        case 23:
            get_paquet_info()->eth->ipv4->tcp->type = TELNET;
            compute_telnet(pck);
            break;
        case 25:
            get_paquet_info()->eth->ipv4->tcp->type = SMTP;
            compute_smtp(pck, 0);
            break;
        case 80:
            get_paquet_info()->eth->ipv4->tcp->type = HTTP;
            compute_http(pck, 0);
            break;
        case 110:
            get_paquet_info()->eth->ipv4->tcp->type = POP;
            compute_pop(pck, 0);
            break;
        case 143:
            get_paquet_info()->eth->ipv4->tcp->type = IMAP;
            compute_imap(pck, 0);
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
    CHECK(drapeaux = calloc(sizeof(char),10));
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
    CHECK(tcp_info = calloc(sizeof(struct tcp_info), 1));
    tcp_info->tcp = tcp;
    CHECK(tcp_info->infos = calloc(sizeof(char), 255));
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
    tcp_info->telnet = NULL;
    tcp_info->ftp = NULL;
    tcp_info->pop = NULL;
    tcp_info->imap = NULL;
    tcp_info->smtp = NULL;
    tcp_info->http = NULL;

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
    if (tcp_info->type == TELNET && tcp_info->telnet != NULL)
    {
        free_telnet_info(tcp_info->telnet);
    }
    else if (tcp_info->type == FTP)
    {
        free_ftp_info(tcp_info->ftp);
    }
    else if (tcp_info->type == POP && tcp_info->pop != NULL)
    {
        free_pop_logs(tcp_info->pop);
    }
    else if (tcp_info->type == IMAP && tcp_info->imap != NULL)
    {
        free_imap_logs(tcp_info->imap);
    }
    else if (tcp_info->type == SMTP && tcp_info->smtp != NULL)
    {
        free_smtp_logs(tcp_info->smtp);
    }
    else if (tcp_info->type == HTTP && tcp_info->http != NULL)
    {
        free_http_logs(tcp_info->http);
    }
    free(tcp_info);
}