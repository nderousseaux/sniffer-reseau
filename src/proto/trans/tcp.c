// Analyse d'un paquet tcp

#include "../../includes/includes.h"

/* Analyse du paquet tcp */
void compute_tcp(struct pck_t * pck)
{
    //On vérifie que le paquet est bien un paquet tcp
    fill_tcp(pck);

    //On saute le header tcp
    shift_pck(pck, pck->log->tl->tcp->doff * 4);

    //On met à jour le log de la couche tcp
    set_tcp_log(pck);
}

/* Remplit la structure tcp */
void fill_tcp(struct pck_t * pck)
{
    pck->log->tl->tcp = (struct tcphdr *) pck->data;

}

/* Met à jour le log de la couche tcp */
void set_tcp_log(struct pck_t * pck)
{
    struct trans_layer_t *tl = pck->log->tl;
    char * drapeaux;
    char * log;
    CHECK(log = calloc(2048, sizeof(char)));

    //On met à jour les logs
    CHECK(drapeaux = calloc(20, sizeof(char)));
    if (tl->tcp->syn)
        strcat(drapeaux, "SYN ");
    if (tl->tcp->ack)
        strcat(drapeaux, "ACK ");
    if (tl->tcp->fin)
        strcat(drapeaux, "FIN ");
    if (tl->tcp->rst)
        strcat(drapeaux, "RST ");
    if (tl->tcp->psh)
        strcat(drapeaux, "PSH ");
    if (tl->tcp->urg)
        strcat(drapeaux, "URG ");
    //On supprime le dernier espace
    drapeaux[strlen(drapeaux) - 1] = '\0';

    sprintf(
        log,
        "%d > %d [%s], Seq:0x%x, Ack:%x, Len:%x",
        ntohs(tl->tcp->source),
        ntohs(tl->tcp->dest),
        drapeaux,
        tl->tcp->seq,
        tl->tcp->ack_seq,
        tl->tcp->doff * 4
    );
    
    //On met à jour le log verbose 1
    strcpy(pck->log->log, log);
    strcpy(pck->log->proto, PRINT_TCP_SHORT);

    //On met à jour le log verbose 2
    sprintf(tl->log, "%s, %s", PRINT_TCP, log);

    //On met à jour le log verbose 3
    fill_tcp_log_v3(pck);

    free(drapeaux);
    free(log);
}

/* Rempli les logs détaillés pour le verbose 3 */
void fill_tcp_log_v3(struct pck_t * pck)
{
    char * src_port;
    char * dst_port;
    char * seq;
    char * ack;
    char * flags;
    char * win;
    char * checksum;
    char * urg;

    CHECK(src_port = calloc(2048, sizeof(char)));
    CHECK(dst_port = calloc(2048, sizeof(char)));
    CHECK(seq = calloc(2048, sizeof(char)));
    CHECK(ack = calloc(2048, sizeof(char)));
    CHECK(flags = calloc(2048, sizeof(char)));
    CHECK(win = calloc(2048, sizeof(char)));
    CHECK(checksum = calloc(2048, sizeof(char)));
    CHECK(urg = calloc(2048, sizeof(char)));

    //On récupère les données tcp
    struct tcphdr * tcp = pck->log->tl->tcp;

    //On met à jour les logs
    sprintf(src_port, "Source port: %d", ntohs(tcp->source));
    sprintf(dst_port, "Destination port: %d", ntohs(tcp->dest));
    sprintf(seq, "Sequence number: %d (0x%08x)", tcp->seq, tcp->seq);
    sprintf(ack, "Acknowledgment number: %d (0x%08x)", tcp->ack_seq, tcp->ack_seq);

    sprintf(flags, "Flags: [");
    if (tcp->syn)
        strcat(flags, "SYN ");
    if (tcp->ack)
        strcat(flags, "ACK ");
    if (tcp->fin)
        strcat(flags, "FIN ");
    if (tcp->rst)
        strcat(flags, "RST ");
    if (tcp->psh)
        strcat(flags, "PSH ");
    if (tcp->urg)
        strcat(flags, "URG ");
    
    //On supprime le dernier espace
    flags[strlen(flags) - 1] = '\0';
    strcat(flags, "]");
    // sprintf(flags, "Flags: [%s]", flags);
    sprintf(win, "Window size: %d", ntohs(tcp->window));
    sprintf(checksum, "Checksum: 0x%04x", tcp->check);
    sprintf(urg, "Urgent pointer: %d", tcp->urg_ptr);
    
    //On ajoute les éléments au log
    add_log_v3(&pck->log->tl->log_v3, src_port);
    add_log_v3(&pck->log->tl->log_v3, dst_port);
    add_log_v3(&pck->log->tl->log_v3, seq);
    add_log_v3(&pck->log->tl->log_v3, ack);
    add_log_v3(&pck->log->tl->log_v3, flags);
    add_log_v3(&pck->log->tl->log_v3, win);
    add_log_v3(&pck->log->tl->log_v3, checksum);
    add_log_v3(&pck->log->tl->log_v3, urg);

    //On libère la mémoire
    free(src_port);
    free(dst_port);
    free(seq);
    free(ack);
    free(flags);
    free(win);
    free(checksum);
    free(urg);

}