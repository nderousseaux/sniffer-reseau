// Analyse d'un paquet udp

#include "../../includes/includes.h"

/* Analyse du paquet udp */
void compute_udp(struct pck_t * pck)
{
    //On récupère les données de la couche udp
    fill_udp(pck);

    //On saute l'entête udp
    shift_pck(pck, sizeof(struct udphdr));

    //On met à jour le log de la couche udp
    set_udp_log(pck);   
}

/* Remplit la structure udp */
void fill_udp(struct pck_t * pck)
{
    //On récupère l'entête udp
    pck->log->tl->udp = (struct udphdr *) pck->data;
}

/* Met à jour le log de la couche udp */
void set_udp_log(struct pck_t * pck)
{
    struct trans_layer_t *tl = pck->log->tl;
    char * log;
    CHECK(log = calloc(2048, sizeof(char)));

    //On met à jour les logs
    sprintf(
        log,
        "Src Port: %d, Dst Port: %d",
        ntohs(tl->udp->uh_sport),
        ntohs(tl->udp->uh_dport)
    );

    //On met à jour le log verbose 1
    strcpy(pck->log->log, log);
    strcpy(pck->log->proto, PRINT_UDP_SHRT);

    //On met à jour le log verbose 2
    sprintf(tl->log, "%s, %s", PRINT_UDP, log);

    //On met à jour le log verbose 3
    fill_udp_log_v3(pck);

    //On libère la mémoire
    free(log);
}

/* Rempli les logs détaillés pour le verbose 3 */
void fill_udp_log_v3(struct pck_t * pck)
{
    char * src_port;
    char * dst_port;
    char * length;
    char * checksum;

    CHECK(src_port = calloc(2048, sizeof(char)));
    CHECK(dst_port = calloc(2048, sizeof(char)));
    CHECK(length = calloc(2048, sizeof(char)));
    CHECK(checksum = calloc(2048, sizeof(char)));

    //On récupère les données de la couche udp
    struct udphdr * udp = pck->log->tl->udp;

    //On met à jour les logs
    sprintf(src_port, "Source Port: %d", ntohs(udp->uh_sport));
    sprintf(dst_port, "Destination Port: %d", ntohs(udp->uh_dport));
    sprintf(length, "Length: %d", ntohs(udp->uh_ulen));
    sprintf(checksum, "Checksum: 0x%04x", ntohs(udp->uh_sum));

    //On ajoute les éléments au log
    add_log_v3(&pck->log->tl->log_v3, src_port);
    add_log_v3(&pck->log->tl->log_v3, dst_port);
    add_log_v3(&pck->log->tl->log_v3, length);
    add_log_v3(&pck->log->tl->log_v3, checksum);

    //On libère la mémoire
    free(src_port);
    free(dst_port);
    free(length);
    free(checksum);
}