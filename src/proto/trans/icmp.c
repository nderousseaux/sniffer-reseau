// Analyse d'un paquet icmp

#include "../../includes/includes.h"

/* Analyse du paquet icmp */
void compute_icmp(struct pck_t * pck)
{
    //On récupère les données de la couche icmp
    fill_icmp(pck);

    //On saute l'entête icmp
    shift_pck(pck, 8 + 32);

    //On met à jour le log de la couche icmp
    set_icmp_log(pck);
}

/* Remplit la structure icmp */
void fill_icmp(struct pck_t * pck)
{
    //On récupère l'entête icmp
    pck->log->tl->icmp = (struct icmp *) pck->data;
}

/* Met à jour le log de la couche icmp */
void set_icmp_log(struct pck_t * pck)
{
    struct trans_layer_t *tl = pck->log->tl;
    char * log;
    CHECK(log = calloc(2048, sizeof(char)));

    //On met à jour les logs
    switch (tl->icmp->icmp_type)
    {
        case ICMP_ECHOREPLY:
            sprintf(log, "Echo (ping) Reply");
            break;
        case ICMP_ECHO:
            sprintf(log, "Echo (ping) Request");
            break;
        case ICMP_UNREACH:
            sprintf(log, "Destination Unreachable");
            break;
        case ICMP_TIMXCEED:
            sprintf(log, "Time Exceeded");
            break;
        default:
            sprintf(log, UNKNOWN);
            break;
    }

    if (tl->icmp->icmp_type == ICMP_ECHOREPLY || tl->icmp->icmp_type == ICMP_ECHO)
        sprintf(
            log,
            "%s, id=%d, seq=%d",
            log,
            tl->icmp->icmp_id,
            tl->icmp->icmp_seq
        );
    else
        sprintf(
            log,
            "%s, code=%d",
            log,
            tl->icmp->icmp_code
        );
        
    //On met à jour le log verbose 1
    strcpy(pck->log->log, log);
    strcpy(pck->log->proto, PRINT_ICMP_SHRT);
    
    //On met à jour le log verbose 2
    sprintf(tl->log, "%s, %s", PRINT_ICMP, log);

    //On met à jour le log verbose 3
    fill_icmp_log_v3(pck);

    //On libère la mémoire
    free(log);
}


/* Rempli les logs détaillés pour le verbose 3 */
void fill_icmp_log_v3(struct pck_t * pck)
{
    char * type;
    char * code;
    char * checksum;
    char * id;
    char * seq;
    char * data;

    CHECK(type = calloc(2048, sizeof(char)));
    CHECK(code = calloc(2048, sizeof(char)));
    CHECK(checksum = calloc(2048, sizeof(char)));
    CHECK(id = calloc(2048, sizeof(char)));
    CHECK(seq = calloc(2048, sizeof(char)));
    CHECK(data = calloc(2048, sizeof(char)));

    //On récupère les données de la couche icmp
    struct icmp * icmp = pck->log->tl->icmp;

    //On met à jour les logs
    sprintf(type, "Type: %d", icmp->icmp_type);

    switch (icmp->icmp_type)
    {
        case ICMP_ECHOREPLY:
            strcat(type, " (Echo (ping) Reply)");
            break;
        case ICMP_ECHO:
            strcat(type, " (Echo (ping) Request)");
            break;
        case ICMP_UNREACH:
            strcat(type, " (Destination Unreachable)");
            break;
        case ICMP_TIMXCEED:
            strcat(type, " (Time Exceeded)");
            break;
        default:
            break;
    }

    sprintf(code, "Code: %d", icmp->icmp_code);

    sprintf(checksum, "Checksum: 0x%04x", flip_octets(icmp->icmp_cksum));
    sprintf(id, "Identifier: %d (0x%04x)", flip_octets(icmp->icmp_id), flip_octets(icmp->icmp_id));
    sprintf(seq, "Sequence Number: %d (0x%04x)", flip_octets(icmp->icmp_seq), flip_octets(icmp->icmp_seq));

    // Data
    sprintf(data, "Data (32 bytes): ");
    for(int i = 0; i < 32; i++)
        sprintf(data, "%s%c", data, icmp->icmp_data[i]);

    //On ajoute les éléments au log
    add_log_v3(&pck->log->tl->log_v3, type);
    add_log_v3(&pck->log->tl->log_v3, code);
    add_log_v3(&pck->log->tl->log_v3, checksum);
    add_log_v3(&pck->log->tl->log_v3, id);
    add_log_v3(&pck->log->tl->log_v3, seq);
    add_log_v3(&pck->log->tl->log_v3, data);

    //On libère la mémoire
    free(type);
    free(code);
    free(checksum);
    free(id);
    free(seq);
    free(data);
}
