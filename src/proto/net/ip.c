// Analyse d'un paquet ip

#include "../../includes/includes.h"

/* Analyse du paquet ip */
void compute_ip(struct pck_t * pck)
{
    //On récupère les données de la couche ip
    fill_ip(pck);

    //On saute l'entête ip
    shift_pck(pck, sizeof(struct ip));

    //On met à jour le log de la couche ip
    set_ip_log(pck);
}

/* Remplit la structure ip */
void fill_ip(struct pck_t * pck)
{
    //On récupère l'entête ip
    pck->log->nl->ip = (struct ip *) pck->data;
}

/* Met à jour le log de la couche ip */
void set_ip_log(struct pck_t * pck)
{
    struct net_layer_t *nl = pck->log->nl;
    char * src = ip_to_string(&nl->ip->ip_src);
    char * dst = ip_to_string(&nl->ip->ip_dst);
    char * log;
    CHECK(log = calloc(2048, sizeof(char)));

    //On met à jour les logs
    sprintf(
        log,
        "%s > %s",
        src,
        dst
    );

    //On met à jour le log verbose 1
    strcpy(pck->log->log, log);
    strcpy(pck->log->proto, PRINT_IP_SHRT);
    strcpy(pck->log->dst, dst);
    strcpy(pck->log->src, src);

    //On met à jour le log verbose 2
    sprintf(nl->log, "%s, %s", PRINT_IP, log);

    //On met à jour le log verbose 3
    fill_ip_log_v3(pck);

    //On libère la mémoire
    free(log);
    free(src);
    free(dst);
}

/* Rempli les logs détaillés pour le verbose 3 */
void fill_ip_log_v3(struct pck_t * pck)
{
    char * version;
    char * ihl;
    char * len;
    char * id;
    char * frag_off;
    char * ttl;
    char * protocol;
    char * check;
    char * src;
    char * dst;
    
    CHECK(version = calloc(2048, sizeof(char)));
    CHECK(ihl = calloc(2048, sizeof(char)));
    CHECK(len = calloc(2048, sizeof(char)));
    CHECK(id = calloc(2048, sizeof(char)));
    CHECK(frag_off = calloc(2048, sizeof(char)));
    CHECK(ttl = calloc(2048, sizeof(char)));
    CHECK(protocol = calloc(2048, sizeof(char)));
    CHECK(check = calloc(2048, sizeof(char)));
    CHECK(src = calloc(2048, sizeof(char)));
    CHECK(dst = calloc(2048, sizeof(char)));    

    //On récupère les données de la couche ip
    struct ip * ip = pck->log->nl->ip;

    //On met à jour les logs

    //Version
    sprintf(version, "Version: %d", ip->ip_v);

    //IHL
    sprintf(ihl, "Header Length: %d bytes (%d)", ip->ip_hl*4, ip->ip_hl);

    //Len 
    sprintf(len, "Total Length: %d", ip->ip_len>>8);

    //ID
    sprintf(id, "Identification: 0x%x (%d)", flip_octets(ip->ip_id), flip_octets(ip->ip_id));

    //Frag off
    sprintf(frag_off, "Don't fragment: %s", (ip->ip_off & IP_DF) ? "yes" : "no");

    //TTL
    sprintf(ttl, "Time to live: %d", ip->ip_ttl);

    //Protocol
    sprintf(protocol, "Protocol:");
    if(ip->ip_p == IPPROTO_TCP)
        strcat(protocol, " TCP");
    else if(ip->ip_p == IPPROTO_UDP)
        strcat(protocol, " UDP");
    else if(ip->ip_p == IPPROTO_ICMP)
        strcat(protocol, " ICMP");
    else
        strcat(protocol, " Unknown");
    sprintf(protocol, "%s (%d)", protocol, ip->ip_p);

    //Check
    sprintf(check, "Header Checksum: 0x%x", flip_octets(ip->ip_sum));

    //Src
    sprintf(src, "Source Address: %s", ip_to_string(&ip->ip_src));

    //Dst
    sprintf(dst, "Destination Address: %s", ip_to_string(&ip->ip_dst));

    //On ajoute les éléments au log
    add_log_v3(&pck->log->nl->log_v3, version);
    add_log_v3(&pck->log->nl->log_v3, ihl);
    add_log_v3(&pck->log->nl->log_v3, len);
    add_log_v3(&pck->log->nl->log_v3, id);
    add_log_v3(&pck->log->nl->log_v3, frag_off);
    add_log_v3(&pck->log->nl->log_v3, ttl);
    add_log_v3(&pck->log->nl->log_v3, protocol);
    add_log_v3(&pck->log->nl->log_v3, check);
    add_log_v3(&pck->log->nl->log_v3, src);
    add_log_v3(&pck->log->nl->log_v3, dst);

    //On libère la mémoire
    free(version);
    free(ihl);
    free(len);
    free(id);
    free(frag_off);
    free(ttl);
    free(protocol);
    free(check);
    free(src);
    free(dst);
}