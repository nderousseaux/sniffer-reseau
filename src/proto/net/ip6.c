// Analyse d'un paquet ip6

#include "../../includes/includes.h"

/* Analyse du paquet ip6 */
void compute_ip6(struct pck_t * pck)
{
    //On récupère les données de la couche ip6
    fill_ip6(pck);

    //On saute l'entête ip6
    shift_pck(pck, sizeof(struct ip6_hdr));

    //On met à jour le log de la couche ip6
    set_ip6_log(pck);
}

/* Remplit la structure ip6 */
void fill_ip6(struct pck_t * pck)
{
    //On récupère l'entête ip6
    pck->log->nl->ip6 = (struct ip6_hdr *) pck->data;
}

/* Met à jour le log de la couche ip6 */
void set_ip6_log(struct pck_t * pck)
{
    struct net_layer_t *nl = pck->log->nl;
    char * src = ip6_to_string(&nl->ip6->ip6_src);
    char * dst = ip6_to_string(&nl->ip6->ip6_dst);
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
    strcpy(pck->log->proto, PRINT_IP6_SHRT);
    strcpy(pck->log->dst, dst);
    strcpy(pck->log->src, src);

    //On met à jour le log verbose 2
    sprintf(nl->log, "%s, %s", PRINT_IP6, log);

    //On met à jour le log verbose 3
    fill_ip6_log_v3(pck);

    //On libère la mémoire
    free(log);
    free(src);
    free(dst);
}

/* Rempli les logs détaillés pour le verbose 3 */
void fill_ip6_log_v3(struct pck_t * pck)
{
    char * version;
    char * traffic_class;
    char * flow_label;
    char * payload_length;
    char * next_header;
    char * hop_limit;
    char * src;
    char * dst;

    CHECK(version = calloc(2048, sizeof(char)));
    CHECK(traffic_class = calloc(2048, sizeof(char)));
    CHECK(flow_label = calloc(2048, sizeof(char)));
    CHECK(payload_length = calloc(2048, sizeof(char)));
    CHECK(next_header = calloc(2048, sizeof(char)));
    CHECK(hop_limit = calloc(2048, sizeof(char)));
    CHECK(src = calloc(2048, sizeof(char)));
    CHECK(dst = calloc(2048, sizeof(char)));

    //On récupère les données de la couche ip6
    struct ip6_hdr * ip6 = pck->log->nl->ip6;

    //On met à jour les logs

    //Version
    sprintf(version, "Version: %d", ip6->ip6_vfc >> 4);

    //Traffic class
    sprintf(traffic_class, "Traffic class: 0x%x", ip6->ip6_flow >> 20);

    //Flow label
    sprintf(flow_label, "Flow label: 0x%x", ip6->ip6_flow >> 8);

    //Payload length
    sprintf(payload_length, "Payload length: %d", ntohs(ip6->ip6_plen));

    //Next header
    sprintf(next_header, "Next header:");
    if(ip6->ip6_nxt == IPPROTO_TCP)
        sprintf(next_header, "%s TCP", next_header);
    else if(ip6->ip6_nxt == IPPROTO_UDP)
        sprintf(next_header, "%s UDP", next_header);
    else
        sprintf(next_header, "%s Unknown", next_header);
    sprintf(next_header, "%s (0x%x)", next_header, ip6->ip6_nxt);

    //Hop limit
    sprintf(hop_limit, "Hop limit: %d", ip6->ip6_hlim);

    //Source
    sprintf(src, "Source Address: %s", ip6_to_string(&ip6->ip6_src));

    //Destination
    sprintf(dst, "Destination Address: %s", ip6_to_string(&ip6->ip6_dst));

    //On ajoute les éléments au log
    add_log_v3(&pck->log->nl->log_v3, version);
    add_log_v3(&pck->log->nl->log_v3, traffic_class);
    add_log_v3(&pck->log->nl->log_v3, flow_label);
    add_log_v3(&pck->log->nl->log_v3, payload_length);
    add_log_v3(&pck->log->nl->log_v3, next_header);
    add_log_v3(&pck->log->nl->log_v3, hop_limit);
    add_log_v3(&pck->log->nl->log_v3, src);
    add_log_v3(&pck->log->nl->log_v3, dst);
    
    //On libère la mémoire
    free(version);
    free(traffic_class);
    free(flow_label);
    free(payload_length);
    free(next_header);
    free(hop_limit);
    free(src);
    free(dst);
}