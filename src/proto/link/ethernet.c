// Analyse d'un paquet ethernet
#include "../../includes/includes.h"

/* Analyse du paquet ethernet */
void compute_ether(struct pck_t * pck)
{
    //On récupère les données de la couche ethernet
    fill_ether(pck);

    // On saute l'entête ethernet
    shift_pck(pck, 14);

    //On met à jour le log de la couche ethernet
    set_ether_log(pck);
}

/* Remplit la structure ethernet */
void fill_ether(struct pck_t * pck)
{ 
    //On récupère l'entête ethernet
    pck->log->ll->eth = (struct ether_header *) pck->data;
}

/* Met à jour le log de la couche ethernet */
void set_ether_log(struct pck_t * pck)
{
    struct link_layer_t *ll = pck->log->ll;
    char * src = ether_to_string((struct ether_addr *) ll->eth->ether_shost);
    char * dst = ether_to_string((struct ether_addr *) ll->eth->ether_dhost);
    char * log;
    CHECK(log = calloc(2048, sizeof(char)));

    //On met à jour les logs
    sprintf(
        log,
        "Src: %s, Dst: %s",
        src,
        dst
    );

    //On met à jour le log de la couche liason
    sprintf(ll->log, "%s, %s", PRINT_ETH, log);

    //On met à jour le log de top niveau
    //On peut déterminer l'addresse src, et dst et le protocole
    strcpy(pck->log->src, src);
    strcpy(pck->log->dst, dst);
    strcpy(pck->log->proto, PRINT_ETH_SHRT);
    strcpy(pck->log->log, log);

    //On remplit les données pour le verbose 3
    fill_ether_log_v3(pck);

    // On libère la mémoire
    free(src);
    free(dst);
    free(log);

}

/* Rempli les logs détaillés pour le verbose 3 */
void fill_ether_log_v3(struct pck_t * pck)
{
    char * dst;
    char * src;
    char * type;
    CHECK(dst = calloc(2048, sizeof(char)));
    CHECK(src = calloc(2048, sizeof(char)));
    CHECK(type = calloc(2048, sizeof(char)));

    //On récupère les données de la couche ethernet
    struct link_layer_t *ll = pck->log->ll;
    sprintf(src, "Destination: %s", ether_to_string((struct ether_addr *) ll->eth->ether_shost));
    sprintf(dst, "Source: %s", ether_to_string((struct ether_addr *) ll->eth->ether_dhost));
    


    if (ntohs(ll->eth->ether_type) == ETHERTYPE_IP)
        sprintf(type, "Type: %s (0x%x)", "IPv4", ntohs(ll->eth->ether_type));
    else if (ntohs(ll->eth->ether_type) == ETHERTYPE_IPV6)
        sprintf(type, "Type: %s (0x%x)", "IPv6", ntohs(ll->eth->ether_type));
    else if (ntohs(ll->eth->ether_type) == ETHERTYPE_ARP)
        sprintf(type, "Type: %s (0x%x)", "ARP", ntohs(ll->eth->ether_type));
    else
        sprintf(type, "Type: %s (0x%x)", UNKNOWN, ntohs(ll->eth->ether_type));

    //On ajoute les éléments à log v3
    add_log_v3(&pck->log->ll->log_v3, src);
    add_log_v3(&pck->log->ll->log_v3, dst);
    add_log_v3(&pck->log->ll->log_v3, type);
    
}