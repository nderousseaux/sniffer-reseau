// Analyse d'un paquet arp

#include "../../includes/includes.h"

/* Analyse du paquet arp */
void compute_arp(struct pck_t * pck)
{
    //On récupère les données de la couche arp
    fill_arp(pck);

    // On saute l'entête arp
    shift_pck(pck, sizeof(struct ether_arp));

    //On met à jour le log de la couche arp
    set_arp_log(pck);
}

/* Remplit la structure arp */
void fill_arp(struct pck_t * pck)
{
    //On récupère l'entête arp
    pck->log->nl->arp = (struct ether_arp *) pck->data;
}

/* Met à jour le log de la couche arp */
void set_arp_log(struct pck_t * pck)
{
    struct net_layer_t *nl = pck->log->nl;
    char * src = ether_to_string((struct ether_addr *) nl->arp->arp_sha);
    char * ip_dst = ip_to_string((struct in_addr *) nl->arp->arp_tpa);
    char * ip_src = ip_to_string((struct in_addr *) nl->arp->arp_spa);

    char * log;
    CHECK(log = calloc(2048, sizeof(char)));

    //On met à jour les logs
    if(ntohs(nl->arp->ea_hdr.ar_op) == ARPOP_REQUEST)
    {
        sprintf(
            log,
            "Who has %s? Tell %s",
            ip_dst,
            ip_src
        );
    }
    else if(ntohs(nl->arp->ea_hdr.ar_op) == ARPOP_REPLY)
    {
        sprintf(
            log,
            "%s is at %s",
            ip_src,
            src
        );
    }
    else
    {
        sprintf(
            log,
            UNKNOWN
        );
    }


    //On met à jour le log verbose 1
    strcpy(pck->log->log, log);
    strcpy(pck->log->proto, PRINT_ARP_SHRT);

    //On met le log verbose 2
    sprintf(nl->log, "%s, %s", PRINT_ARP, log);

    //On met à jour le log verbose 3
    fill_arp_log_v3(pck);

    // On libère la mémoire
    free(src);
    free(ip_dst);
    free(ip_src);
    free(log);
}

/* Rempli les logs détaillés pour le verbose 3 */
void fill_arp_log_v3(struct pck_t * pck)
{
    char * hardware_type;
    char * protocol_type;
    char * hardware_size;
    char * protocol_size;
    char * opcode;
    char * sender_mac;
    char * sender_ip;
    char * target_mac;
    char * target_ip;

    CHECK(hardware_type = calloc(2048, sizeof(char)));
    CHECK(protocol_type = calloc(2048, sizeof(char)));
    CHECK(hardware_size = calloc(2048, sizeof(char)));
    CHECK(protocol_size = calloc(2048, sizeof(char)));
    CHECK(opcode = calloc(2048, sizeof(char)));
    CHECK(sender_mac = calloc(2048, sizeof(char)));
    CHECK(sender_ip = calloc(2048, sizeof(char)));
    CHECK(target_mac = calloc(2048, sizeof(char)));
    CHECK(target_ip = calloc(2048, sizeof(char)));

    //On récupère les données de la couche arp
    struct ether_arp * arp = pck->log->nl->arp;

    //On écrit les logs

    //Hardware type
    sprintf(hardware_type, "Hardware type:");
    if(ntohs(arp->ea_hdr.ar_hrd) == ARPHRD_ETHER)
        sprintf(hardware_type, "%s Ethernet", hardware_type);
    else
        sprintf(hardware_type, "%s Unknown", hardware_type);
    sprintf(hardware_type, "%s (%d)", hardware_type, ntohs(arp->ea_hdr.ar_hrd));

    //Protocol type
    sprintf(protocol_type, "Protocol type:");
    if(ntohs(arp->ea_hdr.ar_pro) == ETHERTYPE_IP)
        sprintf(protocol_type, "%s IPv4", protocol_type);
    else if(ntohs(arp->ea_hdr.ar_pro) == ETHERTYPE_ARP)
        sprintf(protocol_type, "%s ARP", protocol_type);
    else if (ntohs(arp->ea_hdr.ar_pro) == ETHERTYPE_IPV6)
        sprintf(protocol_type, "%s IPv6", protocol_type);
    else
        sprintf(protocol_type, "%s Unknown", protocol_type);
    sprintf(protocol_type, "%s (0x%x)", protocol_type, ntohs(arp->ea_hdr.ar_pro));

    //Hardware size
    sprintf(hardware_size, "Hardware size: %d", arp->ea_hdr.ar_hln);

    //Protocol size
    sprintf(protocol_size, "Protocol size: %d", arp->ea_hdr.ar_pln);

    //Opcode
    sprintf(opcode, "Opcode:");
    if(ntohs(arp->ea_hdr.ar_op) == ARPOP_REQUEST)
        sprintf(opcode, "%s Request", opcode);
    else if(ntohs(arp->ea_hdr.ar_op) == ARPOP_REPLY)
        sprintf(opcode, "%s Reply", opcode);
    else
        sprintf(opcode, "%s Unknown", opcode);
    sprintf(opcode, "%s (%d)", opcode, ntohs(arp->ea_hdr.ar_op));

    //Sender MAC
    sprintf(sender_mac, "Sender MAC address: %s", ether_to_string((struct ether_addr *) arp->arp_sha));

    //Sender IP
    sprintf(sender_ip, "Sender IP address: %s", ip_to_string((struct in_addr *) arp->arp_spa));

    //Target MAC
    sprintf(target_mac, "Target MAC address: %s", ether_to_string((struct ether_addr *) arp->arp_tha));

    //Target IP
    sprintf(target_ip, "Target IP address: %s", ip_to_string((struct in_addr *) arp->arp_tpa));


    //On ajoute les éléments au log
    add_log_v3(&pck->log->nl->log_v3, hardware_type);
    add_log_v3(&pck->log->nl->log_v3, protocol_type);
    add_log_v3(&pck->log->nl->log_v3, hardware_size);
    add_log_v3(&pck->log->nl->log_v3, protocol_size);
    add_log_v3(&pck->log->nl->log_v3, opcode);
    add_log_v3(&pck->log->nl->log_v3, sender_mac);
    add_log_v3(&pck->log->nl->log_v3, sender_ip);
    add_log_v3(&pck->log->nl->log_v3, target_mac);
    add_log_v3(&pck->log->nl->log_v3, target_ip);

    //On libère la mémoire
    free(hardware_type);
    free(protocol_type);
    free(hardware_size);
    free(protocol_size);
    free(opcode);
    free(sender_mac);
    free(sender_ip);
    free(target_mac);
    free(target_ip);
}