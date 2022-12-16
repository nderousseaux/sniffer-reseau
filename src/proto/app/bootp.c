// Analyse d'un paquet bootp

#include "../../includes/includes.h"

/* Analyse du paquet bootp */
void compute_bootp(struct pck_t * pck)
{
    //On vérifie que le paquet est bien un paquet bootp
    fill_bootp(pck);

    //On met à jour le log de la couche bootp
    set_bootp_log(pck);
}

/* Remplit la structure bootp */
void fill_bootp(struct pck_t * pck)
{
    pck->log->al->bootp = init_bootp();
    pck->log->al->bootp->header= (struct bootp_header_t *) pck->data;
    shift_pck(pck, 236);

    //Si on détecte le magic cookie, on registre la zone vendor specific
    if(*pck->data == 99 && *(pck->data + 1) == 130 && *(pck->data + 2) == 83 && *(pck->data + 3) == 99)
    {
        shift_pck(pck, 4);
        //Pour chaque option, on l'enregistre dans la strucutre
        CHECK(pck->log->al->bootp->options = malloc(sizeof(struct bootp_option_t *) * 256));
        memset(pck->log->al->bootp->options, 0, sizeof(struct bootp_option_t *) * 256);
        struct bootp_option_t ** options = pck->log->al->bootp->options;
        while(*pck->data != 0xff)
        {
            printf("%x\n", *pck->data);
            int option = *pck->data;
            shift_pck(pck, 1);
            CHECK(options[option] = malloc(sizeof(struct bootp_option_t)));
            options[option]->length = *pck->data;
            shift_pck(pck, 1); 
            CHECK(options[option]->value = malloc(options[option]->length));
            memcpy(options[option]->value, pck->data, options[option]->length);
            shift_pck(pck, options[option]->length); 
        }
    }
}

/* Met à jour le log de la couche bootp */
void set_bootp_log(struct pck_t * pck)
{
    struct app_layer_t *al = pck->log->al;
    char * log;
    CHECK(log = calloc(2048, sizeof(char)));

    char dhcp = 0;
    //On met à jour les logs
    if (al->bootp->options != NULL && al->bootp->options[53] == NULL)
    {
        switch (al->bootp->header->bp_op)
        {
            case 1:
                sprintf(log, "Request");
                break;
            case 2:
                sprintf(log, "Reply");
                break;
            default:
                sprintf(log, UNKNOWN);
                break;
        }
    }
    //DHCP
    else{
        dhcp = 1;
        switch (al->bootp->options[53]->value[0])
        {
            case 1:
                sprintf(
                    log,
                    "DISCOVER"
                );
                break;
            case 2:
                sprintf(
                    log,
                    "OFFER"
                );
                break;
            case 3:
                sprintf(
                    log,
                    "REQUEST"
                );
                break;
            case 5:
                sprintf(
                    log,
                    "ACK"
                );
                break;
            default:
                sprintf(
                    log,
                    UNKNOWN
                );
                break;
        }
        //On rajoute l'adresse IP si elle est présente
        if(
            (al->bootp->options[53]->value[0] == 3 || al->bootp->options[53]->value[0] == 5) &&
            al->bootp->options[50] != NULL
        )
        {
            strcat(log, " (IP:");
            strcat(log, ip_to_string((struct in_addr *)al->bootp->options[50]->value));
            strcat(log, ")");
        }
 
    }
    

    

    //On met à jour le log verbose 1
    strcpy(pck->log->log, log);
    if (dhcp)
        strcpy(pck->log->proto, PRINT_DHCP_SHRT);
    else
        strcpy(pck->log->proto, PRINT_BOOTP_SHRT);

    //On met à jour le log verbose 2
    if (dhcp)
        sprintf(al->log, "%s, %s", PRINT_DHCP, log);
    else
        sprintf(al->log, "%s, %s", PRINT_BOOTP, log);

    //On met à jour le log verbose 3
    fill_bootp_log_v3(pck);

    free(log);
}

/* Rempli les logs détaillés pour le verbose 3 */
void fill_bootp_log_v3(struct pck_t * pck)
{
    char * code;
    char * type_h;
    char * len_h;
    char * hops;
    char * ciaddr;
    char * yiaddr;
    char * siaddr;
    char * giaddr;
    char * chaddr;
    char * sname;
    char * file;


    CHECK(code = calloc(2048, sizeof(char)));
    CHECK(type_h = calloc(2048, sizeof(char)));
    CHECK(len_h = calloc(2048, sizeof(char)));
    CHECK(hops = calloc(2048, sizeof(char)));
    CHECK(ciaddr = calloc(2048, sizeof(char)));
    CHECK(yiaddr = calloc(2048, sizeof(char)));
    CHECK(siaddr = calloc(2048, sizeof(char)));
    CHECK(giaddr = calloc(2048, sizeof(char)));
    CHECK(chaddr = calloc(2048, sizeof(char)));
    CHECK(sname = calloc(2048, sizeof(char)));
    CHECK(file = calloc(2048, sizeof(char)));

    //On récupère les données de la couche bootp
    struct bootp_header_t * header = pck->log->al->bootp->header;
    
    //On met à jour les logs
    sprintf(code, "Op code: %d (", header->bp_op);
    switch (header->bp_op)
    {
        case 1:
            strcat(code, "Request");
            break;
        case 2:
            strcat(code, "Reply");
            break;
        default:
            strcat(code, UNKNOWN);
            break;
    }
    strcat(code, ")");

    //Type de hardware
    sprintf(type_h, "Hardware type: %d (", header->bp_htype);
    switch (header->bp_htype)
    {
        case 1:
            strcat(type_h, "Ethernet");
            break;
        default:
            strcat(type_h, UNKNOWN);
            break;
    }
    strcat(type_h, ")");

    //Longueur de l'adresse hardware
    sprintf(len_h, "Hardware address length: %d", header->bp_hlen);

    //Nombre de sauts
    sprintf(hops, "Hops: %d", header->bp_hops);

    //Adresse IP client
    sprintf(ciaddr, "Client IP address: %s", ip_to_string(&header->bp_ciaddr));

    //Adresse IP assignée
    sprintf(yiaddr, "Your (client) IP address: %s", ip_to_string(&header->bp_yiaddr));

    //Adresse IP serveur
    sprintf(siaddr, "Next server IP address: %s", ip_to_string(&header->bp_siaddr));

    //Adresse IP relais
    sprintf(giaddr, "Relay agent IP address: %s", ip_to_string(&header->bp_giaddr));

    //Adresse hardware client
    sprintf(chaddr, "Client hardware address: %x:%x:%x:%x:%x:%x", header->bp_chaddr[0], header->bp_chaddr[1], header->bp_chaddr[2], header->bp_chaddr[3], header->bp_chaddr[4], header->bp_chaddr[5]);

    //Nom du serveur
    sprintf(sname, "%s", header->bp_sname);
    if (strlen(sname) == 0)
        sprintf(sname, "Server name: (none)");
    else
        sprintf(sname, "Server name: %s", sname);

    //Nom du fichier de boot
    sprintf(file, "%s", header->bp_file);
    if (strlen(file) == 0)
        sprintf(file, "Boot file name: (none)");
    else
        sprintf(file, "Boot file name: %s", file);

    //On ajoute les éléments au log
    add_log_v3(&pck->log->al->log_v3, code);
    add_log_v3(&pck->log->al->log_v3, type_h);
    add_log_v3(&pck->log->al->log_v3, len_h);
    add_log_v3(&pck->log->al->log_v3, hops);
    add_log_v3(&pck->log->al->log_v3, ciaddr);
    add_log_v3(&pck->log->al->log_v3, yiaddr);
    add_log_v3(&pck->log->al->log_v3, siaddr);
    add_log_v3(&pck->log->al->log_v3, giaddr);
    add_log_v3(&pck->log->al->log_v3, chaddr);
    add_log_v3(&pck->log->al->log_v3, sname);
    add_log_v3(&pck->log->al->log_v3, file);

    //On libère la mémoire
    free(code);
    free(type_h);
    free(len_h);
    free(hops);
    free(ciaddr);
    free(yiaddr);
    free(siaddr);
    free(giaddr);
    free(chaddr);
    free(sname);
    free(file);

    //On affiche la zone vendor specific
    fill_bootp_log_v3_vs(pck);
}

/* Rempli les logs détaillés pour le verbose 3 vendor spécific */
void fill_bootp_log_v3_vs(struct pck_t * pck)
{
    //On récupère les données de la couche bootp
    struct bootp_option_t ** options = pck->log->al->bootp->options;
    
    char * log = NULL;
    CHECK(log = calloc(2048, sizeof(char)));
    sprintf(log, "Vendor specific information :");
    add_log_v3(&pck->log->al->log_v3, log);
    free(log);

    //On parcourt les options
    for(int i = 0; i < 256; i++)
    {
        if(options[i] != NULL)
        {
            //On récupère les données de l'option
            struct bootp_option_t * option = options[i];
            char * name = NULL;
            char * log = NULL;
            CHECK(name = calloc(256, sizeof(char)));
            CHECK(log = calloc(512, sizeof(char)));

            //On récupère le nom de l'option
            name = get_dhcp_opt_log(i, option->value, option->length);

            sprintf(log, "- Option: (%d) %s", i, name);

            //On ajoute les éléments au log
            add_log_v3(&pck->log->al->log_v3, log);

            //On libère la mémoire
            free(name);
            free(log);
        }
    }
}

/* Renvoie le nom d'une option DHCP */
char * get_dhcp_opt_log(int i, unsigned char * value, int length)
{
    char * name = NULL;
    char * v = NULL;
    char * log = NULL;
    CHECK(name = calloc(256, sizeof(char)));
    CHECK(v = calloc(256, sizeof(char)));
    CHECK(log = calloc(512, sizeof(char)));

    switch (i)
    {
        case 1:
            sprintf(name, "Subnet Mask");
            sprintf(v, "%s", ip_to_string((struct in_addr *) value));
            break;
        case 2:
            sprintf(name, "Time Offset");
            sprintf(v, "%d", ntohl(*((uint32_t *) value)));
            break;
        case 3:
            sprintf(name, "Router");
            sprintf(v, "%s", ip_to_string((struct in_addr *) value));
            break;
        case 50:
            sprintf(name, "Requested IP Address");
            sprintf(v, "%s", ip_to_string((struct in_addr *) value));
            break;
        case 51:
            sprintf(name, "IP Address Lease Time");
            sprintf(v, "%d", ntohl(*((uint32_t *) value))); 
            break;
        case 53:
            sprintf(name, "DHCP Message Type");
            switch (value[0])
            {
                case 1:
                    sprintf(v, "DHCPDISCOVER");
                    break;
                case 2:
                    sprintf(v, "DHCPOFFER");
                    break;
                case 3:
                    sprintf(v, "DHCPREQUEST");
                    break;
                case 4:
                    sprintf(v, "DHCPDECLINE");
                    break;
                case 5:
                    sprintf(v, "DHCPACK");
                    break;
                case 6:
                    sprintf(v, "DHCPNAK");
                    break;
                case 7:
                    sprintf(v, "DHCPRELEASE");
                    break;
                case 8:
                    sprintf(v, "DHCPINFORM");
                    break;
                default:
                    sprintf(v, UNKNOWN);
                    break;
            }
            break;
        case 54:
            sprintf(name, "Server Identifier");
            sprintf(v, "%s", ip_to_string((struct in_addr *) value));
            break;
        case 55:
            sprintf(name, "Parameter Request List");
            printf("length : %d\n", length);
            for(int i = 0; i<length; i++)
            {
                sprintf(v, "%s %d", v, value[i]);
            }
            break;
        case 57:
            sprintf(name, "Maximum DHCP Message Size");
            sprintf(v, "%d", ntohs(*((uint16_t *) value)));
            break;
        case 58:
            sprintf(name, "Renewal Time Value");
            sprintf(v, "%d", ntohl(*((uint32_t *) value)));
            break;
        case 59:
            sprintf(name, "Rebinding Time Value");
            sprintf(v, "%d", ntohl(*((uint32_t *) value)));
            break;
        case 61:
            sprintf(name, "Client Identifier");
            sprintf(v, "%s", ether_to_string((struct ether_addr *) value));
            break;

        default:
            sprintf(name, UNKNOWN);
            sprintf(v, UNKNOWN);
            break;
    }

    sprintf(log, "%s: %s", name, v);
    free(name);
    free(v);
    (void) length;
    return log;
}

/* Fonction propres aux structures */

/* Initialise une structure bootp_t */
struct bootp_t * init_bootp()
{
    struct bootp_t * bootp;
    CHECK(bootp = malloc(sizeof(struct bootp_t)));
    bootp->header = NULL;
    bootp->options = NULL;
    return bootp;
}

/* Libère la mémoire d'une structure bootp_t */
void free_bootp(struct bootp_t * bootp)
{
    if(bootp == NULL) return;
    if(bootp->header != NULL) free(bootp->header);
    if(bootp->options != NULL)
    {
        for(int i = 0; i < 256; i++)
        {
            if(bootp->options[i] != NULL)
            {
                if(bootp->options[i]->value != NULL) free(bootp->options[i]->value);
                free(bootp->options[i]);
            }
        }
        free(bootp->options);
    }
    free(bootp);
}