// Gère un paquet icmp
#include "includes/includes.h"

/* Traite un paquet icmp */
void compute_icmp(const u_char **pck)
{
    struct icmp *icmp = (struct icmp *) *pck;

    //On définit la couche réseau
    set_printer_icmp(icmp);
}

/* Définit les variables du printer pour icmp */
void set_printer_icmp(struct icmp *icmp)
{
    //On définit les variables
    char * type;
    struct icmp_info *icmp_info;
    struct paquet_info *paquet_info;

    //On définit le type
    CHECK(type = malloc(100));
    switch(icmp->icmp_type)
    {
        case ICMP_ECHOREPLY:
            strcpy(type, "Echo (ping) reply");
            break;
        case ICMP_ECHO:
            strcpy(type, "Echo (ping) request");
            break;
        case ICMP_UNREACH:
            strcpy(type, "Destination Unreachable");
            break;
        case ICMP_TIMXCEED:
            strcpy(type, "Time Exceeded");
            break;
        default:
            strcpy(type, UNKNOWN);
            break;
    }

    //On remplit icmp_info
    CHECK(icmp_info = malloc(sizeof(struct icmp_info)));
    icmp_info->icmp = icmp;
    CHECK(icmp_info->infos = malloc(255));
    if (icmp->icmp_type == ICMP_ECHOREPLY || icmp->icmp_type == ICMP_ECHO)
    {
        sprintf(
            icmp_info->infos,
            "%s id=%d, seq=%d",
            type,
            icmp->icmp_id,
            icmp->icmp_seq
        );
    }
    else
    {
        sprintf(
            icmp_info->infos,
            "%s, Code: %d",
            type,
            icmp->icmp_code
        );
    }

    //On remplit paquet_info
    paquet_info = get_paquet_info();
    paquet_info->eth->ipv4->icmp = icmp_info;
    strcpy(paquet_info->infos, icmp_info->infos);

    //On libère la mémoire
    free(type);
}

/* On libère la mémoire */
void free_icmp_info(struct icmp_info *icmp_info)
{
    free(icmp_info->infos);
    free(icmp_info);
}