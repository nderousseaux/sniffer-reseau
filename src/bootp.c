// Gère un paquet bootp

#include "includes/includes.h"

/* Traite un paquet bootp */
void compute_bootp(const u_char **pck)
{
    struct bootp_t *bootp = (struct bootp_t *) *pck;

    //On définit la couche réseau
    set_printer_bootp(bootp);

    //On saute l'entête bootp
    incr_pck(pck, 236); 

    //Si on détecte le magic cookie, on enregistre la zone vendor specific
    if(**pck == 99 && *(*pck + 1) == 130 && *(*pck + 2) == 83 && *(*pck + 3) == 99)
    {
        incr_pck(pck, 4); 
        compute_vs(pck);        
    }

}

/* Définit les variables du printer pour bootp */
void set_printer_bootp(struct bootp_t *bootp)
{
    //on définit les variables
    struct bootp_info *bootp_info;
    struct paquet_info *paquet_info;

    //On remplit bootp_info
    CHECK(bootp_info = malloc(sizeof(struct bootp_info)));
    bootp_info->bootp = bootp;
    CHECK(bootp_info->infos = malloc(100));
    switch (bootp->bp_op)
    {
        case 1:
            sprintf(bootp_info->infos, "Bootstap protocol (Request)");
            break;
        case 2:
            sprintf(bootp_info->infos, "Bootsrap protocol (Reply)");
            break;
        default:
            sprintf(bootp_info->infos, UNKNOWN);
            break;
    }
    
    //On remplit paquet_info
    paquet_info = get_paquet_info();
    paquet_info->eth->ipv4->udp->bootp = bootp_info;
    strcpy(paquet_info->infos, bootp_info->infos);
}

/* On libère la mémoire */
void free_bootp_info(struct bootp_info *bootp_info)
{
    free(bootp_info->infos);

    if(bootp_info->vs != NULL)
        free_vs_info(bootp_info->vs);

    free(bootp_info);
}