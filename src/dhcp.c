// Gère un paquet dhcp (et vendor specific si jamais)

#include "includes/includes.h"

/* Traite la zone vendor specific ou dhcp */
void compute_vs(const u_char **pck){
    //Pour chaque option, on l'enregistre dans la strucutre
    struct vs_options_t **options = malloc(sizeof(struct vs_options_t *) * 256);

    while(**pck != 0xff)
    {
        int option = **pck;
        incr_pck(pck, 1); 
        options[option] = malloc(sizeof(struct vs_options_t));
        options[option]->length = **pck;
        incr_pck(pck, 1); 
        options[option]->value = malloc(options[option]->length);
        memcpy(options[option]->value, *pck, options[option]->length);
        incr_pck(pck, options[option]->length); 
    }
    set_printer_vs(options);
}

/* Définit les variables du printer pour vs */
void set_printer_vs(struct vs_options_t **options)
{
    //On définit les variables
    int nb_options = 0;
    char * ip;
    struct vs_info *vs_info;
    struct paquet_info *paquet_info;

    //On compte le nombre d'options
    for(int i = 0; i < 256; i++)
    {
        if(options[i] != NULL)
        {
            nb_options++;
        }
    }

    //On remplit vs_info
    CHECK(vs_info = malloc(sizeof(struct vs_info)));
    vs_info->options = options;
    CHECK(vs_info->infos = malloc(255));
    CHECK(ip = malloc(16));
    //Si on détecte de le type (dhcp ou vendor specific)
    if(options[53] == 0)
        sprintf(vs_info->infos, "Vendor specific (%d options)", nb_options);
    else{
        sprintf(vs_info->infos, "DHCP");
        switch (options[53]->value[0])
        {
            case 1:
                sprintf(
                    vs_info->infos,
                    "%s Discover",
                    vs_info->infos
                );
                break;
            case 2:
                sprintf(
                    vs_info->infos,
                    "%s Offer",
                    vs_info->infos
                );
                break;
            case 3:
                sprintf(
                    vs_info->infos,
                    "%s Request",
                    vs_info->infos
                );
                break;
            case 5:
                sprintf(
                    vs_info->infos,
                    "%s Ack",
                    vs_info->infos
                );
                break;
            default:
                sprintf(
                    vs_info->infos,
                    "%s Unknown (%d options)",
                    vs_info->infos,
                    nb_options
                );
                break;
        }
        //On rajoute l'adresse IP si elle est présente
        if(
            (options[53]->value[0] == 3 || options[53]->value[0] == 5) &&
            options[50] != NULL
        )
        {
            ip_to_string((struct in_addr *)options[50]->value, ip);
            sprintf(
                vs_info->infos,
                "%s (IP : %s)",
                vs_info->infos,
                ip
            );
        }
    }

    //On remplit paquet_info
    paquet_info = get_paquet_info();
    strcpy(paquet_info->protocol, "DHCP");
    paquet_info->eth->ipv4->udp->bootp->vs = vs_info;
    strcpy(paquet_info->infos, vs_info->infos);
}

/* On libère la mémoire */
void free_vs_info(struct vs_info *vs_info)
{
    for(int i = 0; i < 256; i++)
    {
        if(vs_info->options[i] != NULL)
        {
            free(vs_info->options[i]->value);
            free(vs_info->options[i]);
        }
    }
    free(vs_info->infos);
    free(vs_info);
}