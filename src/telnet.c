// Gère un paquet telnet
#include "includes/includes.h"

/* Traite un paquet telnet */
void compute_telnet(const u_char **pck)
{
    //On déclare une struct telnet
    struct telnet *telnet;
    CHECK(telnet = malloc(sizeof(struct telnet)));
    telnet->nb_options = 0;
    telnet->options = NULL;
    telnet->data = NULL;

    //Si le paquet commence par 0xff, on a une commande
    if(**pck == 0xff)
        save_telnet_command(telnet, pck);
    //Sinon, on a des données
    else
        save_telnet_data(telnet, pck);

    //On définit la couche application
    set_printer_telnet(telnet);
}

/* Sauvegarde un paquet telnet de type commande */
void save_telnet_command(struct telnet *telnet, const u_char **pck)
{
    CHECK(telnet->options = calloc(255, sizeof(struct telnet_options)));
    telnet->nb_options = 0;
    telnet->data = NULL;
    // Tant que le paquet n'est pas vide, on stocke les options
    enum {mode_option, mode_subcommand, mode_data_option} mode;
    do
    {
        //Si packet == 0xff, on a une option
        if(**pck == 0xff)
        {
            //On passe le mode en mode option
            mode = mode_option;
            telnet->nb_options++;
            //On intialise le nombre de données à 0
            telnet->options[telnet->nb_options].length_data = 0;
            continue;
        }

        switch (mode)
        {
            //Si on est en mode option, on stocke l'option
            case mode_option:
                telnet->options[telnet->nb_options-1].command = (enum telnet_command) **pck;
                mode = mode_subcommand;
                break;
            //Si on est en mode subcommand, on stocke la subcommand
            case mode_subcommand:
                telnet->options[telnet->nb_options-1].subcommand = (enum telnet_subcommand) **pck;
                mode = mode_data_option;
                break;
            //Si on est en mode data option, on stocke les données
            case mode_data_option:
                if (telnet->options[telnet->nb_options-1].length_data == 0)
                    CHECK(telnet->options[telnet->nb_options-1].data = calloc(1024, sizeof(char)));

                //Pour chaque octet, on stocke les données
                sprintf(
                    telnet->options[telnet->nb_options-1].data,
                    "%s%x ",
                    telnet->options[telnet->nb_options-1].data,
                    **pck
                );
                telnet->options[telnet->nb_options-1].length_data++;
                break;
            default:
                break;
        }
    } while(incr_pck(pck, 1));

}
    
/* Sauvegarde un paquet telnet de type données */
void save_telnet_data(struct telnet *telnet, const u_char **pck)
{
    char *data;
    CHECK(data = calloc(1024, sizeof(char)));
    do
    {
        sprintf(
            data,
            "%s%c",
            data,
            **pck
        );
    } while(incr_pck(pck, 1));
    sprintf(
        data,
        "%s%c",
        data,
        '\0'
    );
    telnet->data = data;
}

/* Définit les variables du printer pour telnet */
void set_printer_telnet(struct telnet *telnet)
{
    //On définit les variables
    struct telnet_info *telnet_info;
    struct paquet_info *paquet_info;

    //On remplit telent_info
    CHECK(telnet_info = malloc(sizeof(struct telnet_info)));
    telnet_info->telnet = telnet;
    CHECK(telnet_info->infos = malloc(sizeof(char)*1024));
    //On affiche les infos
    if(telnet->data != NULL){
        printable_str(telnet->data);
        sprintf(
            telnet_info->infos,
            "Telnet Data: %s",
            telnet->data
        );
    }
    //On indique les options
    else{
        sprintf(
            telnet_info->infos,
            "Telnet Options: %d",
            telnet->nb_options + 1
        );
    }

    //On remplit paquet_info;
    paquet_info = get_paquet_info();
    paquet_info->eth->ipv4->tcp->telnet = telnet_info;
    strcpy(paquet_info->protocol, "TELNET");
    strcpy(paquet_info->infos, telnet_info->infos);
}

/* Renvoie la commande telnet */
char * get_telnet_command(enum telnet_command command)
{
    switch (command)
    {
        case SE:
            return "SE";
        case NOP:
            return "NOP";
        case DM:
            return "DM";
        case BRK:
            return "BRK";
        case IP:
            return "IP";
        case AO:
            return "AO";
        case AYT:
            return "AYT";
        case EC:
            return "EC";
        case EL:
            return "EL";
        case GA:
            return "GA";
        case SB:
            return "SB";
        case WILL:
            return "WILL";
        case WONT:
            return "WONT";
        case DO:
            return "DO";
        case DONT:
            return "DONT";
        case IAC:
            return "IAC";
        default:
            return UNKNOWN;
    }
}

/* Renvoie la subcommande telnet */
char * get_telnet_subcommand(enum telnet_subcommand subcommand)
{
    switch (subcommand)
    {
        case ECHO:
            return "ECHO";
        case SUPPRESS_GO_AHEAD:
            return "SUPPRESS_GO_AHEAD";
        case STATUS:
            return "STATUS";
        case TERMINAL_TYPE:
            return "TERMINAL_TYPE";
        case NEGOTIAE_WINDOW_SIZE:
            return "NEGOTIAE_WINDOW_SIZE";
        case TERMINAL_SPEED:
            return "TERMINAL_SPEED";
        case REMOTE_FLOW_CONTROL:
            return "REMOTE_FLOW_CONTROL";
        case LINEMODE:
            return "LINEMODE";
        case DISPLAY_LOCATION:
            return "DISPLAY_LOCATION";
        case ENVIRONMENT_OPTION:
            return "ENVIRONMENT_OPTION";
        case AUTHENTICATION_OPTION:
            return "AUTHENTICATION_OPTION";
        case ENCRYPTION_OPTION:
            return "ENCRYPTION_OPTION";
        case NEW_ENVIRONMENT_OPTION:
            return "NEW_ENVIRONMENT_OPTION";
        default:
            return UNKNOWN;
    }
}

/* On libère la mémoire */
void free_telnet_info(struct telnet_info *telnet)
{
    if(telnet->telnet->data != NULL)
        free(telnet->telnet->data);
    if(telnet->telnet->options != NULL){
        for(int i = 0; i < telnet->telnet->nb_options; i++)
            if(telnet->telnet->options[i].data != NULL)
                free(telnet->telnet->options[i].data);
        free(telnet->telnet->options);
    }


    free(telnet->telnet);
    free(telnet->infos);
    free(telnet);
}