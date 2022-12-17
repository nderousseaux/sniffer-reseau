// Analyse d'un paquet telnet

#include "../../includes/includes.h"

/* Analyse du paquet telnet */
void compute_telnet(struct pck_t * pck)
{
    //On remplit la structure telnet
    fill_telnet(pck);

    //On met à jour le log de la couche
    set_telnet_log(pck);
}

/* Remplit la structure telnet */
void fill_telnet(struct pck_t * pck)
{
    struct telnet_t * telnet = init_telnet();
    pck->log->al->telnet = telnet;

    //Si le paquet commence par 0xff, on a une commande
    if(*pck->data == 0xff)
        save_telnet_command(telnet, pck);
    //Sinon, on a des données
    else
        save_telnet_data(telnet, pck);
}

/* Met à jour le log de la couche telnet */
void set_telnet_log(struct pck_t * pck)
{
    struct telnet_t * telnet = pck->log->al->telnet;
    char *log;
    CHECK(log = calloc(1024, sizeof(char)));


    // On met à jour les logs
    if(telnet->data != NULL){
        sprintf(
            log,
            "Data: \"%s\"",
            telnet->data
        );
    }
    else
        sprintf(
            log,
            "Options: %d",
            telnet->nb_options + 1
        );

    printable_str(log);
    
    //On met à jour le log verbose 1

    strcpy(pck->log->log, log);
    strcpy(pck->log->proto, PRINT_TELNET_SHRT);

    //On met à jour le log verbose 2
    sprintf(
        pck->log->al->log,
        "%s, %s",
        PRINT_TELNET,
        log
    );

    //On met à jour le log verbose 3
    fill_telnet_log_v3(pck);

    //On libère la mémoire
    free(log);
}

/* Rempli les logs détaillés pour le verbose 3 */
void fill_telnet_log_v3(struct pck_t * pck)
{
    char * data;
    char * command;
    char * subcommand;
    CHECK(data = calloc(1024, sizeof(char)));
    CHECK(command = calloc(1024, sizeof(char)));
    CHECK(subcommand = calloc(1024, sizeof(char)));

    //On récupère les données telnet
    struct telnet_t * telnet = pck->log->al->telnet;


    //On affiche chaque option
    for(int i = 0; i<telnet->nb_options; i++){
        
        
        telnet_command_str(telnet->options[i].command, command);
        telnet_subcommand_str(telnet->options[i].subcommand, subcommand);

        sprintf(data, "Option: %s %s", command, subcommand);
        add_log_v3(&pck->log->al->log_v3, data);

    }

    if(telnet->data != NULL)
    {
        // Pour chaque ligne dans telnet->data 
        const char * separators = "\n";
        char * strToken = strtok ( telnet->data, separators );
        while ( strToken != NULL ) {
            printable_str(strToken);
            sprintf(data, "Data: \"%s\"", strToken);
            add_log_v3(&pck->log->al->log_v3, data);
            strToken = strtok ( NULL, separators );
        }
    }



    //On libère la mémoire
    free(data);
    free(command);
    free(subcommand);
}

/* Enregistre une commande telnet */
void save_telnet_command(struct telnet_t * telnet, struct pck_t * pck)
{
    CHECK(telnet->options = calloc(255, sizeof(struct telnet_options_t)));
    telnet->nb_options = 0;
    telnet->data = NULL;
    // Tant que le paquet n'est pas vide, on stocke les options
    enum {mode_option, mode_subcommand, mode_data_option} mode;
    do
    {
        //Si packet == 0xff, on a une option
        if(*pck->data == 0xff)
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
                telnet->options[telnet->nb_options-1].command = (enum telnet_command) *pck->data;
                mode = mode_subcommand;
                break;
            //Si on est en mode subcommand, on stocke la subcommand
            case mode_subcommand:
                telnet->options[telnet->nb_options-1].subcommand = (enum telnet_subcommand) *pck->data;
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
                    *pck->data
                );
                telnet->options[telnet->nb_options-1].length_data++;
                break;
            default:
                break;
        }
    } while(shift_pck(pck, 1));
}

/* Enregistre des données telnet */
void save_telnet_data(struct telnet_t * telnet, struct pck_t * pck)
{
    char *data;
    CHECK(data = calloc(1024, sizeof(char)));
    do
    {
        sprintf(
            data,
            "%s%c",
            data,
            *pck->data
        );
    } while(shift_pck(pck, 1));
    sprintf(
        data,
        "%s%c",
        data,
        '\0'
    );
    telnet->data = data;
}

/* Convertit une code commande en str */
void telnet_command_str(enum telnet_command command, char * str)
{
    switch (command)
    {
        case SE:
            sprintf(str, "SE");
            break;
        case NOP:
            sprintf(str, "NOP");
            break;
        case DM:
            sprintf(str, "DM");
            break;
        case BRK:
            sprintf(str, "BRK");
            break;
        case IP_C:
            sprintf(str, "IP");
            break;
        case AO:
            sprintf(str, "AO");
            break;
        case AYT:
            sprintf(str, "AYT");
            break;
        case EC:
            sprintf(str, "EC");
            break;
        case EL:
            sprintf(str, "EL");
            break;
        case GA:
            sprintf(str, "GA");
            break;
        case SB:
            sprintf(str, "SB");
            break;
        case WILL:
            sprintf(str, "WILL");
            break;
        case WONT:
            sprintf(str, "WONT");
            break;
        case DO:
            sprintf(str, "DO");
            break;
        case DONT:
            sprintf(str, "DONT");
            break;
        case IAC:
            sprintf(str, "IAC");
            break;
        default:
            sprintf(str, UNKNOWN);
            break;
    }
}

/* Convertit un code subcommande en str */
void telnet_subcommand_str(enum telnet_subcommand subcommand, char * str)
{
    switch (subcommand)
    {
        case ECHO:
            sprintf(str, "ECHO");
            break;
        case SUPPRESS_GO_AHEAD:
            sprintf(str, "SUPPRESS_GO_AHEAD");
            break;
        case STATUS:
            sprintf(str, "STATUS");
            break;
        case TERMINAL_TYPE:
            sprintf(str, "TERMINAL_TYPE");
            break;
        case NEGOTIAE_WINDOW_SIZE:
            sprintf(str, "NEGOTIAE_WINDOW_SIZE");
            break;
        case TERMINAL_SPEED:
            sprintf(str, "TERMINAL_SPEED");
            break;
        case REMOTE_FLOW_CONTROL:
            sprintf(str, "REMOTE_FLOW_CONTROL");
            break;
        case LINEMODE:
            sprintf(str, "LINEMODE");
            break;
        case DISPLAY_LOCATION:
            sprintf(str, "DISPLAY_LOCATION");
            break;
        case ENVIRONMENT_OPTION:
            sprintf(str, "ENVIRONMENT_OPTION");
            break;
        case AUTHENTICATION_OPTION:
            sprintf(str, "AUTHENTICATION_OPTION");
            break;
        case ENCRYPTION_OPTION:
            sprintf(str, "ENCRYPTION_OPTION");
            break;
        case NEW_ENVIRONMENT_OPTION:
            sprintf(str, "NEW_ENVIRONMENT_OPTION");
            break;
        default:
            sprintf(str, UNKNOWN);
            break;
    }
}


/* Fonction propres aux structures */

/* Initialise une structure telnet_t */
struct telnet_t * init_telnet()
{
    struct telnet_t * telnet;
    CHECK(telnet = malloc(sizeof(struct telnet_t)));

    telnet->data = NULL;
    telnet->options = NULL;
    telnet->nb_options = 0;
    
    return telnet;
}

/* Libère la mémoire d'une structure telnet_t */
void free_telnet(struct telnet_t * telnet)
{
    if(telnet == NULL) return;
    if(telnet->data != NULL) free(telnet->data);
    for(int i = 0; i < telnet->nb_options; i++)
    {
        if(telnet->options[i].data != NULL) free(telnet->options[i].data);
    }
    if(telnet->options != NULL) free(telnet->options);
}
