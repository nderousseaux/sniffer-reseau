// Gère un paquet ftp

#include "includes/includes.h"

/* Traite un paquet ftp */
void compute_ftp(const u_char **pck, char is_request)
{
    char * command = NULL;
    char * arg = NULL;
    struct ftp_t *ftp;
    CHECK(ftp = calloc(1, sizeof(struct ftp_t)));

    //On remplit command
    CHECK(command = calloc(sizeof(char), 5));
    enum {
        COMMAND,
        ARG
    } state = COMMAND;
    do{
        switch (state)
        {
            case COMMAND:
                //Si on rencontre 0x20, on passe à l'état ARG
                if(**pck == 0x20){
                    state = ARG;
                    CHECK(arg = calloc(sizeof(char), 255));
                    break;
                }
                else
                    sprintf(command, "%s%c", command, **pck);
                break;
            case ARG:
                sprintf(arg, "%s%c", arg, **pck);
                break;
            default:
                break;
        }
        incr_pck(pck, 1);
    } while(
        **pck != 0x0d &&
        get_remaining_bytes(pck) > 0
    );
    if (is_request){
        ftp->type = FTP_REQUEST;
        ftp->request_command = command;
        if(arg != NULL)
            ftp->request_arg = arg;
    }
    else{
        ftp->type = FTP_RESPONSE;
        ftp->response_code = command;
        if(arg != NULL)
            ftp->response_arg = arg;
    }


    //On définit la couche application
    set_printer_ftp(ftp);
}

/* Définit les variables du printer pour ftp */
void set_printer_ftp(struct ftp_t *ftp)
{
    //On définit les variables
    char *infos;
    struct ftp_info *ftp_info;
    struct paquet_info *paquet_info;

    //On remplit infos
    CHECK(infos = malloc(255));
    if(ftp->type == FTP_REQUEST){
        sprintf(
            infos,
            "Request: %s",
            ftp->request_command
        );
        if(ftp->request_arg != NULL)
            sprintf(
                infos,
                "%s %s",
                infos,
                ftp->request_arg
            );
    }
    else
        sprintf(infos, 
        "Response: %s %s",
        ftp->response_code,
        ftp->response_arg
    );
    printable_str(infos);

    //On remplit ftp_info
    CHECK(ftp_info = malloc(sizeof(struct ftp_info)));
    ftp_info->ftp = ftp;
    CHECK(ftp_info->infos = malloc(255)); 
    sprintf(ftp_info->infos, "FTP %s", infos);
   
    //On remplit paquet_info
    paquet_info = get_paquet_info();
    paquet_info->eth->ipv4->tcp->ftp = ftp_info;
    strcpy(paquet_info->protocol, "FTP");
    strcpy(paquet_info->infos, infos);

    //On libère la mémoire
    free(infos);
}

/* On libère la mémoire */
void free_ftp_info(struct ftp_info *ftp_info)
{
    if(ftp_info->ftp->type == FTP_REQUEST){
        free(ftp_info->ftp->request_command);
        if(ftp_info->ftp->request_arg != NULL)
            free(ftp_info->ftp->request_arg);
    }
    if(ftp_info->ftp->type == FTP_RESPONSE){
        free(ftp_info->ftp->response_code);
        if(ftp_info->ftp->response_arg != NULL)
            free(ftp_info->ftp->response_arg);
    }
    free(ftp_info->infos);
    free(ftp_info->ftp);
    free(ftp_info);
}