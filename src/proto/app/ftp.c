// Analyse d'un paquet ftp

#include "../../includes/includes.h"

/* Analyse du paquet ftp */
void compute_ftp(struct pck_t * pck, char is_request)
{
    // On remplit la structure ftp
    fill_ftp(pck, is_request);

    // On met à jour le log de la couche
    set_ftp_log(pck);
}

/* Remplit la structure ftp */
void fill_ftp(struct pck_t * pck, char is_request)
{
    pck->log->al->ftp = init_ftp();
    struct ftp_t * ftp = pck->log->al->ftp;

    if (is_request)
        ftp->type = FTP_REQUEST;
    else
        ftp->type = FTP_RESPONSE;
        

    //On remplit command
    CHECK(ftp->command = calloc(2048, sizeof(char)));
    enum {
        COMMAND,
        ARG
    } state = COMMAND;
    do{
        switch (state)
        {
            case COMMAND:
                //Si on rencontre 0x20, on passe à l'état ARG
                if(*pck->data == 0x20){
                    state = ARG;
                    CHECK(ftp->arg = calloc(sizeof(char), 255));
                    break;
                }
                else
                    sprintf(ftp->command, "%s%c", ftp->command, *pck->data);
                break;
            case ARG:
                sprintf(ftp->arg, "%s%c", ftp->arg, *pck->data);
                
                break;
            default:
                break;
        }
        shift_pck(pck, 1);
    } while(
        *pck->data != 0x0d &&
        get_remaining_bits(pck) > 0
    );
}

/* Met à jour le log de la couche ftp */
void set_ftp_log(struct pck_t * pck)
{
    struct ftp_t * ftp = pck->log->al->ftp;
    char *log;
    CHECK(log = calloc(1024, sizeof(char)));

    // On met à jour les logs
    if(ftp->type == FTP_REQUEST)
        sprintf(log, "Command: ");
    else
        sprintf(log, "Response: ");

    strcat(log, ftp->command);
    if(ftp->arg != NULL){
        strcat(log, " ");
        strcat(log, ftp->arg);
    }
    
    //On met à jour le log verbose 1
    strcpy(pck->log->log, log);
    strcpy(pck->log->proto, PRINT_FTP_SHRT);

    //On met à jour le log verbose 2
    sprintf(
        pck->log->al->log,
        "%s, %s",
        PRINT_FTP,
        log
    );

    //On met à jour le log verbose 3
    fill_ftp_log_v3(pck);

    free(log);
}

/* Rempli les logs détaillés pour le verbose 3 */
void fill_ftp_log_v3(struct pck_t * pck)
{
    char * log;
    CHECK(log = calloc(1024, sizeof(char)));

    struct ftp_t * ftp = pck->log->al->ftp;


    sprintf(log, "Data: ");
    // On met à jour les logs
    if(ftp->type == FTP_REQUEST)
        strcat(log, "Command, ");
    else
        strcat(log, "Response, ");

    strcat(log, ftp->command);
    if(ftp->arg != NULL){
        strcat(log, " ");
        strcat(log, ftp->arg);
    }

    add_log_v3(&pck->log->al->log_v3, log);

    free(log);
}


/* Fonction propres aux structures */

/* Initialise une structure ftp_t */
struct ftp_t * init_ftp()
{
    struct ftp_t * ftp;
    CHECK(ftp = calloc(1, sizeof(struct ftp_t)));
    return ftp;
}

/* Libère la mémoire d'une structure ftp_t */
void free_ftp(struct ftp_t * ftp)
{
    if (ftp == NULL) return;
    if (ftp->command != NULL) free(ftp->command);
    // if (ftp->arg != NULL) free(ftp->arg);
    free(ftp);
}
