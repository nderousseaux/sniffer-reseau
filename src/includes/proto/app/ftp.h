// Analyse d'un paquet ftp
#ifndef FTP_H
#define FTP_H

#include "pck.h"

#define PRINT_FTP "File Transfer Protocol"
#define PRINT_FTP_SHRT "FTP"

struct ftp_t {
    enum {
        FTP_REQUEST,
        FTP_RESPONSE
    } type;
    //Request ou commande
    char * command;
    char * arg;
};

/* Analyse du paquet ftp */
void compute_ftp(struct pck_t * pck, char is_request);

/* Remplit la structure ftp */
void fill_ftp(struct pck_t * pck, char is_request);

/* Met à jour le log de la couche ftp */
void set_ftp_log(struct pck_t * pck);

/* Rempli les logs détaillés pour le verbose 3 */
void fill_ftp_log_v3(struct pck_t * pck);


/* Fonction propres aux structures */

/* Initialise une structure ftp_t */
struct ftp_t * init_ftp();

/* Libère la mémoire d'une structure ftp_t */
void free_ftp(struct ftp_t * ftp);

#endif /* FTP_H */