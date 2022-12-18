// Analyse de la couche application
#ifndef APP_H
#define APP_H

#include "pck.h"

enum app_type {
    HTTP,
    FTP_REQ,
    FTP_RES,
    SMTP,
    POP3,
    IMAP,
    DNS,
    TELNET,
    BOOTP,
};

struct app_layer_t {
    enum app_type           type; // Type de protocole applicatif
    int                     offset; // Offset du la fin de la couche application
    char                    *log; // Log de la couche application
    struct bootp_t          *bootp; // Structure bootp
    struct dns_t            *dns; // Structure dns
    struct telnet_t         *telnet; // Structure telnet
    struct ftp_t            *ftp; // Structure ftp
    struct log_v3_t         *log_v3;
};

/* Analyse la couche application */
void compute_app(struct pck_t * pck);

/* Détermine le type d'application */
void determine_app_type(struct pck_t * pck);

/* Met à jour le log de la couche application */
void set_app_log(struct pck_t * pck, struct app_layer_t * al);


/* Fonctions propre à la structure app_layer */

/* Initialise une structure app_layer */
struct app_layer_t *init_al();

/* Libère la structure app_layer */
void free_al(struct app_layer_t *al);

#endif