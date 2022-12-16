// Analyse d'un paquet bootp
#ifndef BOOTP_H
#define BOOTP_H

#include "pck.h"

#define PRINT_BOOTP "Bootstrap Protocol"
#define PRINT_DHCP "Dynamic Host Configuration Protocol"
#define PRINT_BOOTP_SHRT "BOOTP"
#define PRINT_DHCP_SHRT "DHCP"

struct bootp_t {
    struct bootp_header_t * header;
    struct bootp_option_t ** options;
};

struct bootp_option_t {
    unsigned char length;
    unsigned char * value;
};

/* Structure de l'entête bootp */
struct bootp_header_t {
    unsigned char bp_op; //Code op
    unsigned char bp_htype; // Type de hardware
    unsigned char bp_hlen; // Taille de l'adresse hardware
    unsigned char bp_hops; // Nombre de sauts
    unsigned int bp_xid; // Identifiant de transaction
    unsigned short bp_secs; // Nombre de secondes depuis le début du boot
    unsigned short bp_flags; // Flags
    struct in_addr bp_ciaddr; // Adresse IP du client
    struct in_addr bp_yiaddr; // Adresse IP allouée
    struct in_addr bp_siaddr; // Adresse IP du serveur
    struct in_addr bp_giaddr; // Adresse IP du routeur
    unsigned char bp_chaddr[16]; // Adresse hardware du client
    unsigned char bp_sname[64]; // Nom du serveur
    unsigned char bp_file[128]; // Nom du fichier boot
};


/* Analyse du paquet bootp */
void compute_bootp(struct pck_t * pck);

/* Remplit la structure bootp */
void fill_bootp(struct pck_t * pck);

/* Met à jour le log de la couche bootp */
void set_bootp_log(struct pck_t * pck);

/* Rempli les logs détaillés pour le verbose 3 */
void fill_bootp_log_v3(struct pck_t * pck);

/* Rempli les logs détaillés pour le verbose 3 vendor spécific */
void fill_bootp_log_v3_vs(struct pck_t * pck);

/* Renvoie le nom d'une option DHCP */
char * get_dhcp_opt_log(int i, unsigned char * value, int length);

/* Fonction propres aux structures */

/* Initialise une structure bootp_t */
struct bootp_t * init_bootp();

/* Libère la mémoire d'une structure bootp_t */
void free_bootp(struct bootp_t * bootp);

#endif /* BOOTP_H */