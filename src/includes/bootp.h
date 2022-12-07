// Gère un paquet bootp
#ifndef H_GL_BOOTP
#define H_GL_BOOTP

struct bootp_info {
    struct bootp_t      *bootp;   //Paquet BOOTP
    char                *infos; //Informations résumant le paquet
    struct vs_info      *vs;    //Informations DHCP
};

/* Structure de l'entête bootp */
struct bootp_t {
    unsigned char bp_op; //Code op
    unsigned char bp_htype; // Type de hardware
    unsigned char bp_hlen; // Taille de l'adresse hardware
    unsigned char bp_hops; // Nombre de sauts
    unsigned long bp_xid; // Identifiant de transaction
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

/* Traite un paquet bootp */
void compute_bootp(const u_char **pck);

/* Définit les variables du printer pour bootp */
void set_printer_bootp(struct bootp_t *bootp);

/* On libère la mémoire */
void free_bootp_info(struct bootp_info *bootp_info);

#endif // H_GL_BOOTP