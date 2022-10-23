#ifndef H_GL_PROTOCOLS
#define H_GL_PROTOCOLS

/* Structure de l'entête bootp */
struct bootp {
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

struct vendor_specific_t {
    struct vendor_specific_option_t ** options; //Liste des options, le type correspond à l'index
};

struct vendor_specific_option_t {
    unsigned char length;
    unsigned char * value;
};


#endif