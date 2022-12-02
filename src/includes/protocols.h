#ifndef H_GL_PROTOCOLS
#define H_GL_PROTOCOLS

#include <arpa/inet.h>

#define UNKNOWN "Unknown"

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

struct dns_t {
    struct dns_header_t * header;
    struct dns_query_t * queries;
    struct dns_answer_t * answers;
    struct dns_answer_t * authorities;
    struct dns_answer_t * additionals;
};

struct dns_header_t {
    unsigned short id; // Identification
    unsigned char rd :1; // Recursion desired
    unsigned char tc :1; // Truncated message
    unsigned char aa :1; // Authoritative answer
    unsigned char opcode :4; // Operation code
    unsigned char qr :1; // Query/Response flag
    unsigned char rcode :4; // Response code
    unsigned char cd :1; // Checking disabled
    unsigned char ad :1; // Authentic data
    unsigned char z :1; // Reserved
    unsigned char ra :1; // Recursion available
    unsigned short q_count; // Number of questions
    unsigned short ans_count; // Number of answers
    unsigned short auth_count; // Number of authority records
    unsigned short add_count; // Number of resource records
};

struct dns_query_t {
    char        *type;
    char        *class;
    char        *name;
};

struct dns_answer_t {
    char            *type;
    char            *class;
    char            *name;
    unsigned int    ttl;
    unsigned short  data_len;
    char            *main_info; //Addresse ip pour les A, nom de domaine pour les SOA, etc  
    char            *responsible_mail;
    unsigned int    serial;
    unsigned int    refresh;
    unsigned int    retry;
    unsigned int    expire;
    unsigned int    minimum;
    unsigned short  preference;
    char            *txt;
};

#endif