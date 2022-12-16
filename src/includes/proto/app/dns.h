// Analyse d'un paquet dns
#ifndef DNS_H
#define DNS_H

#include "pck.h"

#define PRINT_DNS "Domain Name System"
#define PRINT_DNS_SHRT "DNS"



struct dns_t {
    struct dns_header_t     * header;       //Entête DNS
    struct dns_query_t      * queries;      //Requêtes DNS
    struct dns_answer_t     * answers;      //Réponses DNS
    struct dns_answer_t     * authorities;  //Autorités DNS
    struct dns_answer_t     * additionals;  //Informations additionnelles DNS
};

struct dns_header_t {
    unsigned short  id;             // Identification
    unsigned char   rd :1;          // Recursion desired
    unsigned char   tc :1;          // Truncated message
    unsigned char   aa :1;          // Authoritative answer
    unsigned char   opcode :4;      // Operation code
    unsigned char   qr :1;          // Query/Response flag
    unsigned char   rcode :4;       // Response code
    unsigned char   cd :1;          // Checking disabled
    unsigned char   ad :1;          // Authentic data
    unsigned char   z :1;           // Reserved
    unsigned char   ra :1;          // Recursion available
    unsigned short  q_count;        // Number of questions
    unsigned short  ans_count;      // Number of answers
    unsigned short  auth_count;     // Number of authority records
    unsigned short  add_count;      // Number of resource records
};

struct dns_query_t {
    char        *type;      //Type de la requête
    char        *class;     //Classe de la requête
    char        *name;      //Nom de la requête
};

struct dns_answer_t {
    char            *type;
    char            *class;
    char            *name;
    unsigned int    ttl;
    unsigned short  data_len;
    char            *main_info;         //Addresse ip pour les A, nom de domaine pour les SOA, etc  
    char            *responsible_mail;
    unsigned int    serial;
    unsigned int    refresh;
    unsigned int    retry;
    unsigned int    expire;
    unsigned int    minimum;
    unsigned short  preference;
    char            *txt;
};

/* Analyse du paquet dns */
void compute_dns(struct pck_t * pck);

/* Remplit la structure dns */
void fill_dns(struct pck_t * pck);

/* Met à jour le log de la couche dns */
void set_dns_log(struct pck_t * pck);

/* Rempli les logs détaillés pour le verbose 3 */
void fill_dns_log_v3(struct pck_t * pck);

/* Rempli les logs détaillés pour une queries */
void fill_dns_query_log_v3(struct pck_t * pck, struct dns_query_t * query);

/* Rempli les logs détaillés pour une réponse */
void fill_dns_answer_log_v3(struct pck_t * pck, struct dns_answer_t * ans);

/* Lit une requête dns */
void read_dns_query(struct pck_t * pck, struct dns_query_t * query);

/* Lit une réponse dns */
void read_dns_answer(struct pck_t * pck, struct dns_answer_t * ans);

/* Lit un str dans les données (utilise le c0 pour pointer vers une autre zone) */
void read_dns_name(char* str, struct pck_t * paq, const u_char * data, char base);

/* Fonction propres aux structures */

/* Initialise une structure dns_t */
struct dns_t * init_dns();

/* Initialise les query dns */
struct dns_query_t * init_dns_query(int nb_query);

/* Initialise les answer dns */
struct dns_answer_t * init_dns_answer(int nb_answer);

/* Libère la mémoire d'une structure dns_t */
void free_dns(struct dns_t * dns);

/* Libère la mémoire d'une structure dns_query_t */
void free_dns_query(struct dns_query_t * query, int nb_query);

/* Libère la mémoire d'une structure dns_answer_t */
void free_dns_answer(struct dns_answer_t * answer, int nb_answer);

#endif /* dns_H */