// Gère un paquet dns
#ifndef H_GL_DNS
#define H_GL_DNS

#include <arpa/inet.h>
#include <netinet/ip.h>
#include <stdio.h>
#include <stdlib.h>


#include "printer.h"
#include "sniffer.h"
#include "udp.h"
#include "utils.h"

struct dns_info {
    struct dns_t        *dns;   //Paquet DNS
    char                *infos; //Informations résumant le paquet
};

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


/* Traite un paquet dns */
void compute_dns(const u_char **pck);

/* Définit les variables du printer pour dns */
void set_printer_dns(struct dns_t *dns);

/* Stocke une requête dns */
void read_dns_query(struct dns_query_t *query, const u_char **data);

/* Stocke une réponse dns */
void read_dns_answer(struct dns_answer_t *ans, const u_char **data);

/* Lit un str dans les données (utilise le c0 pour pointer vers une autre zone) */
void read_dns_name(char* str, const u_char **data);

#endif // H_GL_DNS