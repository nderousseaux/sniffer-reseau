// Gère un paquet http
#ifndef H_GL_HTTP
#define H_GL_HTTP

struct http_logs {
    struct http_t   * http;  // Paquet http
    char            * logs;  // Informations résumant le paquet
};

struct http_t {
    char                          is_request;       // Indique si c'est une requête ou une réponse
    struct http_data_t            * data;           // Données du paquet
};

struct http_data_t {
    char                          * data;           // Données du paquet
    struct http_data_t            * next;           // Données suivantes
};

/* Traite un paquet http */
void compute_http(const u_char **pck, char is_request);

/* Définit les variables du printer pour http */
void set_http_logs(struct http_t *http);


/*** Fonctions utiles aux structures ***/

/* Initialise une structure http_t */
struct http_t * init_http(char is_request);

/* Ajoute une ligne à la liste des données */
char * add_http_data(struct http_t * http);

/* Initialise une structure http_logs */
struct http_logs * init_http_logs();

/* Libère une structure http_t */
void free_http(struct http_t *http);

/* Libère une structure http_logs */
void free_http_logs(struct http_logs *http_logs);

#endif // H_GL_HTTP