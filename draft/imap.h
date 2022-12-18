// Gère un paquet imap
#ifndef H_GL_IMAP
#define H_GL_IMAP


struct imap_logs {
    struct imap_t   * imap;  // Paquet imap
    char            * logs;  // Informations résumant le paquet
};

struct imap_t {
    char                         is_request;       // Indique si c'est une requête ou une réponse
    struct imap_request_t        * list_request;   // Liste des requêtes
    struct imap_response_t       * list_response;  // Liste des réponses
};

struct imap_request_t {
    char                    * tag;            // Tag de la requête
    char                    * command;        // Commande
    char                    * data;           // Données de la commande
    struct imap_request_t   * next;           // Requête suivante
};

struct imap_response_t {
    char                      * data;            // Data
    struct imap_response_t    * next;            // Réponse suivante

};

/* Traite un paquet imap */
void compute_imap(const u_char **pck, char is_request);

/* Définit les variables du printer pour imap */
void set_imap_logs(struct imap_t *imap);


/*** Fonctions utiles aux structures ***/

/* Initialise une structure imap_t */
struct imap_t * init_imap(char is_request);

/* Ajoute une requête à la liste des requêtes */
struct imap_request_t * add_imap_request(struct imap_t * imap);

/* Ajoute une réponse à la liste des réponses */
struct imap_response_t * add_imap_response(struct imap_t * imap);

/* Initialise une structure imap_logs */
struct imap_logs * init_imap_logs();

/* Libère une structure imap_t */
void free_imap(struct imap_t *imap);

/* Libère une structure imap_logs */
void free_imap_logs(struct imap_logs *imap_logs);

#endif // H_GL_IMAP