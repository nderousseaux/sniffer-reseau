// Gère un paquet smtp
#ifndef H_GL_SMTP
#define H_GL_SMTP


struct smtp_logs {
    struct smtp_t   * smtp;  // Paquet smtp
    char            * logs;  // Informations résumant le paquet
};

struct smtp_t {
    char                          is_request;       // Indique si c'est une requête ou une réponse
    struct smtp_data_t            * data;           // Données du paquet
};

struct smtp_data_t {
    char                          * data;           // Données du paquet
    struct smtp_data_t            * next;           // Données suivantes
};

/* Traite un paquet smtp */
void compute_smtp(const u_char **pck, char is_request);

/* Définit les variables du printer pour smtp */
void set_smtp_logs(struct smtp_t *smtp);


/*** Fonctions utiles aux structures ***/

/* Initialise une structure smtp_t */
struct smtp_t * init_smtp(char is_request);

/* Ajoute une ligne à la liste des données */
char * add_smtp_data(struct smtp_t * smtp);

/* Initialise une structure smtp_logs */
struct smtp_logs * init_smtp_logs();

/* Libère une structure smtp_t */
void free_smtp(struct smtp_t *smtp);

/* Libère une structure smtp_logs */
void free_smtp_logs(struct smtp_logs *smtp_logs);

#endif // H_GL_SMTP