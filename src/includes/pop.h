// Gère un paquet pop
#ifndef H_GL_POP
#define H_GL_POP


struct pop_logs {
    struct pop_t    * pop;  // Paquet pop
    char            * logs;    // Informations résumant le paquet
};

struct pop_t {
    char        is_request;       // Indique si c'est une requête ou une réponse
    char        * command;        // Indicateur de réponse (pour une réponse) ou commande (pour une requête)
    char        * description;    // Description de la réponse (pour une réponse) ou de la commande (pour une requête)
    char        * data;           // Données (toujours vide pour une requête)
};

/* Traite un paquet pop */
void compute_pop(const u_char **pck, char is_request);

/* Définit les variables du printer pour pop */
void set_pop_logs(struct pop_t *pop);

/* Initialise une structure pop_t */
struct pop_t * init_pop();

/* Initialise une structure pop_logs */
struct pop_logs * init_pop_logs();

/* On libère la mémoire */
void free_pop_logs(struct pop_logs *pop_logs);

#endif // H_GL_POP