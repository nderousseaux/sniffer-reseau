// Contient la structure et les fonctions pour un objet log
#ifndef H_GL_LOG
#define H_GL_LOG


/* Structure stockant les logs du paquet */
struct log_t {
    int                     nb_pck;     // Numéro du paquet
    char                    *src;       // Adresse source
    char                    *dst;       // Adresse destination
    char                    *proto;     // Protocole
    char                    *log;       // Informations principale du paquet (niveau de verbosité 1)
    struct link_layer_t     *ll;        // Informations liées à la couche lien
    struct net_layer_t      *nl;        // Informations liées à la couche réseau
    struct trans_layer_t    *tl;        // Informations liées à la couche transport
    struct app_layer_t      *al;        // Informations liées à la couche applicative
};

/* Logs détaillés pour le verbose 3 */
struct log_v3_t {
    char              *log;   // Ligne de log
    struct log_v3_t   *next;  // Ligne suivante
};

/* Initialise une structure log */
struct log_t *init_log();

/* Libère la structure log */
void free_log(struct log_t *log);

/* Ajoute un élément à log_v3 */
void add_log_v3(struct log_v3_t **log_v3, char *log);

/* Libère la structure log_v3 */
void free_log_v3(struct log_v3_t *log_v3);


#endif //H_GL_LOG