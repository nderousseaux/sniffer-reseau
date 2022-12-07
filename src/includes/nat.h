// Gère un paquet nat
#ifndef H_GL_NAT
#define H_GL_NAT

struct nat_logs {
    struct nat_t    * nat;      // Paquet NAT
    char            * logs;    // Informations résumant le paquet
};

// Structure d'un paquet nat
struct nat_t {
    int     something; // TODO
};

/* Traite un paquet nat */
void compute_nat(const u_char ** pck);

/* Définit les variables du printer pour nat */
void set_nat_logs(struct nat_t * nat);

/* Crée une structure nat_t */
struct nat_t * init_nat();

/* Crée une structure nat_logs */
struct nat_logs * init_nat_logs();

/* On libère la mémoire */
void free_nat_logs(struct nat_logs * nat_logs);

#endif // H_GL_NAT