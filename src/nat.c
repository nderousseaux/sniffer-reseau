// Gère un paquet nat
#include "include.h"

/* Traite un paquet nat */
void compute_nat(const u_char ** pck)
{
    struct nat_t * nat = init_nat();   


    (void) pck;
    (void) nat;
}

/* Définit les variables du printer pour nat */
void set_nat_logs(struct nat_t * nat)
{
    (void) nat;
}

/* Crée une structure nat_t */
struct nat_t * init_nat()
{
    struct nat_t * nat;
    CHECK(nat = calloc(sizeof(struct nat_t), 1));
    
    //On met toutes les variables à 0 (ou NULL) (pour être sûr)
    nat->something = 0;

    return nat;
}

/* Crée une structure nat_logs */
struct nat_logs * init_nat_logs()
{
    struct nat_logs * nat_logs;
    CHECK(nat_logs = calloc(sizeof(struct nat_logs), 1));
    
    //On met toutes les variables à 0 (ou NULL) (pour être sûr)
    nat_logs->nat = NULL;
    nat_logs->logs = NULL;    

    return nat_logs;
}

/* On libère la mémoire */
void free_nat_logs(struct nat_logs * nat_logs)
{
    free(nat_logs->logs);
    free(nat_logs->nat);
    free(nat_logs);
}