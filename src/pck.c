// Contient les structures et fonctions pour stocker les informations du paquet
#include "includes/includes.h"

/* Initialise une structure pck */
struct pck_t *init_pck(const u_char *pck, struct pcap_pkthdr *meta)
{
    struct pck_t *pck_info;
    CHECK(pck_info = malloc(sizeof(struct pck_t)));
    pck_info->pck_original = pck;
    pck_info->data = pck;
    pck_info->meta = meta;
    pck_info->log = init_log(pck_info);
    pck_info->nb_incr = 0;
    return pck_info;
}

/* Déplace le pointeur de i octets, sur la structure pck. Renvoie le nombre d'octets décalés */
int shift_pck(struct pck_t *pck, int i)
{
    // Nouvelle longueur
    int len = pck->nb_incr + i;

    // Si la longueur est supérieure à la longueur du paquet, on décale de la longueur du paquet
    if ((unsigned int)len > pck->meta->len)
        i = pck->meta->len - pck->nb_incr;
    
    // On décale le pointeur
    pck->data += i;
    pck->nb_incr += i;
    return i;
}

/* Libère la structure pck */
void free_pck(struct pck_t *pck)
{
    if (pck == NULL) return;
    free_log(pck->log);
    free(pck);
}