// Contient les structures et fonctions pour stocker les informations du paquet
#ifndef H_GL_PCK
#define H_GL_PCK


/* Structure stockant le paquet et ses informations */
struct pck_t {
    const u_char                *pck_original;  // Paquet original: non modifié
    const u_char                *data;          // Paquet modifié: peut être modifié par les fonctions
    struct pcap_pkthdr          *meta;          // Informations méta sur le paquet
    struct log_t                *log;           // Log du paquet, structure définie dans le log.h
    int                         nb_incr;        // Nombre d'octets décalés
};

/* Initialise une structure pck */
struct pck_t *init_pck(const u_char *pck, struct pcap_pkthdr *meta);

/* Déplace le pointeur de i octets, sur la structure pck. Renvoie le nombre d'octets décalés */
int shift_pck(struct pck_t *pck, int i);

/* Libère la structure pck */
void free_pck(struct pck_t *pck);

#endif //H_GL_PCK