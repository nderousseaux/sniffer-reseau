//Recense les fonctions d'affichage

#ifndef H_GL_PRINTER
#define H_GL_PRINTER

#define SIZE_COLONE_INFO 80 // Taille de la colonne d'informations (verbose 1)

int verbose_level;      //Niveau de verbosité

int nb_frames;          // Nombre de frames analysées
struct timeval *ts;     // Heure du premier paquet

struct paquet_info {    // Structure d'affichage
    const struct pcap_pkthdr    *meta;
    int                         no;         // Numéro du paquet
    char                        *src;       // Source
    char                        *dst;       // Destination
    char                        *protocol;  // Protocole
    char                        *infos;     // Informations résumant le paquet
    struct ether_info           *eth;       // Paquet ethernet
};

#define UNKNOWN "Unknown"

/* Initialise le printer */
void printer_init(int vl);

/* Affiche le footer */
void print_footer();

/* Initialise le print pour le paquet courrant */
void printer_init_current(const struct pcap_pkthdr *meta);

/* Get le paquet */
struct paquet_info *get_paquet_info();

/* On libère la mémoire */
void free_paquet_info();

/* Affiche le paquet */
void print();

/* Affiche l'entête en verbose 1 */
void print_header_v1();

/* Affiche le footer en verbose 1 */
void print_footer_v1();

/* Affiche le paquet verbose 1*/
void print_v1();

#endif // H_GL_PRINTER