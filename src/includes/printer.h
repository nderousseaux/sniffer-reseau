//Recense les fonctions d'affichage

#ifndef H_GL_PRINTER
#define H_GL_PRINTER

#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "utils.h"

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
void printer_footer();

/* Initialise le print pour le paquet courrant */
void printer_init_current(const struct pcap_pkthdr *meta);

/* Get le paquet */
struct paquet_info *get_paquet_info();

/* Affiche le paquet */
void print();

/* Affiche le paquet verbose 1*/
void print_v1();

#endif // H_GL_PRINTER