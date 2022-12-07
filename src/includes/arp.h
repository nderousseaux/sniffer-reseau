// Gère un paquet arp
#ifndef H_GL_ARP
#define H_GL_ARP


struct arp_info {
    struct ether_arp    *arp;   // Entête arp
    char                *infos; // Informations résumant le paquet
};

/* Traite un paquet arp */
void compute_arp(const u_char **pck);

/* Définit les variables du printer pour arp */
void set_printer_arp(struct ether_arp *arp);

/* On libère la mémoire */
void free_arp_info(struct arp_info *arp_info);

#endif // H_GL_ARP