// Gère un paquet ethernet
#ifndef H_GL_ETH
#define H_GL_ETH


struct ether_info {
    struct ether_header *eth;   // Entête ethernet
    char                *infos; // Informations résumant le paquet
    struct arp_info     *arp;   // Paquet arp
    struct ipv4_info    *ipv4;  // Paquet ipv4
    // struct ipv6_info    *ipv6;  // Paquet ipv6
};

/* Traite un paquet ethernet */
void compute_ethernet(const u_char **pck);

/* Définit les variables du printer pour ethernet */
void set_printer_ethernet(struct ether_header *eth);

/* On libère la mémoire */
void free_ether_info(struct ether_info *eth_info);

#endif // H_GL_ETH