// Gère un paquet icmp
#ifndef H_GL_ICMP
#define H_GL_ICMP


struct icmp_info {
    struct icmp         *icmp;  // Entête icmp
    char                *infos; // Informations résumant le paquet
};

/* Traite un paquet icmp */
void compute_icmp(const u_char **pck);

/* Définit les variables du printer pour icmp */
void set_printer_icmp(struct icmp *icmp);

/* On libère la mémoire */
void free_icmp_info(struct icmp_info *icmp_info);

#endif // H_GL_ICMP