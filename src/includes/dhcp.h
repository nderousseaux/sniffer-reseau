// Gère un paquet dhcp (et vendor specific si jamais)
#ifndef H_GL_DHCP
#define H_GL_DHCP



struct vs_info {
    struct vs_options_t   **options; // Liste des options (le type correspond à l'index)
    char                   *infos; // Informations résumant le paquet
};

struct vs_options_t {
    uint8_t     length;
    uint8_t     *value;
};

/* Traite la zone vendor specific ou dhcp */
void compute_vs(const u_char **pck);

/* Définit les variables du printer pour vendor_specific */
void set_printer_vs(struct vs_options_t **options);

/* On libère la mémoire */
void free_vs_info(struct vs_info *vs_info);

#endif // H_GL_DHCP