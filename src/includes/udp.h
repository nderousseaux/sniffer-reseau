// Gère un paquet udp
#ifndef H_GL_UDP
#define H_GL_UDP

struct udp_info {
    struct udphdr       *udp;   //Entête udp
    char                *infos; //Informations résumant le paquet
    struct dns_info     *dns;  //Entête dns
    struct bootp_info   *bootp; //Entête bootp
};

/* Traite un paquet udp */
void compute_udp(const u_char **pck);

/* Définit les variables du printer pour udp */
void set_printer_udp(struct udphdr *udp);

/* On libère la mémoire */
void free_udp_info(struct udp_info *udp_info);

#endif // H_GL_UDP