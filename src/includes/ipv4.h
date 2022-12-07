// Gère un paquet ipv4
#ifndef H_GL_IPV4
#define H_GL_IPV4


struct ipv4_info {
    struct ip           *ipv4;  //Entête IP
    char                *infos; //Informations résumant le paquet
    struct udp_info     *udp;   //Informations UDP
    struct tcp_info_2   *tcp;   //Informations TCP
    struct icmp_info    *icmp;  //Informations ICMP
};

/* Traite un paquet ipv4 */
void compute_ipv4(const u_char **pck);

/* Définit les variables du printer pour ipv4 */
void set_printer_ipv4(struct ip *ipv4);

/* On libère la mémoire */
void free_ipv4_info(struct ipv4_info *ipv4_info);

#endif // H_GL_IPV4