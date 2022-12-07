// Gère un paquet tcp
#ifndef H_GL_TCP
#define H_GL_TCP

struct tcp_info_2 { //Car il existe déjà une structure tcp_info
    struct tcphdr       *tcp;      // Header tcp
    char                *infos;    // Informations sur le paquet
    enum {TELNET, PURE_TCP, FTP}       type;     // Type de paquet
    struct telnet_info  *telnet;   // Informations sur le paquet telnet
    struct ftp_info     *ftp;      // Informations sur le paquet ftp
};

/* Traite un paquet tcp */
void compute_tcp(const u_char **pck);

/* Définit les variables du printer pour tcp */
void set_printer_tcp(struct tcphdr *tcp);

/* On libère la mémoire */
void free_tcp_info(struct tcp_info_2 *tcp_info);

#endif // H_GL_TCP
