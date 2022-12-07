// Gère un paquet ftp
#ifndef H_GL_FTP
#define H_GL_FTP

struct ftp_info {
    struct ftp_t        *ftp; //Entête ftp
    char                *infos; //Informations résumant le paquet
};

struct ftp_t {
    enum {
        FTP_REQUEST,
        FTP_RESPONSE
    } type;
    //Request
    char * request_command;
    char * request_arg;

    //Response
    char * response_code;
    char * response_arg; 
};

/* Traite un paquet ftp */
void compute_ftp(const u_char **pck, char is_request);

/* Définit les variables du printer pour ftp */
void set_printer_ftp(struct ftp_t *ftp);

/* On libère la mémoire */
void free_ftp_info(struct ftp_info *ftp_info);

#endif // H_GL_FTP