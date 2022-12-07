// Gère un paquet telnet
#ifndef H_GL_TELNET
#define H_GL_TELNET



enum telnet_command {
    SE = 0xF0,
    NOP = 0xF1,
    DM = 0xF2,
    BRK = 0xF3,
    IP = 0xF4,
    AO = 0xF5,
    AYT = 0xF6,
    EC = 0xF7,
    EL = 0xF8,
    GA = 0xF9,
    SB = 0xFA,
    WILL = 0xFB,
    WONT = 0xFC,
    DO = 0xFD,
    DONT = 0xFE,
    IAC = 0xFF
};

enum telnet_subcommand {
    ECHO = 1,
    SUPPRESS_GO_AHEAD = 0x03,
    STATUS = 0x05,
    TERMINAL_TYPE = 0x18,
    NEGOTIAE_WINDOW_SIZE = 0x1F,
    TERMINAL_SPEED = 0x20,
    REMOTE_FLOW_CONTROL = 0x21,
    LINEMODE = 0x22,
    DISPLAY_LOCATION = 0x23,
    ENVIRONMENT_OPTION = 0x24,
    AUTHENTICATION_OPTION = 0x25,
    ENCRYPTION_OPTION = 0x26,
    NEW_ENVIRONMENT_OPTION = 0x27,
};

struct telnet {
    char        *data; //Caractère telnet
    struct telnet_options *options;
    int        nb_options;
};

struct telnet_options {
    enum telnet_command command;
    enum telnet_subcommand subcommand; //Sous-commande telnet
    int length_data;
    char *data;
};

struct telnet_info {
    struct telnet       *telnet;      // Header telnet
    char                *infos;    // Informations sur le paquet
};

/* Traite un paquet telnet */
void compute_telnet(const u_char **pck);

/* Sauvegarde un paquet telnet de type commande */
void save_telnet_command(struct telnet *telnet, const u_char **pck);

/* Sauvegarde un paquet telnet de type données */
void save_telnet_data(struct telnet *telnet, const u_char **pck);

/* Définit les variables du printer pour telnet */
void set_printer_telnet(struct telnet *telnet);

/* Renvoie la commande telnet */
char * get_telnet_command(enum telnet_command command);

/* Renvoie la subcommande telnet */
char * get_telnet_subcommand(enum telnet_subcommand subcommand);

/* On libère la mémoire */
void free_telnet_info(struct telnet_info *telnet_info);

#endif // H_GL_TELNET
