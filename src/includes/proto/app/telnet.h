// Analyse d'un paquet telnet
#ifndef TELNET_H
#define TELNET_H

#include "pck.h"

#define PRINT_TELNET "Telnet"
#define PRINT_TELNET_SHRT "TELNET"

enum telnet_command {
    SE = 0xF0,
    NOP = 0xF1,
    DM = 0xF2,
    BRK = 0xF3,
    IP_C = 0xF4,
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

struct telnet_t {
    char        *data; //Caractère telnet
    struct telnet_options_t *options;
    int        nb_options;
};

struct telnet_options_t {
    enum telnet_command command;
    enum telnet_subcommand subcommand; //Sous-commande telnet
    int length_data;
    char *data;
};

/* Analyse du paquet telnet */
void compute_telnet(struct pck_t * pck);

/* Remplit la structure telnet */
void fill_telnet(struct pck_t * pck);

/* Met à jour le log de la couche telnet */
void set_telnet_log(struct pck_t * pck);

/* Rempli les logs détaillés pour le verbose 3 */
void fill_telnet_log_v3(struct pck_t * pck);

/* Enregistre une commande telnet */
void save_telnet_command(struct telnet_t * telnet, struct pck_t * pck);

/* Enregistre des données telnet */
void save_telnet_data(struct telnet_t * telnet, struct pck_t * pck);

/* Convertit une code commande en str */
void telnet_command_str(enum telnet_command command, char * str);

/* Convertit un code subcommande en str */
void telnet_subcommand_str(enum telnet_subcommand subcommand, char * str);

/* Fonction propres aux structures */

/* Initialise une structure telnet_t */
struct telnet_t * init_telnet();

/* Libère la mémoire d'une structure telnet_t */
void free_telnet(struct telnet_t * telnet);

#endif /* TELNET_H */