#ifndef H_GL_ARGS
#define H_GL_ARGS

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

/* Structure pour stocker les arguments */
struct args {
    char *interface;
    char *file;
    char *filter;
    int verbose;
};

/* Parse les arguments et vérifie leur cohérence */
struct args parse_args(int argc, char *argv[]);

/* Affiche le message d'usge de la commande */
void print_help();

/* Renvoie 1 si l'interface existe, 0 sinon */
int is_interface_valid(char *interface);

#endif