//Gère les arguments en entrée du programme

#include "includes/includes.h"

/* Parse les arguments et vérifie leur cohérence */
struct args parse_args(int argc, char *argv[])
{
    int opt;

    struct args args = {
        .interface = NULL,
        .file = NULL,
        .filter = NULL,
        .verbose = 1
    };

    while((opt = getopt(argc, argv, ":i:o:f:v:")) != -1) 
    { 
        switch(opt) 
        { 
            case 'i':
                args.interface = optarg;
                break; 
            case 'o': 
                args.file = optarg;
                break; 
            case 'f': 
                args.filter = optarg;
                break; 
            case 'v': 
                args.verbose = atoi(optarg);
                break; 
            case ':': 
                fprintf(stderr, "Option %c attend une valeur\n", optopt); 
                print_help();
                exit(EXIT_FAILURE);
                break; 
            case '?': 
                fprintf(stderr, "Option inconnue: %c\n", optopt);
                print_help();
                exit(EXIT_FAILURE);
                break; 
        } 
    } 

    //On vérifie qu'il n'y pas d'arguments en plus
    for(; optind < argc; optind++){
        fprintf(stderr, "argument: %s inconnu\n", argv[optind]);
        print_help();
        exit(EXIT_FAILURE);
    }

    //On vérifie que interface et file ne sont pas renseignés en même temps
    if(args.interface != NULL && args.file != NULL){
        fprintf(stderr, "L'option -i et -o ne peuvent pas être utilisées en même temps\n");
        print_help();
        exit(EXIT_FAILURE);
    }

    //On vérifie que interface ou file est renseigné
    if(args.interface == NULL && args.file == NULL){
        fprintf(stderr, "L'option -i ou -o doit être utilisée\n");
        print_help();
        exit(EXIT_FAILURE);
    }

    //On vérifie que le fichier existe
    if(args.file != NULL){
        if(access(args.file, F_OK) == -1){
            fprintf(stderr, "Le fichier %s n'existe pas\n", args.file);
            print_help();
            exit(EXIT_FAILURE);
        }
    }

    //On vérifie que le niveau de verbosité est correct
    if(args.verbose < 1 || args.verbose > 3){
        fprintf(stderr, "Le niveau de verbosité doit être compris entre 1 et 3\n");
        print_help();
        exit(EXIT_FAILURE);
    }

    return args;
}

/* Affiche le message d'usge de la commande */
void print_help()
{
    fprintf(stderr, "Usage: analyzer [-i interface] [-o fichier] [-f filtre] [-v niveau]\n");
    fprintf(stderr, "Options:\n");
    fprintf(stderr, "-i <interface>\tInterface pour l'analyse live\n");
    fprintf(stderr, "-o <fichier>\tFichier d'entrée pour l'analyse offline\n");
    fprintf(stderr, "-f <filtre>\tFiltre BPF\n");
    fprintf(stderr, "-v <niveau>\tNiveau de verbosité (1=très concis ; 2=synthétique ; 3=complet)\n");
}