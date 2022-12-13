#include "includes/includes.h"


pcap_t *handler = NULL;

/* Ouvre un handler de socket pour la capture de paquets */
pcap_t *init_handler(struct args args)
{
    char error[PCAP_ERRBUF_SIZE];
    pcap_t *handle;

    if(args.interface != NULL)
        handle = pcap_open_live(args.interface, BUFSIZ, 1, 1000, error);
    else
        handle = pcap_open_offline(args.file, error);
        
    
    if(handle == NULL)
    {
        fprintf(stderr, "Impossible d'ouvrir le handler: %s\n", error);
        exit(EXIT_FAILURE);
    }

    //On set le filtre
    if(args.filter != NULL){

        //On compile le filtre
        struct bpf_program filter;
        if(pcap_compile(handle, &filter, args.filter, 0, PCAP_NETMASK_UNKNOWN) == -1){
            fprintf(stderr, "Impossible de compiler le filtre: %s\n", pcap_geterr(handle));
            exit(EXIT_FAILURE);
        }

        if(pcap_setfilter(handle, &filter) == -1){
            fprintf(stderr, "Impossible d'appliquer le filtre: %s\n", pcap_geterr(handle));
            exit(EXIT_FAILURE);
        }
    }

    return handle;
}

/* Termine proprement le handler */
void end_analyze()
{
    printf("Bye !\n");
    pcap_close(handler);
    exit(0);
}

/*  Boucle principale de l'appli, Analyse un paquet reçu */
void compute_paquet(struct args *args, struct pcap_pkthdr *meta, const u_char *data)
{
    (void)args; // On n'utilise pas les arguments

    //On initialise la structure de paquet (qui contient les infos du paquet)
    struct pck_t * pck = init_pck(data, meta);

    //On traite le paquet
    compute_pck(pck);

    //On affiche le paquet
    logger_print(pck);

    //On libère la mémoire
    free_pck(pck);
}

int main(int argc, char *argv[])
{
    //On récupère les arguments
    struct args args = parse_args(argc, argv);

    //On initilise pcap
    handler = init_handler(args);

    //On déclare le handler (pour le CTRL+C)
    signal(SIGINT, end_analyze);

    //On initialise le printer
    logger_init(args.verbose);

    //On lance la capture
    int count = 0;
    if(pcap_loop(handler, count, (pcap_handler)compute_paquet, (u_char*)&args) == PCAP_ERROR){
        fprintf(stderr, "Erreur lors de la capture: %s\n", pcap_geterr(handler));
        return EXIT_FAILURE;
    }

    //On ferme le logger
    logger_end();
      
    return EXIT_SUCCESS;
}