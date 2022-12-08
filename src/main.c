#include "includes/includes.h"


pcap_t *handler = NULL;

/* Termine proprement le handler */
void end_analyze()
{
    printf("Bye !\n");
    pcap_close(handler);
    exit(0);
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
    printer_init(args.verbose);

    //On lance la capture
    int count = 0;
    if(pcap_loop(handler, count, (pcap_handler)compute_paquet, (u_char*)&args) == PCAP_ERROR){
        fprintf(stderr, "Erreur lors de la capture: %s\n", pcap_geterr(handler));
        return EXIT_FAILURE;
    }

    //On affiche le footer
    print_footer();
      
    return EXIT_SUCCESS;
}