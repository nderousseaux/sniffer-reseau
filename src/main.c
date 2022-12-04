#include <pcap.h>
#include <signal.h>
#include <stdlib.h>

#include "includes/args.h"
#include "includes/sniffer.h"
#include "includes/printer.h"

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
    printer_footer();
      
    return EXIT_SUCCESS;
}