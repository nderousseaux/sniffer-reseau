//Boucle principale de l'appli, redirige vers les fonctions de traitement de chaque protocole

#include "includes/sniffer.h"

const u_char *packet;

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

    return handle;
}

/* Analyse un paquet reçu */
void compute_paquet(struct args *args, const struct pcap_pkthdr *meta, const u_char *pck)
{
    (void)args;

    //On enregistre le paquet
    packet = pck;
    
    //On initialise le printer
    printer_init_current(meta);

    //On traite le paquet
    compute_ethernet(&pck);

    //On affiche le paquet
    print();

    printf("\n");
    char * str = printable_pck(packet, meta->len);
    printf("%s\n", str);

    printf("\n");

}

/* Get le paquet original */
const u_char **get_paquet(){
    return &packet;
}
