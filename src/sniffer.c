//Boucle principale de l'appli, redirige vers les fonctions de traitement de chaque protocole

#include "includes/includes.h"

const u_char *packet;
int nb_incr = 0;

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

/* Analyse un paquet reçu */
void compute_paquet(struct args *args, const struct pcap_pkthdr *meta, const u_char *pck)
{
    (void)args;
    //On enregistre le paquet
    packet = pck;
    //On remet le compteur de décalage à 0
    nb_incr = 0;
    
    //On initialise le printer
    printer_init_current(meta);

    //On traite le paquet
    compute_ethernet(&pck);

    //On affiche le paquet
    print();
    //On libère la mémoire
    free_paquet_info();
}

/* Get le paquet original */
const u_char **get_paquet(){
    return &packet;
}


/* Déplace le pointeur de i octets, sur le pointeur pck. Renvoie 0 si on a atteint la taille du packet */
int incr_pck(const u_char **pck, int i)
{   
    unsigned int len = (unsigned int) nb_incr + i;
    if(len > get_paquet_info()->meta->len)
        return 0;
    
    *pck += i;
    nb_incr += i;
    return i;
}

/* Renvoie le nombre d'octet restant à analyser */
int get_remaining_bytes()
{
    return get_paquet_info()->meta->len - nb_incr;
}

