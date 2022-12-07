//Boucle principale de l'appli, redirige vers les fonctions de traitement de chaque protocole

#ifndef H_GL_SNIFFER
#define H_GL_SNIFFER

/* Ouvre un handler de socket pour la capture de paquets */
pcap_t *init_handler(struct args args);

/* Analyse un paquet reçu */
void compute_paquet(struct args *args, const struct pcap_pkthdr *hdr, const u_char *pck);

/* Get le paquet original */
const u_char **get_paquet();

/* Déplace le pointeur de i octets, sur le pointeur pck. Renvoie 0 si on a atteint la taille du packet */
int incr_pck(const u_char **pck, int i);

/* Renvoie le nombre d'octet restant à analyser */
int get_remaining_bytes();

#endif //H_GL_SNIFFER