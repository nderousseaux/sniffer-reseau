//Recense les fonctions d'affichage

#include "./includes/printer.h"

int verbose_level = 1;          //Niveau de verbosité
int nb_frames = 0;              // Nombre de frames analysées
struct timeval *ts;             // Heure du premier paquet
struct paquet_info *paquet;     // Structure d'affichage

/* Initialise le printer */
void printer_init(int vl)
{
    verbose_level = vl;

    //On affiche l'entête
    switch (verbose_level)
    {
        case 1:
            printf("╔═══════╤═══════════════╤═══════════════════════╤═══════════════════════╤═══════╤═══════╤═════════════════════════════════════════════════════════════════╗\n");
            printf("║ No.\t│ Time\t\t│ Source\t\t│ Destination\t\t│ Proto\t│ Len\t│ Informations\t\t\t\t\t\t\t  ║\n");
            printf("╠═══════╪═══════════════╪═══════════════════════╪═══════════════════════╪═══════╪═══════╪═════════════════════════════════════════════════════════════════╣\n");
            break;
        default:
            break;
    }
}

/* Affiche le footer */
void printer_footer()
{
    //On affiche le footer
    switch (verbose_level)
    {
        case 1:
            printf("╚═══════╧═══════════════╧═══════════════════════╧═══════════════════════╧═══════╧═══════╧═════════════════════════════════════════════════════════════════╝\n");
            printf("Nombre de paquets analysés : %d\n", nb_frames);
            break;
        default:
            break;
    }
}

/* Initialise le print pour le paquet courrant */
void printer_init_current(const struct pcap_pkthdr *meta)
{
    CHECK(paquet = malloc(sizeof(struct paquet_info)));

    //Si c'est la première frame, on enregistre le temps 0 (secondes et microsecondes)
    if (nb_frames == 0){
        ts = malloc(sizeof(struct timeval));
        ts->tv_sec = meta->ts.tv_sec;
        ts->tv_usec = meta->ts.tv_usec;
    }
    
    paquet->meta = meta;

    //On initialise les chaines
    CHECK(paquet->src = malloc(20));
    CHECK(paquet->dst = malloc(20));
    CHECK(paquet->protocol = malloc(10));
    CHECK(paquet->infos = malloc(255));
}

/* Get le paquet */
struct paquet_info *get_paquet_info(){
    return paquet;
}

/* Affiche le paquet */
void print(){
    //On affiche le paquet
    switch (verbose_level)
    {
        case 1:
            print_v1();
            break;
        default:
            break;
    }
    printf("\n");

    nb_frames++;
    free(paquet);
}

/* Affiche le paquet verbose 1*/
void print_v1()
{
    //On affiche le numéro de la frame
    printf("║ %d\t", nb_frames);

    //On affiche le temps
    //On soustrait le temps 0 au temps de la frame
    int sec = paquet->meta->ts.tv_sec - ts->tv_sec;
    int usec = paquet->meta->ts.tv_usec - ts->tv_usec;
    //Si les microsecondes sont négatives, on les ajoute à la seconde
    if (usec < 0) {
        usec += 1000000;
        sec--;
    }
    printf("│ %d.%06d\t", sec, usec);

    //On affiche la source
    printf("│ %s\t", paquet->src);
    if (strlen(paquet->src) < 14)
        printf("\t");

    //On affiche la destination
    printf("│ %s\t", paquet->dst);
    if (strlen(paquet->dst) < 14)
        printf("\t");


    //On affiche le protocole
    printf("│ %s\t", paquet->protocol);

    //On affiche la longueur
    printf("│ %d\t", paquet->meta->len);

    //Si les infos dépassent la taille de la colonne, on les coupe et on rajoute des points de suspension
    unsigned int taille_colonne = 61;
    if (strlen(paquet->infos) > taille_colonne)
    {
        char *infos = malloc(taille_colonne);
        strncpy(infos, paquet->infos, taille_colonne);
        infos[taille_colonne] = '\0';
        printf("│ %s...", infos);
        free(infos);
    }
    else
    {
        printf("│ %s", paquet->infos);
    }
    //On rajoute des espaces pour remplir la colonne
    for (unsigned int i = strlen(paquet->infos); i < taille_colonne+3; i++)
    {
        printf(" ");
    }
    printf("║");
}