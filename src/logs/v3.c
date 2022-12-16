// Fonctions d'afficage des logs, pour le verbose = 3
#include "../includes/includes.h"

/* Affiche le log */
void logger_print_3(struct logger_info_t * logger_info, struct pck_t *pck)
{
    char * title = logger_title(pck, logger_info);

    //On affiche l'entête du paquet
    printf("╔══ %s ", title);
    for(unsigned int i = 0; i < SIZE_TERM - strlen(title) + 1; i++) printf("═");
    printf("═╗\n");

    
    //On affiche une ligne vide
    printf("║");
    for(unsigned int i = 0; i < SIZE_TERM - 2; i++) printf(" ");
    printf("║\n");

    //On affiche les données
    struct log_v3_t * log_v3 = get_log_v3_line(pck);

    while (log_v3 != NULL){
        printf("║ %s ║\n", str_exact_len(log_v3->log, SIZE_TERM - 4));
        log_v3 = log_v3->next;
    }


    //On affiche une ligne vide
    printf("║");
    for(unsigned int i = 0; i < SIZE_TERM - 2; i++) printf(" ");
    printf("║\n");

    //On affiche le footer
    printf("╚");
    for(unsigned int i = 0; i < SIZE_TERM - 2; i++) printf("═");
    printf("╝\n");

    printf("\n");
    free(title);
    free_log_v3(log_v3);
}

/* Crée une strucure log_v3 totale (somme de log_v3 str et log_v3_data)*/
struct log_v3_t * get_log_v3_line(struct pck_t *pck)
{
    struct log_v3_t * log_v3_str = get_log_v3_str(pck);
    struct log_v3_t * log_v3_data = get_log_v3_data(pck);
    struct log_v3_t * log_v3 = NULL;

    //On met la première ligne de log_v3_str dans log_v3
    add_log_v3(&log_v3, log_v3_str->log);
    log_v3_str = log_v3_str->next;

    while (log_v3_str != NULL && log_v3_data != NULL){
        char * log;
        CHECK(log = calloc(2048, sizeof(char)));

        //On concatène les deux lignes
        sprintf(log, "%s   %s", log_v3_str->log, log_v3_data->log);

        add_log_v3(&log_v3, log);
        log_v3_str = log_v3_str->next;
        log_v3_data = log_v3_data->next;
        free(log);
    }
    while(log_v3_str != NULL){
        add_log_v3(&log_v3, log_v3_str->log);
        log_v3_str = log_v3_str->next;
    }
    while(log_v3_data != NULL){
        char * data_only;
        CHECK(data_only = calloc(2048, sizeof(char)));

        for(int i = 0; i < SIZE_SECONDARY_CASE + 5; i++) strcat(data_only, " ");
        strcat(data_only, log_v3_data->log);

        add_log_v3(&log_v3, data_only);
        log_v3_data = log_v3_data->next;
    }

    free_log_v3(log_v3_str);
    free_log_v3(log_v3_data);
    return log_v3;
}

/* Crée une structure log_v3, contenant chaque ligne des données */
struct log_v3_t * get_log_v3_str(struct pck_t *pck)
{
    struct log_v3_t * log_v3 = NULL;

    // Pour chaque couche, on enregistre l'entête, les données, et le footer
    // Couche liaison
    if(pck->log->ll != NULL && pck->log->ll->log != NULL && strlen(pck->log->ll->log) > 0)
        add_layer_log_v3(&log_v3, "Liaison", pck->log->ll->log_v3, pck->log->ll->log, COLOR_LL);

    // Couche réseau
    if(pck->log->nl != NULL && pck->log->nl->log != NULL && strlen(pck->log->nl->log) > 0)
        add_layer_log_v3(&log_v3, "Network", pck->log->nl->log_v3, pck->log->nl->log, COLOR_NL);

    // Couche transport
    if(pck->log->tl != NULL && pck->log->tl->log != NULL && strlen(pck->log->tl->log) > 0)
        add_layer_log_v3(&log_v3, "Transport", pck->log->tl->log_v3, pck->log->tl->log, COLOR_TL);

    return log_v3;
}

/* Remplit la strucuture log_v3, pour une couche entière */
void add_layer_log_v3(struct log_v3_t ** log_v3, char * name, struct log_v3_t * data, char * log, int color)
{
    // On enregistre l'entête
    add_header_log_v3(log_v3, name, log, color);

    //On ajoute une ligne vide
    add_line_log_v3(log_v3, "");

    // On enregistre les données
    struct log_v3_t * log_v3_l = data;
    while(log_v3_l != NULL){
        //On enregistre les données 
        add_line_log_v3(log_v3, log_v3_l->log);

        log_v3_l = log_v3_l->next;
    }
    add_line_log_v3(log_v3, "");

    // On enregistre le footer
    char * footer;
    CHECK(footer = calloc(2048, sizeof(char)));
    sprintf(footer, "└");
    for(int i = 0; i < SIZE_SECONDARY_CASE; i++) strcat(footer, "─");
    strcat(footer, "┘");
    add_log_v3(log_v3, footer);
    free(footer);
}

/* Crée une strucutre log_v3, contenant chaque ligne la version hexa du paquet */
struct log_v3_t * get_log_v3_data(struct pck_t *pck)
{
    char * data = printable_pck(pck);

    //On répartit chaque ligne de data dans une structure log_v3
    struct log_v3_t * log_v3 = NULL;
    char * line = strtok(data, "\n");
    while(line != NULL){
        add_log_v3(&log_v3, line);
        line = strtok(NULL, "\n");
    }

    free(data);
    return log_v3;
}

/* Enregistre l'entête d'une couche dans log_v3 */
void add_header_log_v3(struct log_v3_t ** log_v3, char * title, char * data, int color)
{
    char * header;
    CHECK(header = calloc(2048, sizeof(char)));
    sprintf(
        header,
        "┌─ %s ",
        logger_proto_title(title, data, color)
    );
    int len_header = strlen_special(header);
    for(int i = 0; i < SIZE_SECONDARY_CASE - len_header +1; i++) sprintf(header, "%s─", header);
    if (len_header >= SIZE_SECONDARY_CASE){
        //On tronque le titre et on rajoute des points de suspension
        header[SIZE_SECONDARY_CASE + 11] = '.';
        header[SIZE_SECONDARY_CASE + 12] = '.';
        header[SIZE_SECONDARY_CASE + 13] = '.';
        header[SIZE_SECONDARY_CASE + 14] = '\0';

    }
    sprintf(header, "%s┐", header);

    // On enregistre l'entête
    add_log_v3(log_v3, header);

    free(header);
}

/* Enregistre une ligne d'une couche dans log_v3 */
void add_line_log_v3(struct log_v3_t ** dst, char * src)
{
    char * line;
    CHECK(line = calloc(2048, sizeof(char)));
    sprintf(
        line,
        "│ %s ",
        src
    );
    
    line = str_exact_len(line, SIZE_SECONDARY_CASE +1);
    sprintf(line, "%s│", line);

    // On enregistre l'entête
    add_log_v3(dst, line);

    free(line);
}

/* Renvoie une version printable du paquet */
char * printable_pck(struct pck_t * pck)
{
    int x = pck->meta->len;
    const u_char * data = pck->pck_original;
    char * str;

    int color = 0;
    int next_offset = 0;
    CHECK(str = malloc(x*100));
    for(int i = 0; i < x; i+=16)
    {
        choose_color(i, pck, &color, &next_offset);

        //On affiche l'adresse en couleur et en gras
        sprintf(str, "%s\033[1;90m%04x\033[0m  ", str, i);

        //On commence avec la couleur de la couche
        sprintf(str+strlen(str), "\033[3%dm", color);

        //On affiche les 16 octets
        for(int j = 0; j < 16; j++)
        {
            if(i + j >= x) {
                sprintf(str+strlen(str), "   ");
                continue;
            }

            if(i + j >= next_offset){
                //On finit la couleur
                sprintf(str+strlen(str), "\033[0m");

                //On change de couleur
                choose_color(i+j, pck, &color, &next_offset);
                sprintf(str+strlen(str), "\033[3%dm", color);
            }
            sprintf(str+strlen(str), "%02x ", data[i+j]);
            if (j == 7)
                sprintf(str+strlen(str), " ");
        }        

        //Fin de la couleur
        sprintf(str+strlen(str), "\033[0m");
        sprintf(str+strlen(str), "  ");

        //On affiche la couleur
        choose_color(i, pck, &color, &next_offset);

        sprintf(str+strlen(str), "\033[3%d;2m", color);
        //On affiche les caractères
        for(int j = 0; j < 16; j++)
        {
            if(i + j >= x) {
                sprintf(str+strlen(str), " ");
                continue;
            }
            if(i + j >= next_offset){
                //On finit la couleur
                sprintf(str+strlen(str), "\033[0m");

                //On change de couleur
                choose_color(i+j, pck, &color, &next_offset);
                sprintf(str+strlen(str), "\033[3%d;2m", color);
            }
            if(data[i+j] >= 32 && data[i+j] <= 126)
                sprintf(str+strlen(str), "%c", data[i+j]);
            else
                sprintf(str+strlen(str), ".");
            
            if (j == 7)
                sprintf(str+strlen(str), " ");
        }
        sprintf(str+strlen(str), "\033[0m");

        //On saute la ligne
        sprintf(str+strlen(str), "\n");
    }
    (void) color;
    return str;
}

// Met dans color la nouvelle couleur à utiliser, et dans offset_next l'offset de la prochaine couche
void choose_color(int x, struct pck_t *pck, int * color, int * offset_next)
{
    //On détermine la couleur à utiliser
    if(pck->log->ll != NULL && x < pck->log->ll->offset) {
        *color = COLOR_LL;
        *offset_next = pck->log->ll->offset;
    }
    else if(pck->log->nl != NULL && x < pck->log->nl->offset) {
        *color = COLOR_NL;
        *offset_next = pck->log->nl->offset;
    }
    else if(pck->log->tl != NULL && x < pck->log->tl->offset) {
        *color = COLOR_TL;
        *offset_next = pck->log->tl->offset;
    }
    else {
        *color = COLOR_DATA;
        *offset_next = pck->meta->len;
    }
}

/* Initialise le printer */
void logger_init_3(){
}

/* On finit le printer */
void logger_end_3()
{
}