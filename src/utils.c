// Fonctions utiles

#include "includes/includes.h"

/* Renvoie une chaine de caractère correspondant au temps écoulé depuis un temps de référence */
char * interval(struct timeval *ref, struct timeval *now)
{
    char * str;
    CHECK(str = calloc(128, sizeof(char)));
    //On calcule le temps écoulé
    int sec = now->tv_sec - ref->tv_sec;
    int usec = now->tv_usec - ref->tv_usec;
    //Si les microsecondes sont négatives, on les ajoute à la seconde
    if (usec < 0) {
        usec += 1000000;
        sec--;
    }

    //On affiche le temps
    sprintf(str, "%d.%06d", sec, usec);

    return str;
}

/* Renvoie une chaine de manière à ce qu'elle prenne exactement x caractères */
/* Remplit par des \t et des espaces si trop courte */
/* Tronquée, et conclue par "..." si trop longue */
/* Compte les caractères ─, ┌, ┐, etc... comme 1 caractère */
char * str_exact_len(char *str, int x)
{

    char * str_dst;
    CHECK(str_dst = calloc(2048, sizeof(char)));
    //On calcule la longueur de la chaine
    int len = strlen_special(str);
    //Si la chaine est trop longue, on la tronque
    if (len > x) {

        //On tronque la chaine
        strncpy(str_dst, str, strlen(str) - (len - x) - 3);
        str_dst[strlen(str) - (len - x) - 3] = '.';
        str_dst[strlen(str) - (len - x) - 2] = '.';
        str_dst[strlen(str) - (len - x) - 1] = '.';
        str_dst[strlen(str) - (len - x)] = '\0';
    }

    //Si la chaine est trop courte, on la complète
    else {
        strncpy(str_dst, str, 2048);
        for (int i = 0; i < x - len; i++) {
            strcat(str_dst, " ");
        }
    }

    return str_dst;
}

/* Calcule la longueur de la chaine */
/* Compte les caractères ─, ┌, ┐, etc... comme 1 caractère */
/* Compte la couleur ansi comme 0 caractères */
int strlen_special(char *str)
{
    //On compte les caracères couleurs
    int nb_color = 0;
    int i = 0;
    while (str[i] != '\0') {
        if (str[i] == '\033') {
            while (str[i] != 'm') {
                i++;
                nb_color++;
            }
            nb_color++;
        }
        i++;
    }

    //On compte les caractères spéciaux
    //On affiche les code ascii de chaque caractère
    i = 0;
    int nb_special = 0;
    char * str_tmp = str;
    while(*str_tmp != '\0') {
        if((*str_tmp < 32 || *str_tmp > 126) && *str_tmp != '\033')
            nb_special++;
        str_tmp++;
    }
    nb_special/=3;
    return strlen(str) - nb_color - 2*nb_special;
}

/* Transforme un int en string */
char * int_to_str(int x)
{
    char * str;
    CHECK(str = calloc(128, sizeof(char)));
    sprintf(str, "%d", x);
    return str;
}

/* Convertit une addresse mac en char */
char * ether_to_string(struct ether_addr *ether)
{   
    char * str;
    CHECK(str = calloc(18, sizeof(char)));
    strcpy(str, ether_ntoa(ether));
    if (strcmp(str, "ff:ff:ff:ff:ff:ff") == 0)
        strcpy(str, BROADCAST);
    else if (strcmp(str, "0:0:0:0:0:0") == 0)
        strcpy(str, UNSPECIFIED);

    return str;
}

/* Convertit une addresse ip en char */
char *ip_to_string(struct in_addr *ip)
{
    char * str;
    CHECK(str = calloc(16, sizeof(char)));
    strcpy(str, inet_ntoa(*ip));
    if (strcmp(str, "0.0.0.0") == 0)
        strcpy(str, UNSPECIFIED);
    else if (strcmp(str, "255.255.255.255") == 0)
        strcpy(str, BROADCAST);
    else if (strcmp(str, "127.0.0.1") == 0)
        strcpy(str, LOOPBACK);
    return str;
}

/* Convertit une addresse ip6 en char */
char *ip6_to_string(struct in6_addr *ip6)
{
    char * str;
    CHECK(str = calloc(46, sizeof(char)));
    inet_ntop(AF_INET6, ip6, str, 46);
    if (strcmp(str, "::") == 0)
        strcpy(str, UNSPECIFIED);
    else if (strcmp(str, "::1") == 0)
        strcpy(str, LOOPBACK);

    return str;
}

/* Inverse la position des octets */
int flip_octets(int x)
{
    int y = (x & 0xFF) << 24 | (x & 0xFF00) << 8 | (x & 0xFF0000) >> 8 | (x & 0xFF000000) >> 24;
    //On le décale vers la droite de 4 bits
    return (y >> 16) & 0xFFFF;
}

/* Convertit des données en str */
char * str_by_hex(unsigned char * data, int len)
{
    char * str;
    CHECK(str = calloc(2048, sizeof(char)));
    for (int i = 0; i < len; i++) {
        sprintf(str, "%s%02x ", str, data[i]);
    }
    return str;
}

/* Convertit une chaine en chaine imprimable (\r\n\t ) */
void printable_str(char * str)
{
    char * new_str;
    CHECK(new_str = calloc(strlen(str), 2));
    for(unsigned int i = 0; i < strlen(str); i++)
    {
        if(str[i] == '\n')
            sprintf(new_str+strlen(new_str), "\\n");
        else if (str[i] == '\r')
            sprintf(new_str+strlen(new_str), "\\r");
        else if (str[i] == '\t')
            sprintf(new_str+strlen(new_str), "\\t");
        else if (str[i] == '\003')
            sprintf(new_str+strlen(new_str), "\\003");
        else
            sprintf(new_str+strlen(new_str), "%c", str[i]);
    }
    strcpy(str, new_str);
    free(new_str);
}