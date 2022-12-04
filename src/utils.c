//Fonctions utiles

#include "includes/utils.h"

/* Convertit une addresse mac en char * */
void ether_to_string(struct ether_addr *ether, char * str)
{   
    strcpy(str, ether_ntoa(ether));
    if (strcmp(str, "ff:ff:ff:ff:ff:ff") == 0)
        strcpy(str, "Broadcast");
    else if (strcmp(str, "0:0:0:0:0:0") == 0)
        strcpy(str, "Unspecified");
}

/* Convertit une addresse ipV4 en char * */
void ip_to_string(struct in_addr *ip, char * str)
{
    strcpy(str, inet_ntoa(*ip));
    if(strcmp(str, "255.255.255.255") == 0)
        strcpy(str, "Broadcast");
    else if(strcmp(str, "0.0.0.0") == 0)
        strcpy(str, "Unspecified");
}
