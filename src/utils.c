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

/* Renvoie une version printable des x octets du paquet */
char * printable_pck(const u_char *pck, int x)
{
    char * str;
    CHECK(str = malloc(x*10));
    for(int i = 0; i < x; i+=16)
    {
        //On affiche l'adresse en couleur et en gras
        sprintf(str, "%s\033[1;90m%04x\033[0m  ", str, i);
        // sprintf(str+strlen(str), "%04x   ", i);

        //On affiche les 16 octets
        for(int j = 0; j < 16; j++)
        {
            sprintf(str+strlen(str), "%02x ", pck[i+j]);
            if (j == 7)
                sprintf(str+strlen(str), " ");
        }        

        sprintf(str+strlen(str), "  ");

        //On affiche la couleur
        sprintf(str+strlen(str), "\033[90m");
        //On affiche les caractères
        for(int j = 0; j < 16; j++)
        {
            if(pck[i+j] >= 32 && pck[i+j] <= 126)
                sprintf(str+strlen(str), "%c", pck[i+j]);
            else
                sprintf(str+strlen(str), ".");
            
            if (j == 7)
                sprintf(str+strlen(str), " ");
        }
        sprintf(str+strlen(str), "\033[0m");

        //On saute la ligne
        sprintf(str+strlen(str), "\n");
    }
    (void)pck;
    return str;
}