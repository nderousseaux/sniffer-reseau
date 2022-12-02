#include "./includes/dns.h"

//Lit un str dans les données (utilise le c0 pour pointer vers une autre zone)
void read_str(char* str, const u_char **data, const u_char **pck){
    int i = 0;
    //On lit jusqu'à la fin de chaine
    while(**data != 0){

        //Si on tombe sur un c0, on lit l'adresse pointée
        if(**data == 0xc0){
            *data += 2;
            //On crée un nouveau pointeur pour ne pas modifier le pointeur de départ
            const u_char *new_data = *pck + *(*data-1) + 42;
            char *new_str = malloc(256);
            read_str(new_str, &new_data, pck);
            //Si la chaine n'est pas vide, on ajoute un point
            if(strlen(str) != 0){
                strcat(str, ".");
            }
            //On concatène les deux chaines
            strcat(str, new_str);
            free(new_str);

            //On donne à i la valeur de la taille de la chaine
            return;
        }
        //Si c'est un 0x03 on ajoute un point
        else if(**data == 0x03){
            str[i] = '.';
            i++;
        }
        else { //Sinon on ajoute le caractère
            str[i] = **data;
            i++;
        }
        (*data)++;
    }
    str[i] = '\0';
    
    (*data)++;
}

/* Stocke une requête dns */
void read_dns_query(struct dns_query_t *query, const u_char **data, const u_char **pck)
{ 
    int type;
    int class;
    query->name = malloc(sizeof(char)*256);
    query->type = malloc(sizeof(char)*10);
    query->class = malloc(sizeof(char)*10);
    read_str(query->name, data, pck);
    
    // On stocke le type de la query
    type = ntohs(*((uint16_t *)*data));
    switch(type){
        case 1:
            query->type = "A";
            break;
        case 2:
            query->type = "NS";
            break;
        case 5:
            query->type = "CNAME";
            break;
        case 6:
            query->type = "SOA";
            break;
        case 12:
            query->type = "PTR";
            break;
        case 15:
            query->type = "MX";
            break;
        case 16:
            query->type = "TXT";
            break;
        case 28:
            query->type = "AAAA";
            break;
        case 251:
            query->type = "IXFR";
            break;
        default:
            query->type = UNKNOWN;
            break;
    }
    
    *data += 2;
    class = ntohs(*((uint16_t *)*data));
    // On stocke la classe de la query
    switch(class){
        case 1:
            query->class = "IN";
            break;
        case 2:
            query->class = "CS";
            break;
        case 3:
            query->class = "CH";
            break;
        case 4:
            query->class = "HS";
            break;
        default:
            query->class = UNKNOWN;
            break;
    }
    *data += 2;
}

/* Stocke une réponse dns */
void read_dns_answer(struct dns_answer_t *ans, const u_char **data, const u_char **pck)
{
    read_dns_query((struct dns_query_t *)ans, data, pck);

    //On récupère le ttl
    ans->ttl = ntohl(*((uint32_t *)*data));
    *data += 4;

    //On récupère la taille de la réponse
    ans->data_len = ntohs(*((uint16_t *)*data));
    *data += 2;

    //On copie le pointeur
    const u_char *data_copy = *data;
    //On incrémente le pointeur pour passer à la prochaine réponse
    *data += ans->data_len;

    //On récupère la réponse
    //Si c'est de type A
    if(strcmp(ans->type, "A") == 0){
        ans->main_info = malloc(sizeof(char)*16);
        sprintf(ans->main_info, "%d.%d.%d.%d", data_copy[0], data_copy[1], data_copy[2], data_copy[3]);
    }    
    //Si c'est de type NS, ou CNAME ou PTR
    else if(strcmp(ans->type, "NS") == 0 || strcmp(ans->type, "CNAME") == 0 || strcmp(ans->type, "PTR") == 0){
        ans->main_info = malloc(sizeof(char)*256);
        read_str(ans->main_info, &data_copy, pck);
    }
    //Si c'est de type SOA, on lit les 5 champs
    else if(strcmp(ans->type, "SOA") == 0){
        ans->main_info = malloc(sizeof(char)*256);
        read_str(ans->main_info, &data_copy, pck);
        ans->responsible_mail = malloc(sizeof(char)*256);
        read_str(ans->responsible_mail, &data_copy, pck);
        ans->serial = ntohl(*((uint32_t *)data_copy));
        data_copy += 4;
        ans->refresh = ntohl(*((uint32_t *)data_copy));
        data_copy += 4;
        ans->retry = ntohl(*((uint32_t *)data_copy));
        data_copy += 4;
        ans->expire = ntohl(*((uint32_t *)data_copy));
        data_copy += 4;
        ans->minimum = ntohl(*((uint32_t *)data_copy));
        data_copy += 4;
    }
    //Si c'est du type MX
    else if(strcmp(ans->type, "MX") == 0){
        ans->main_info = malloc(sizeof(char)*256);
        ans->preference = ntohs(*((uint16_t *)data_copy));
        data_copy += 2;
        read_str(ans->main_info, &data_copy, pck);
    }
    //Si c'est du type TXT
    else if(strcmp(ans->type, "TXT") == 0){
        ans->main_info = "TXT record";
        ans->txt = malloc(sizeof(char)*ans->data_len);
        memcpy(ans->txt, data_copy, ans->data_len);
    }
    //Si c'est du type AAAA
    else if(strcmp(ans->type, "AAAA") == 0){
        ans->main_info = malloc(sizeof(char)*40);
        sprintf(ans->main_info, "%x:%x:%x:%x:%x:%x:%x:%x", ntohs(*((uint16_t *)data_copy)), ntohs(*((uint16_t *)(data_copy+2))), ntohs(*((uint16_t *)(data_copy+4))), ntohs(*((uint16_t *)(data_copy+6))), ntohs(*((uint16_t *)(data_copy+8))), ntohs(*((uint16_t *)(data_copy+10))), ntohs(*((uint16_t *)(data_copy+12))), ntohs(*((uint16_t *)(data_copy+14))));
    }
    //Si c'est du type IXFR
    else if(strcmp(ans->type, "IXFR") == 0){
        ans->main_info = "IXFR record";
    }
    else{
        ans->main_info = UNKNOWN;
    }
}