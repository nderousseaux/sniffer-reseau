// Gère un paquet dns

#include "includes/dns.h"

/* Traite un paquet dns */
void compute_dns(const u_char **pck)
{
    struct dns_t *dns = malloc(sizeof(struct dns_t));

    //On récupère l'en-tête dns
    dns->header = (struct dns_header_t *) *pck;
    *pck += sizeof(struct dns_header_t);

    //On stocke chaque query
    dns->queries = malloc(sizeof(struct dns_query_t) * ntohs(dns->header->q_count));
    for (int i = 0; i < ntohs(dns->header->q_count); i++)
    {
        read_dns_query(&dns->queries[i], pck);
    }
    //On stocke chaque réponse
    dns->answers = malloc(sizeof(struct dns_answer_t) * ntohs(dns->header->ans_count));
    for (int i = 0; i < ntohs(dns->header->ans_count); i++)
    {
        read_dns_answer(&dns->answers[i], pck);
    }
    // //On stocke chaque autorité
    dns->authorities = malloc(sizeof(struct dns_answer_t)*dns->header->auth_count);
    for(int i = 0; i < ntohs(dns->header->auth_count); i++){
        read_dns_answer(&dns->authorities[i], pck);
    }
    //On stocke chaque additionnel
    dns->additionals = malloc(sizeof(struct dns_answer_t)*dns->header->add_count);
    for(int i = 0; i < ntohs(dns->header->add_count); i++){
        read_dns_answer(&dns->additionals[i], pck);
    }

    //On prépare les informations
    set_printer_dns(dns);
}

/* Définit les variables du printer pour dns */
void set_printer_dns(struct dns_t *dns)
{
    //On définit les variables
    char * type;
    char * infos;
    struct dns_info *dns_info;
    struct paquet_info *paquet_info;

    //On définit le type
    CHECK(type = malloc(100));
    if(dns->header->qr == 0)
    {
        sprintf(type, "Query");
    }
    else
    {
        sprintf(type, "Response");
    }

    //On remplit les infos principales
    CHECK(infos = malloc(1000));
    //On ajoute toutes les queries à la suite de infos
    for(int i = 0; i < ntohs(dns->header->q_count); i++)
    {
        char * query;
        CHECK(query = malloc(255));
        sprintf(
            query,
            " %s %s",
            dns->queries[i].type,
            dns->queries[i].name
        );
        strcat(infos, query);
        free(query);
    }
    //On ajoute toutes les réponses à la suite de infos
    for(int i = 0; i < ntohs(dns->header->ans_count); i++)
    {
        char * answer;
        CHECK(answer = malloc(255));
        sprintf(
            answer,
            " %s %s",
            dns->answers[i].type,
            dns->answers[i].name
        );
        strcat(infos, answer);
        free(answer);
    }

    //On remplit dns_info
    CHECK(dns_info = malloc(sizeof(struct dns_info)));
    dns_info->dns = dns;
    CHECK(dns_info->infos = malloc(strlen(infos) + 100));
    sprintf(
        dns_info->infos,
        "Domain Name System (%s) 0x%04x%s",
        type,
        ntohs(dns->header->id),
        infos
    );

    //On remplit paquet_info
    paquet_info = get_paquet_info();
    paquet_info->eth->ipv4->udp->dns = dns_info;
    sprintf(
        paquet_info->infos,
        "%s 0x%04x%s",
        type,
        ntohs(dns->header->id),
        infos
    );

}

/* Stocke une requête dns */
void read_dns_query(struct dns_query_t *query, const u_char **data)
{
    //On stocke le nom de la requête
    CHECK(query->name = malloc(256));
    read_dns_name(query->name, data);

    //On stocke le type de la requête
    CHECK(query->type = malloc(10));
    switch(ntohs(*((uint16_t*)*data)))
    {
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

    //On stocke la classe de la query
    CHECK(query->class = malloc(10));
    switch(ntohs(*((uint16_t*)*data)))
    {
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
void read_dns_answer(struct dns_answer_t *ans, const u_char **data)
{
    read_dns_query((struct dns_query_t *)ans, data);

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
        read_dns_name(ans->main_info, &data_copy);
    }
    //Si c'est de type SOA, on lit les 5 champs
    else if(strcmp(ans->type, "SOA") == 0){
        ans->main_info = malloc(sizeof(char)*256);
        read_dns_name(ans->main_info, &data_copy);
        ans->responsible_mail = malloc(sizeof(char)*256);
        read_dns_name(ans->responsible_mail, &data_copy);
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
        read_dns_name(ans->main_info, &data_copy);
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
        //TODO: Remplacer par ipv6 to string quand on aura fait la fonction
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

/* Lit un str dans les données (utilise le c0 pour pointer vers une autre zone) */
void read_dns_name(char* str, const u_char **data)
{
    //On récupère le paquet original
    const u_char **pck = get_paquet();
    
    int i = 0;
    //On lit jusqu'à la fin de chaine
    while(**data != 0){

        //Si on tombe sur un c0, on lit l'adresse pointée
        if(**data == 0xc0){
            *data += 2;
            //On crée un nouveau pointeur pour ne pas modifier le pointeur de départ
            const u_char *new_data = *pck + *(*data-1) + 42;
            char *new_str = malloc(256);
            read_dns_name(new_str, &new_data);
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
        //Si c'est non imprimable, on ajoute un point
        else if(**data < 32 || **data > 126){
            if (i != 0){
                str[i] = '.';
                i++;
            }
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