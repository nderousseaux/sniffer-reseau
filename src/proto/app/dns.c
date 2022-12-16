// Analyse d'un paquet dns

#include "../../includes/includes.h"

/* Analyse du paquet dns */
void compute_dns(struct pck_t * pck)
{
    // On remplit la structure dns
    fill_dns(pck);

    // On met à jour le log de la couche dns
    set_dns_log(pck);
}

/* Remplit la structure dns */
void fill_dns(struct pck_t * pck)
{
    struct dns_t * dns = init_dns();
    pck->log->al->dns = dns;
    
    // On récupère l'enteête dns
    dns->header = (struct dns_header_t *) pck->data;
    shift_pck(pck, sizeof(struct dns_header_t));

    // On récupère les questions
    dns->queries = init_dns_query(ntohs(dns->header->q_count));
    for(int i = 0; i < ntohs(dns->header->q_count); i++)
        read_dns_query(pck, &dns->queries[i]);

    // On récupère les réponses
    dns->answers = init_dns_answer(ntohs(dns->header->ans_count));
    for(int i = 0; i < ntohs(dns->header->ans_count); i++)
        read_dns_answer(pck,  &dns->answers[i]);
    
    // On récupère les autorités
    dns->authorities = init_dns_answer(ntohs(dns->header->auth_count));
    for(int i = 0; i < ntohs(dns->header->auth_count); i++)
        read_dns_answer(pck, &dns->authorities[i]);

    // On récupère les informations additionnelles
    dns->additionals = init_dns_answer(ntohs(dns->header->add_count));
    for(int i = 0; i < ntohs(dns->header->add_count); i++)
        read_dns_answer(pck, &dns->additionals[i]);
}

/* Met à jour le log de la couche dns */
void set_dns_log(struct pck_t * pck)
{
    struct app_layer_t * al = pck->log->al;
    char * log;
    CHECK(log = calloc(2048, sizeof(char)));

    // On met à jour les logs
    if(al->dns->header->qr == 0)
        sprintf(log, "Query");
    else
        sprintf(log, "Response");

    sprintf(log, "%s (0x%04x)", log, ntohs(al->dns->header->id));
    for(int i = 0; i < ntohs(al->dns->header->q_count); i++)
    {
        strcat(log, " ");
        strcat(log, al->dns->queries[i].type);
        strcat(log, " ");
        strcat(log, al->dns->queries[i].name);
    }
    //On ajoute toutes les réponses à la suite de infos
    for(int i = 0; i < ntohs(al->dns->header->ans_count); i++)
    {
        strcat(log, " ");
        strcat(log, al->dns->answers[i].type);
        strcat(log, " ");
        strcat(log, al->dns->answers[i].name);
    }

    //On met à jour le log verbose 1
    strcpy(pck->log->log, log);
    strcpy(pck->log->proto, PRINT_DNS_SHRT);

    //On met à jour le log verbose 2
    sprintf(
        pck->log->al->log,
        "%s, %s",
        PRINT_DNS,
        log
    );

    //On met à jour le log verbose 3
    fill_dns_log_v3(pck);

    free(log);
}

/* Rempli les logs détaillés pour le verbose 3 */
void fill_dns_log_v3(struct pck_t * pck)
{
    char * id;
    char * qr;
    char * opcode;
    char * q_count;
    char * ans_count;
    char * auth_count;
    char * add_count;

    CHECK(id = calloc(256, sizeof(char)));
    CHECK(qr = calloc(256, sizeof(char)));
    CHECK(opcode = calloc(256, sizeof(char)));
    CHECK(q_count = calloc(256, sizeof(char)));
    CHECK(ans_count = calloc(256, sizeof(char)));
    CHECK(auth_count = calloc(256, sizeof(char)));
    CHECK(add_count = calloc(256, sizeof(char)));

    //On récupère les données dns
    struct dns_header_t * header = pck->log->al->dns->header;

    //On met à jour les logs
    sprintf(id, "Transaction ID: 0x%04x", ntohs(header->id));
    sprintf(qr, "Query/response flag: %d (", header->qr);
    if(header->qr == 0)
        strcat(qr, "Query)");
    else
        strcat(qr, "Response)");
    sprintf(opcode, "Code op: %d (", header->opcode);
    if (header->opcode == 0)
        strcat(opcode, "Query)");
    else if (header->opcode == 1)
        strcat(opcode, "Inverse query)");
    else if (header->opcode == 2)
        strcat(opcode, "Server status request)");
    else
        strcat(opcode, "Unknown)");
    sprintf(q_count, "Queries count: %d", ntohs(header->q_count));
    sprintf(ans_count, "Answers count: %d", ntohs(header->ans_count));
    sprintf(auth_count, "Authorities count: %d", ntohs(header->auth_count));
    sprintf(add_count, "Additional count: %d", ntohs(header->add_count));


    //On met à jour les éléments du log
    add_log_v3(&pck->log->al->log_v3, id);
    add_log_v3(&pck->log->al->log_v3, qr);
    add_log_v3(&pck->log->al->log_v3, opcode);
    add_log_v3(&pck->log->al->log_v3, q_count);
    add_log_v3(&pck->log->al->log_v3, ans_count);
    add_log_v3(&pck->log->al->log_v3, auth_count);
    add_log_v3(&pck->log->al->log_v3, add_count);

    //On libère la mémoire
    free(id);
    free(qr);
    free(opcode);
    free(q_count);
    free(ans_count);
    free(auth_count);
    free(add_count);

    
    if(ntohs(header->q_count) > 0)
        add_log_v3(&pck->log->al->log_v3, "Queries:");
    for(int i = 0; i < ntohs(header->q_count); i++)
        fill_dns_query_log_v3(pck, &pck->log->al->dns->queries[i]);
    if(ntohs(header->ans_count) > 0)
        add_log_v3(&pck->log->al->log_v3, "Answers:");
    for(int i = 0; i < ntohs(header->ans_count); i++)
        fill_dns_answer_log_v3(pck, &pck->log->al->dns->answers[i]);
    if(ntohs(header->auth_count) > 0)
        add_log_v3(&pck->log->al->log_v3, "Authorities:");
    for(int i = 0; i < ntohs(header->auth_count); i++)
        fill_dns_answer_log_v3(pck, &pck->log->al->dns->authorities[i]);
    if(ntohs(header->add_count) > 0)
        add_log_v3(&pck->log->al->log_v3, "Additionals:");
    for(int i = 0; i < ntohs(header->add_count); i++)
        fill_dns_answer_log_v3(pck, &pck->log->al->dns->additionals[i]);
    
}

/* Rempli les logs détaillés pour une queries */
void fill_dns_query_log_v3(struct pck_t * pck, struct dns_query_t * query)
{
    char * name;
    char * type;
    char * class;

    CHECK(name = calloc(256, sizeof(char)));
    CHECK(type = calloc(256, sizeof(char)));
    CHECK(class = calloc(256, sizeof(char)));

    //On met à jour les logs
    sprintf(name, "├┬ %s", query->name);
    sprintf(type, "│├─ Type: %s", query->type);
    sprintf(class, "│└─ Class: %s", query->class);

    //On met à jour les éléments du log
    add_log_v3(&pck->log->al->log_v3, name);
    add_log_v3(&pck->log->al->log_v3, type);
    add_log_v3(&pck->log->al->log_v3, class);

    //On libère la mémoire
    free(name);
    free(type);
    free(class);
}

/* Rempli les logs détaillés pour une réponse */
void fill_dns_answer_log_v3(struct pck_t * pck, struct dns_answer_t * ans)
{
    char * name;
    char * type;
    char * class;
    char * ttl;
    char * data_len;
    char * data;

    CHECK(name = calloc(256, sizeof(char)));
    CHECK(type = calloc(256, sizeof(char)));
    CHECK(class = calloc(256, sizeof(char)));
    CHECK(ttl = calloc(256, sizeof(char)));
    CHECK(data_len = calloc(256, sizeof(char)));
    CHECK(data = calloc(256, sizeof(char)));

    //On met à jour les logs
    sprintf(name, "├┬ %s", ans->name);
    sprintf(type, "│├─ Type: %s", ans->type);
    sprintf(class, "│├─ Class: %s", ans->class);
    sprintf(ttl, "│├─ TTL: %d", ans->ttl);
    sprintf(data_len, "│├─ Data length: %d", ans->data_len);
    sprintf(data, "│└─ Data: %s", ans->main_info);

    //On met à jour les éléments du log
    add_log_v3(&pck->log->al->log_v3, name);
    add_log_v3(&pck->log->al->log_v3, type);
    add_log_v3(&pck->log->al->log_v3, class);
    add_log_v3(&pck->log->al->log_v3, ttl);
    add_log_v3(&pck->log->al->log_v3, data_len);
    add_log_v3(&pck->log->al->log_v3, data);

    //On libère la mémoire
    free(name);
    free(type);
    free(class);
    free(ttl);
    free(data_len);
    free(data);
}

/* Lit une requête dns */
void read_dns_query(struct pck_t * pck, struct dns_query_t * query)
{
    //On stocke le nom de la requête
    CHECK(query->name = calloc(1, 256));
    read_dns_name(query->name, pck, pck->data, 1);

    //On stocke le type de la requête
    CHECK(query->type = calloc(10, 1));
    switch(ntohs(*((uint16_t*)pck->data)))
    {
        case 1:
            sprintf(query->type, "A");
            break;
        case 2:
            sprintf(query->type, "NS");
            break;
        case 5:
            sprintf(query->type, "CNAME");
            break;
        case 6:
            sprintf(query->type, "SOA");
            break;
        case 12:
            sprintf(query->type, "PTR");
            break;
        case 15:
            sprintf(query->type, "MX");
            break;
        case 16:
            sprintf(query->type, "TXT");
            break;
        case 28:
            sprintf(query->type, "AAAA");
            break;
        case 41:
            sprintf(query->type, "OPT");
            break;
        case 251:
            sprintf(query->type, "IXFR");
            break;
        default:
            sprintf(query->type, UNKNOWN);
            break;
    }
    shift_pck(pck, 2);

    //On stocke la classe de la query
    CHECK(query->class = calloc(10,1));
    switch(ntohs(*((uint16_t*)pck->data)))
    {
        case 1:
            sprintf(query->class, "IN");
            break;
        case 2:
            sprintf(query->class, "CS");
            break;
        case 3:
            sprintf(query->class, "CH");
            break;
        case 4:
            sprintf(query->class, "HS");
            break;
        default:
            sprintf(query->class, UNKNOWN);
            break;
    }
    shift_pck(pck, 2);
}

/* Lit une réponse dns */
void read_dns_answer(struct pck_t * pck, struct dns_answer_t * ans)
{
    read_dns_query(pck, (struct dns_query_t *)ans);
    //On récupère le ttl
    ans->ttl = ntohl(*((uint32_t *)pck->data));
    shift_pck(pck, 4);

    //On récupère la taille de la réponse
    ans->data_len = ntohs(*((uint16_t *)pck->data));
    shift_pck(pck, 2);

    //On copie le pointeur
    const u_char *data_copy = pck->data;
    //On incrémente le pointeur pour passer à la prochaine réponse
    shift_pck(pck, ans->data_len);

    //On récupère la réponse
    // Si c'est de type A
    if(strcmp(ans->type, "A") == 0){
        CHECK(ans->main_info = calloc(sizeof(char), 16));
        sprintf(ans->main_info, "%s", ip_to_string((struct in_addr *)data_copy));
    }    
    //Si c'est de type NS, ou CNAME ou PTR
    else if(strcmp(ans->type, "NS") == 0 || strcmp(ans->type, "CNAME") == 0 || strcmp(ans->type, "PTR") == 0){
        CHECK(ans->main_info = calloc(sizeof(char), 256));
        read_dns_name(ans->main_info, pck, data_copy, 0);
    }
    //Si c'est de type SOA, on lit les 5 champs
    else if(strcmp(ans->type, "SOA") == 0){
        CHECK(ans->main_info = calloc(sizeof(char),256));
        read_dns_name(ans->main_info, pck, data_copy, 0);
        CHECK(ans->responsible_mail = calloc(sizeof(char),256));
        read_dns_name(ans->responsible_mail, pck, data_copy, 0);
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
    // Si c'est du type MX
    else if(strcmp(ans->type, "MX") == 0){
        CHECK(ans->main_info = calloc(sizeof(char),256));
        ans->preference = ntohs(*((uint16_t *)data_copy));
        data_copy += 2;
        read_dns_name(ans->main_info, pck, data_copy, 1);
    }
    //Si c'est du type TXT
    else if(strcmp(ans->type, "TXT") == 0){
        sprintf(ans->main_info,"TXT record");
        CHECK(ans->txt = calloc(sizeof(char),ans->data_len));
        memcpy(ans->txt, data_copy, ans->data_len);
    }
    //Si c'est du type AAAA
    else if(strcmp(ans->type, "AAAA") == 0){
        CHECK(ans->main_info = calloc(sizeof(char),40));
        sprintf(ans->main_info, "%s", ip6_to_string((struct in6_addr *)data_copy));
    }
    //Si c'est du type IXFR
    else if(strcmp(ans->type, "IXFR") == 0){
        CHECK(ans->main_info = calloc(sizeof(char),256));
        sprintf(ans->main_info,"IXFR record");
    }

}

/* Lit un str dans les données (utilise le c0 pour pointer vers une autre zone) */
void read_dns_name(char* str, struct pck_t * paq, const u_char * data, char base)
{   
    int i = 0;
    //On lit jusqu'à la fin de chaine
    while(*data != 0){

        //Si on tombe sur un c0, on lit l'adresse pointée
        if(*data == 0xc0){
            data += 2;
            if(base == 1) shift_pck(paq, 2);
            // On crée un nouveau pointeur pour ne pas modifier le pointeur de départ
            const u_char *new_data = paq->pck_original + *(data-1) + 42;
    
            char *new_str;
            CHECK(new_str = calloc(256, sizeof(char)));
            read_dns_name(new_str, paq, new_data, 0);
            //Si la chaine n'est pas vide, on ajoute un point
            if(strlen(str) != 0){
                strcat(str, ".");
            }
            //On concatène les deux chaines
            strcat(str, new_str);
            free(new_str);
            return;
        }
        //Si c'est non imprimable, on ajoute un point
        else if(*data < 32 || *data > 126){
            if (i != 0){
                strcat(str, ".");
                i++;
            }
        }
        else { //Sinon on ajoute le caractère
            str[i] = *data;
            i++;
        }
        data++;
        if(base == 1) shift_pck(paq, 1);
    }
    str[i] = '\0';
    
    data++;
    if(base == 1) shift_pck(paq, 1);
}


/* Fonction propres aux structures */

/* Initialise une structure dns_t */
struct dns_t * init_dns()
{
    struct dns_t * dns;
    CHECK(dns = malloc(sizeof(struct dns_t)));
    dns->header = NULL;
    dns->queries = NULL;
    dns->answers = NULL;
    dns->authorities = NULL;
    dns->additionals = NULL;

    return dns;
}

/* Initialise les query dns */
struct dns_query_t * init_dns_query(int nb_query)
{
    struct dns_query_t * query;
    CHECK(query = malloc(sizeof(struct dns_query_t) * nb_query));
    memset(query, 0, sizeof(struct dns_query_t) * nb_query);
    for(int i = 0; i < nb_query; i++)
    {
        query[i].name = NULL;
        query[i].type = NULL;
        query[i].class = NULL;
    }
    return query;
}

/* Initialise les answer dns */
struct dns_answer_t * init_dns_answer(int nb_answer)
{
    struct dns_answer_t * answer;
    CHECK(answer = malloc(sizeof(struct dns_answer_t) * nb_answer));
    memset(answer, 0, sizeof(struct dns_answer_t) * nb_answer);
    for(int i = 0; i < nb_answer; i++)
    {
        answer[i].name = NULL;
        answer[i].type = NULL;
        answer[i].class = NULL;
        answer[i].main_info = NULL;
        answer[i].responsible_mail = NULL;
        answer[i].txt = NULL;
    }
    return answer;
}

/* Libère la mémoire d'une structure dns_t */
void free_dns(struct dns_t * dns)
{

    if (dns == NULL) return;
    if (dns->queries != NULL) free_dns_query(dns->queries, ntohs(dns->header->q_count));
    if (dns->answers != NULL) free_dns_answer(dns->answers, ntohs(dns->header->ans_count));
    if (dns->authorities != NULL) free_dns_answer(dns->authorities, ntohs(dns->header->auth_count));
    if (dns->additionals != NULL) free_dns_answer(dns->additionals, ntohs(dns->header->add_count));
    
    free(dns);
}

/* Libère la mémoire d'une structure dns_query_t */
void free_dns_query(struct dns_query_t * query, int nb_query)
{
    if (query == NULL) return;
    for(int i = 0; i < nb_query; i++)
    {
        if (query[i].name != NULL)  free(query[i].name);
        if (query[i].type != NULL)  free(query[i].type);
        if (query[i].class != NULL) free(query[i].class);    
    }
}

/* Libère la mémoire d'une structure dns_answer_t */
void free_dns_answer(struct dns_answer_t * answer, int nb_answer)
{
    if (answer == NULL) return;
    for(int i = 0; i < nb_answer; i++)
    {
        if (answer[i].name != NULL) free(answer[i].name);
        if (answer[i].type != NULL) free(answer[i].type);
        if (answer[i].class != NULL) free(answer[i].class);
        if (answer[i].main_info != NULL) free(answer[i].main_info);
        if (answer[i].responsible_mail != NULL) free(answer[i].responsible_mail);
        if (answer[i].txt != NULL) free(answer[i].txt);
    }
}