#ifndef H_GL_DNS
#define H_GL_DNS

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "protocols.h"
#include "utils.h"

//Lit un str dans les données (utilise le c0 pour pointer vers une autre zone)
void read_str(char* str, const u_char **data, const u_char **pck);

/* Stocke une requête dns */
void read_dns_query(struct dns_query_t *query, const u_char **data, const u_char **pck);

/* Stocke une réponse dns */
void read_dns_answer(struct dns_answer_t *ans, const u_char **data, const u_char **pck);

#endif // H_GL_DNS