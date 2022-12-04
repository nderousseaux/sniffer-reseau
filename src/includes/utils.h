//Fonctions utiles

#ifndef H_GL_UTILS
#define H_GL_UTILS

#include <errno.h>
#include <string.h>
#include <arpa/inet.h>
#include <netinet/ether.h>

//Pour x == 0 (parfait pour malloc/calloc) et tout les appels systèmes
#define CHECK(x) \
  do { \
    if (!(x)) { \
      fprintf(stderr, "%s:%d: ", __func__, __LINE__); \
	  if(errno==0) errno=ECANCELED; \
      perror(#x); \
      exit(EXIT_FAILURE); \
    } \
  } while (0)

/* Convertit une addresse mac en char * */
void ether_to_string(struct ether_addr *ether, char * str);

/* Convertit une addresse ipV4 en char * */
void ip_to_string(struct in_addr *ip, char * str);


#endif // H_GL_UTILS