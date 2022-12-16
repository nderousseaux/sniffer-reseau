//Fonctions utiles

#ifndef H_GL_UTILS
#define H_GL_UTILS

#define BROADCAST "Broadcast"
#define UNSPECIFIED "Unspecified"
#define LOOPBACK "Loopback"


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

#define UNKNOWN "Unknown"

/* Renvoie une chaine de caractère correspondant au temps écoulé depuis un temps de référence */
char * interval(struct timeval *ref, struct timeval *now);

/* Renvoie une chaine de manière à ce qu'elle prenne exactement x caractères */
/* Remplit par des \t et des espaces si trop courte */
/* Tronquée, et conclue par "..." si trop longue */
char * str_exact_len(char *str, int x);

/* Calcule la longueur de la chaine */
/* Compte les caractères ─, ┌, ┐, etc... comme 1 caractère */
/* Compte la couleur ansi comme 0 caractères */
int strlen_special(char *str);

/* Transforme un int en string */
char * int_to_str(int x);

/* Convertit une addresse mac en char */
char *ether_to_string(struct ether_addr *ether);

/* Convertit une addresse ip en char */
char *ip_to_string(struct in_addr *ip);

/* Convertit une addresse ip6 en char */
char *ip6_to_string(struct in6_addr *ip6);

/* Inverse la position des octets */
int flip_octets(int x);

/* Convertit des données en str */
char * str_by_hex(unsigned char * data, int len);

#endif // H_GL_UTILS