#include "./includes/utils.h"

//Affiche les x prochains octets, en hexa
void print_hex(const u_char **data, int x){
    const unsigned char *data_ptr = *data;
    for (int i = 0; i < x; i++) {
        printf("%02x ", *data_ptr);
        data_ptr++;
    }
    *data = data_ptr;
}