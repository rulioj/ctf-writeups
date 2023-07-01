#include <stdio.h>
#include <stdlib.h>

int main(void){

    char *ptr = malloc(0x18);
    free(ptr);
    gets();
}
