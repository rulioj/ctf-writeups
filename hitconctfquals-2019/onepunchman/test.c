#include <stdio.h>
#include <stdlib.h>

int main(void){

    // char *top = malloc(0x1000);
    // printf("%lx\n", &top);
    // free(top);

    // void *heap_base = ((long)top & 0xfffffffffffff000)+0x10;

    // printf("%lx\n", heap_base+0x20);
    // void *a1 = malloc(0x50);
    // void *a2 = malloc(0x100);
    void *a3 = malloc(0x217);
    // void *a4 = malloc(0x200);
    // void *a5 = malloc(0x250);

    // free(a1);
    // free(a2);
    free(a3);

    a3 = malloc(0x217);

    malloc(0x20);

    free(a3);
    // free(a4);
    // free(a5);

}
