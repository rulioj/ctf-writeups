#include <stdio.h>
#include <stdlib.h>

int main(){
	void *v1 = malloc(0x81);
	void *v2 = malloc(0x81);
	void *v3 = malloc(0x81);
	void *v4 = malloc(0x81);
	void *v5 = malloc(0x81);
	void *v6 = malloc(0x81);
	void *v7 = malloc(0x81);

	void *ptr = malloc(0x81);
	void *ptr2 = malloc(0x81);

	free(v1);
	free(v2);
	free(v3);
	free(v4);
	free(v5);
	free(v6);
	free(v7);

	gets();
	free(ptr);
	gets();
	free(ptr2);
	gets();
}
