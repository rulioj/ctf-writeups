#include <stdlib.h>

int main(){

  void *ptr1;
  void *ptr2;

  // [A]
  ptr1 = malloc(0x20); // 31
  // [B]
  ptr2 = malloc(0x20);

  // [C]
  free(ptr1);
  // [D]
  free(ptr2);

  // [E]
  ptr1 = malloc(0x20);
  // [F]
  ptr2 = malloc(0x20);

  return 0;
}
