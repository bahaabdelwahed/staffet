/* Test fixture: deliberately vulnerable code. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(int argc, char **argv) {
  char b[8];
  strcpy(b, argv[1]);
  printf(argv[1]);
  system(argv[1]);
  scanf("%s", b);
  if (argc = 2) {
    return 1;
  }
  printf("ok\n");
  return 0;
}
