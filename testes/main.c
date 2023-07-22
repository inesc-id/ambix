#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#define PAGE_SIZE_WORD 1024

int main() {
  // 4 pags
  unsigned int *bytes = malloc(4096 * sizeof(int));
  for (int i = 0; i < 4; i++) {
    bytes[PAGE_SIZE_WORD * i] = 123 * (i + 1);
    printf("The addr is %016p\n", bytes + PAGE_SIZE_WORD * i);
    printf("The content is %d\n", bytes[PAGE_SIZE_WORD * i]);
  }

  FILE *f = fopen("/proc/test_kmod", "w");

  if (f == NULL) {
    puts("f is NULL");
    return EXIT_FAILURE; 
  }

  fprintf(f, "%d:", getpid());
  fprintf(stdout, "%d:\n", getpid());
  for (int i = 0; i < 4; i++) {
    int rc = fprintf(f, "%016p:", &bytes[PAGE_SIZE_WORD * i]);
    fprintf(stdout, "%016p:", &bytes[PAGE_SIZE_WORD * i]);
    // printf("rc = %d\n", rc);
  }
  fprintf(f, "\n");

  fclose(f);
  sleep(10);
  free(bytes);
}
