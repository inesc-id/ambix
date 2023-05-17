#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <unistd.h>

#define KiB 1 << 10
#define MiB 1 << 20
#define GiB 1 << 30
#define JUMP 1 << 15
#define ITER (int)1e6

typedef unsigned char byte;

int main(int argc, char **argv) {
  unsigned long size = sizeof(byte) * 20 * GiB;
  byte *buffer = (byte *)malloc(size);
  FILE *f = fopen("/proc/ambix", "w");
  int rc;
  if (!buffer || !f)
    goto die;

  rc = fprintf(f, "bind");
  if (!rc)
    goto die;
  fclose(f);

  srand(time(NULL));

  int pid;
  for (int p = 0; p < 4; p++) {
    pid = fork();
    if (pid == 0)
      break;
  }

  if (pid != 0) {
    for (int j = 0; j < ITER; j++) {
      for (unsigned long i = 0; i < size; i += JUMP)
        buffer[i] = rand();
    }
  } else {
    for (int j = 0; j < ITER; j++) {
      for (unsigned long i = 0; i < size; i += JUMP) {
        int x = buffer[i];
        x++;
      }
    }
  }
  free(buffer);
  return 0;

die:
  if (buffer)
    free(buffer);
  if (!f)
    fclose(f);
  return -1;
}
