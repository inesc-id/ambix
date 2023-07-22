#include <numaif.h>
#include <stdio.h>
#include <stdlib.h>

#define PAGE_SIZE_WORD 1024

int main() {
  // 4 pags
  unsigned int *bytes = malloc(4096 * sizeof(int));
  unsigned int *page_addr[4];
  for (int i = 0; i < 4; i++) {
    bytes[PAGE_SIZE_WORD * i] = 123 * (i + 1);
    page_addr[i] = &bytes[PAGE_SIZE_WORD * i];
    printf("The addr is 0x%016x\n", bytes + PAGE_SIZE_WORD * i);
    printf("The content is %d\n", bytes[PAGE_SIZE_WORD * i]);
  }

  int dcpmm_node[] = {2, 2, 2, 2};
  int status[4];

  long rc =
      move_pages(0, 4, (void **)&page_addr, dcpmm_node, status, MPOL_MF_MOVE);
  printf("rc = %ld\n", rc);

  for (int i = 0; i < 4; i++) {
    printf("status[%d] = %d\n", i, status[i]);
  }
}
