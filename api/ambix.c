#include <stdio.h>
#include <stdlib.h>
#include <errno.h>

int write_procfs(char* command) {
  FILE *f = fopen("/proc/ambix", "w");

  if (!f)
    goto fail_return;

  fprintf(f, command);

  fclose(f);

  return 0;

fail_return:
  errno = -EINVAL;
  return 1;
}

int bind_range(unsigned long start, unsigned long end) {
  char buffer[1024];
  snprintf(buffer, 1023, "bind_range %lx %lx", start, end);
  return write_procfs(buffer);
}

int bind_range_pid(int pid, unsigned long start, unsigned long end) {
  char buffer[1024];
  snprintf(buffer, 1023, "bind_range_pid %d %lx %lx", pid, start, end);
  return write_procfs(buffer);
}

int bind(void) {
  return write_procfs("bind");
}

int unbind(void) {
  return write_procfs("unbind");
}

int bind_pid(int pid) {
  char buffer[1024];
  snprintf(buffer, 1023, "bind %d", pid);
  return write_procfs(buffer);
}

int enable(void) {
  return write_procfs("enable");
}

int disable(void) {
  return write_procfs("disable");
}
