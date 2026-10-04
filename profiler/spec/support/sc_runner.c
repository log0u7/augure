/* Runs the raw shellcode bytes given on stdin (our own assembled
   stubs - trusted input). Compiles with gcc; used by shellcode_spec. */
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
int main(void) {
  unsigned char buf[512];
  size_t n = fread(buf, 1, sizeof(buf), stdin);
  void *m = mmap(NULL, 4096, PROT_READ|PROT_WRITE|PROT_EXEC,
    MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
  memcpy(m, buf, n);
  ((void(*)(void))m)();
  return 0;
}
