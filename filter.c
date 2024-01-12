#include <stdlib.h>
#include <stdio.h>

long asstrace_read(unsigned int fd, char *buf, size_t count) {
    printf(">>> asstrace_read\n");
    return fd + (long)buf + (long)count;
}

long asstrace_munmap(unsigned long addr, size_t len) {
    printf(">>> asstrace_munmap\n");
    return addr + len;
}