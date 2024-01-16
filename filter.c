#include <stdlib.h>
#include <stdio.h>
#include <sys/types.h>

pid_t get_tracee_pid();

long asstrace_read(unsigned int fd, char *buf, size_t count) {
    printf(">>> asstrace_read from tracee with PID=%d\n", get_tracee_pid());
    return fd + (long)buf + (long)count;
}

long asstrace_munmap(unsigned long addr, size_t len) {
    printf(">>> asstrace_munmap from tracee with PID=%d\n", get_tracee_pid());
    return addr + len;
}