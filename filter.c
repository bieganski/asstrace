#include <stdlib.h>
#include <stdio.h>
#include <sys/types.h>

pid_t get_tracee_pid();

long asstrace_read(unsigned int fd, char *buf, size_t count) {
    printf(">>> asstrace_read from PID=%d, fd=%d\n, buf=%p, count=%lu", get_tracee_pid(), fd, buf, count);
    return 1234;
}

long asstrace_munmap(unsigned long addr, size_t len) {
    printf(">>> asstrace_munmap from PID=%d, addr=%p, len=%lu\n", get_tracee_pid(), (void*)addr, len);
    return 5678;
}