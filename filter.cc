#include <stdlib.h>
#include <stdio.h>
// #include <sys/types.h>
// #include <unistd.h>
// #include <assert.h>
// #include <fcntl.h>
// #include <cstring>
// #include <sys/ptrace.h>
// #include <limits.h>
// #include <ctype.h>

#include "api.h"



extern "C" {

long asstrace_write(unsigned int fd, char *buf, size_t count) {
    if (fd != 2) {
        printf("BAD!\n");
        exit(1);
    }

    auto my_buf = (char*) malloc(count);

    api_memcpy_from_tracee(api_get_tracee_pid(), my_buf, buf, count);

    printf("write detected: %s", my_buf);
    exit(0);

    return 0xdead;
}

}
