#include <fcntl.h>
#include <limits.h>

#include "api.h"

static char path[PATH_MAX];

// TODO - we need 'strcpy' function in API - currently we will likely hit OOB access with PATH_MAX copy.
#define COPY_PATH_FROM_TRACEE(dst, src) (api_memcpy_from_tracee(api_get_tracee_pid(), dst, src, PATH_MAX))


extern "C" {

// NOTE:
// The 'pathname' param (in both 'unlink' and 'unlinkat') is a pointer valid only in tracee address space!
// Since user library works in tracer context, we need to copy it explicitly.

long asstrace_unlinkat(int dfd, char * pathname, int flag) {
    if (dfd != AT_FDCWD) {
        printf("dir_fd other than AT_FDCWD not supported!\n");
        exit(1);
    }

    COPY_PATH_FROM_TRACEE(path, pathname);
    printf(">> prevented %s from removing!\n", path);
    return 0;
}

long asstrace_unlink(char *pathname) {
    COPY_PATH_FROM_TRACEE(path, pathname);
    printf(">> prevented %s from removing!\n", path);
    return 0;
}

}
