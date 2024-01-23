#include <stdlib.h>
#include <stdio.h>
#include <sys/types.h>
#include <unistd.h>
#include <assert.h>
#include <fcntl.h>
#include <cstring>
#include <sys/ptrace.h>
#include <limits.h>
#include <ctype.h>

#include "api.h"

static char resolved_target[PATH_MAX];

/*
For demo purpose we run 'cat <filename>' program (see Makefile).
We capture and modify only writes to  <filename>, so resolve it on library load time,
and then in each 'read' call check if associated file descriptor corresponds to that resolved file.
*/
static void
__attribute__((constructor))
on_dlopen() {
    auto cmdline_vec = api_get_tracee_cmdline();
    assert (!cmdline_vec.empty());
    assert (realpath(cmdline_vec.back().c_str(), resolved_target));
}

static void buf_to_uppercase(char* buf, size_t size) {
    for (int i = 0; i < size; i++) {
        char& cur = buf[i];
        if (isalpha(cur))
            cur = toupper(cur);
    }
}

/*
NOTE: 'path_buf' contains empty string if could not resolve path.
*/
static void tracee_resolve_fd(pid_t pid, int fd, char* path_buf) {
    static char link_path[50] = {0};
    snprintf(link_path, 50, "/proc/%d/fd/%d", pid, fd);
    path_buf[0] = (char) 0;
    realpath(link_path, path_buf);
}


static void ptrace_memcpy(pid_t pid, void* dst_tracee, void* src_tracer, size_t size) {
    // TODO - for non word-size-aligned 'count' we will write *less* bytes than expected.
    auto word_size = sizeof(arch_reg_content_t);
    auto iters = size / word_size;

    arch_reg_content_t* dst_buf = (arch_reg_content_t*) dst_tracee;
    arch_reg_content_t* src_buf = (arch_reg_content_t*) src_tracer;

    for (int i = 0; i < iters; i++) {
        ptrace(PTRACE_POKETEXT, pid, dst_buf, *src_buf);
        dst_buf++;
        src_buf++;
    }
}

extern "C" {

long asstrace_read(unsigned int fd, char *buf, size_t count) {

    pid_t pid = api_get_tracee_pid();

    static char resolved_path[PATH_MAX];
    tracee_resolve_fd(pid, fd, resolved_path);

    bool should_bypass = (strncmp(resolved_path, resolved_target, PATH_MAX) != 0);

    if (should_bypass) {
        // tracee reads from file that we don't care about - let it go.
        api_invoke_syscall_anyway();
        return 1234; // return value won't be used in that case.
    }

    char* malloc_buf = (char*) malloc(count);
    assert (malloc_buf);

    // open only once ...
    static int my_fd = open(resolved_path, O_RDONLY);
    // ... read every time.
    int real_count = read(my_fd, malloc_buf, count);

    // transform all read bytes to uppercase.
    buf_to_uppercase(malloc_buf, real_count);

    ptrace_memcpy(pid, buf, malloc_buf, real_count);

    free(malloc_buf);
    return real_count; // that value will go to tracee, as a result of 'read' syscall.
}

}
