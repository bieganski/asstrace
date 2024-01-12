#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/user.h>
#include <sys/syscall.h>
#include <assert.h>
#include <dlfcn.h>
#include <functional>
#include <string>

#include "gen/syscall_names.h"

int BIG_INT = 1;

int main(int argc, char *argv[]) {
    if (argc < 3) {
        fprintf(stderr, "Usage: %s <filterlib.so> <executable>\n", argv[0]);
        exit(EXIT_FAILURE);
    }

    void* filter_lib_handle = dlopen(argv[1], RTLD_LAZY);

    if (filter_lib_handle == nullptr) {
        fprintf(stderr, "Error opening filter library <%s>, because: %s\n", argv[1], dlerror());
        exit(1);
    }

    pid_t child_pid;
    if ((child_pid = fork()) == 0) {
        // Child process
        if (ptrace(PTRACE_TRACEME, 0, NULL, NULL) < 0) {
            perror("ptrace");
            exit(EXIT_FAILURE);
        }
        execvp(argv[2], argv + 2);
        perror("execvp");
        exit(EXIT_FAILURE);
    } else if (child_pid < 0) {
        perror("fork");
        exit(EXIT_FAILURE);
    } else {
        // Parent process
        int status;
        waitpid(child_pid, &status, 0);

        if (WIFEXITED(status)) {
            printf("Child process exited with status %d\n", WEXITSTATUS(status));
            exit(EXIT_SUCCESS);
        }

        printf("Tracing started...\n");

        while (1) {
            struct user_regs_struct regs;
            ptrace(PTRACE_SYSCALL, child_pid, NULL, NULL);

            waitpid(child_pid, &status, 0);
            if (WIFEXITED(status)) {
                printf("Child process exited with status %d\n", WEXITSTATUS(status));
                break;
            }

            ptrace(PTRACE_GETREGS, child_pid, NULL, &regs);
            assert(regs.orig_rax < 448);
            
            const char* syscall_name = syscall_names[regs.orig_rax];
            printf("%llu: %s\n", regs.orig_rax, syscall_name);

            static char filter_symbol_name[1024];
            snprintf(filter_symbol_name, 1023, "asstrace_%s", syscall_name);

            // check whether user has defined asstrace_<syscall_name> symbol in libfilter.so
            void* user_hook = dlsym(filter_lib_handle, filter_symbol_name);
            long hook_ret;
            
            if (user_hook != nullptr) {
                fprintf(stderr, "%s defined (mapped to %p), passing control..\n", filter_symbol_name, user_hook);

                printf("syscall_name loop: %s\n", syscall_name);
                if (std::string(syscall_name) == "read") {
                    auto fn_hook = reinterpret_cast<std::function<long(long, long, long)>*>(user_hook);
                    hook_ret = (*fn_hook)(1l, 2l, 3l);
                } else if (std::string(syscall_name) == "munmap") {
                    auto fn_hook = reinterpret_cast<std::function<long(long, long)>*>(user_hook);
                    hook_ret = (*fn_hook)(1l, 2l);
                } else {
                    assert(false);
                }
                printf("hook ret: %ld\n", hook_ret);
            } else {
                // printf("orig_syscall %s NOT FOUND\n", symbol_name);
            }
            
        }
    }

    return 0;
}
