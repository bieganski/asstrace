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
#include <string>

#include <unordered_map>

const std::unordered_map<const char*, int> myGlobalHashMap = {
    {"one", 1},
    {"two", 2},
    {"three", 3}
};

#include "gen/syscall_names.h"
#include "gen/syscall_num_params.h"

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

        auto syscall_names_size = sizeof(syscall_names) / sizeof(syscall_names[0]);
        auto syscall_num_params_size = sizeof(syscall_names) / sizeof(syscall_names[0]);
        assert (syscall_names_size == syscall_num_params_size);

        int max_syscall_number = syscall_names_size - 1;


        while (1) {
            struct user_regs_struct regs;
            ptrace(PTRACE_SYSCALL, child_pid, NULL, NULL);

            waitpid(child_pid, &status, 0);
            if (WIFEXITED(status)) {
                printf("Child process exited with status %d\n", WEXITSTATUS(status));
                break;
            }

            ptrace(PTRACE_GETREGS, child_pid, NULL, &regs);

            // arch-specific user_regs reference.
            unsigned long long syscall_number = regs.orig_rax;
            
            assert(syscall_number <= max_syscall_number);
            
            const char* syscall_name = syscall_names[syscall_number];
            printf("%llu: %s\n", syscall_number, syscall_name);

            static char filter_symbol_name[1024];
            snprintf(filter_symbol_name, 1023, "asstrace_%s", syscall_name);

            // check whether user has defined asstrace_<syscall_name> symbol in libfilter.so
            void* user_hook = dlsym(filter_lib_handle, filter_symbol_name);
            long hook_ret;
            
            if (user_hook != nullptr) {
                fprintf(stderr, "%s defined (mapped to %p), passing control..\n", filter_symbol_name, user_hook);

                int num_params = syscall_num_params[syscall_number];

                assert(num_params >= 0);
                assert(num_params <= 6);

                if (num_params == 0) {
                    hook_ret = ((long (*)()) user_hook)();
                } else if (num_params == 1) {
                    hook_ret = ((long (*)(long)) user_hook)(1);
                } else if (num_params == 2) {
                    hook_ret = ((long (*)(long, long)) user_hook)(1, 2);
                } else if (num_params == 3) {
                    hook_ret = ((long (*)(long, long, long)) user_hook)(1, 2, 3);
                } else if (num_params == 4) {
                    hook_ret = ((long (*)(long, long, long, long)) user_hook)(1, 2, 3, 4);
                } else if (num_params == 5) {
                    hook_ret = ((long (*)(long, long, long, long, long)) user_hook)(1, 2, 3, 4, 5);
                } else if (num_params == 6) {
                    hook_ret = ((long (*)(long, long, long, long, long, long)) user_hook)(1, 2, 3, 4, 5, 6);
                }

                printf("hook ret: %ld\n", hook_ret);
            } else {
                // printf("orig_syscall %s NOT FOUND\n", symbol_name);
            }
            
        }
    }

    return 0;
}
