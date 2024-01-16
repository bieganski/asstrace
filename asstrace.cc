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

#include "gen/syscall_names.h"
#include "gen/syscall_num_params.h"

#define VERBOSE


static pid_t tracee_pid = -1;


// TODO: move section below to a separate .h header, to be included by user library.
extern "C" {
pid_t
__attribute__((noinline, used))
get_tracee_pid() {
    return tracee_pid;
}
}

long invoke_syscall_mock(void* mock_ptr, int num_params) {
    assert(num_params >= 0);
    assert(num_params <= 6);

    long hook_ret;

    if (num_params == 0) {
        hook_ret = ((long (*)()) mock_ptr)();
    } else if (num_params == 1) {
        hook_ret = ((long (*)(long)) mock_ptr)(1);
    } else if (num_params == 2) {
        hook_ret = ((long (*)(long, long)) mock_ptr)(1, 2);
    } else if (num_params == 3) {
        hook_ret = ((long (*)(long, long, long)) mock_ptr)(1, 2, 3);
    } else if (num_params == 4) {
        hook_ret = ((long (*)(long, long, long, long)) mock_ptr)(1, 2, 3, 4);
    } else if (num_params == 5) {
        hook_ret = ((long (*)(long, long, long, long, long)) mock_ptr)(1, 2, 3, 4, 5);
    } else if (num_params == 6) {
        hook_ret = ((long (*)(long, long, long, long, long, long)) mock_ptr)(1, 2, 3, 4, 5, 6);
    }

    return hook_ret;
}

void check_child_alive_or_exit(int status) {
    if (WIFEXITED(status)) {
        printf("Child process exited with status %d\n", WEXITSTATUS(status));
        exit(0);
    }
}

int main(int argc, char *argv[]) {

#ifndef VERBOSE
    close(2);
#endif

    // Perform gen/*.h sanity check.
    auto syscall_names_size = sizeof(syscall_names) / sizeof(syscall_names[0]);
    auto syscall_num_params_size = sizeof(syscall_names) / sizeof(syscall_names[0]);
    assert (syscall_names_size == syscall_num_params_size);
    int max_syscall_number = syscall_names_size - 1;

    // Check if command line arguments are valid.
    if (argc < 3) {
        printf("Usage: %s <filterlib.so> <executable>\n", argv[0]);
        exit(1);
    }
    void* filter_lib_handle = dlopen(argv[1], RTLD_LAZY);
    if (filter_lib_handle == nullptr) {
        printf("Error opening filter library <%s>, because: %s\n", argv[1], dlerror());
        exit(1);
    }

    // Fork into tracer and tracee.
    if ((tracee_pid = fork()) == 0) {
        // Child process
        if (ptrace(PTRACE_TRACEME, 0, NULL, NULL) < 0) {
            perror("ptrace"); exit(1);
        }
        execvp(argv[2], argv + 2); // TODO: +2 hardcoded
        perror("execvp"); exit(1);
    } else if (tracee_pid < 0) {
        perror("fork"); exit(1);
    } else {
        // Parent process
        int status;

        waitpid(tracee_pid, &status, 0);

        while (1) {
            // Wait for syscall entry/exit event.
            ptrace(PTRACE_SYSCALL, tracee_pid, NULL, NULL);
            waitpid(tracee_pid, &status, 0);
            check_child_alive_or_exit(status);

            // Get some insights into what syscall tracee called.
            struct user_regs_struct regs;
            ptrace(PTRACE_GETREGS, tracee_pid, NULL, &regs);
            unsigned long long syscall_number = regs.orig_rax; // arch-specific user_regs reference.
            assert(syscall_number <= max_syscall_number);
            const char* syscall_name = syscall_names[syscall_number];
            printf("%llu: %s\n", syscall_number, syscall_name);
            
            // Check whether user has defined asstrace_<syscall_name> symbol in libfilter.so
            static char filter_symbol_name[1024];
            snprintf(filter_symbol_name, 1023, "asstrace_%s", syscall_name);
            void* user_hook = dlsym(filter_lib_handle, filter_symbol_name);
            
            if (user_hook != nullptr) {
                fprintf(stderr, "%s defined (mapped to %p), passing control..\n", filter_symbol_name, user_hook);
                long hook_ret = invoke_syscall_mock(user_hook, syscall_num_params[syscall_number]);
                printf("hook ret: %ld\n", hook_ret);
            } else {
                // bypass
            }
            
        }
    }

    return 0;
}
