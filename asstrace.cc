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

#include "gen/syscall_names.h"

int main(int argc, char *argv[]) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <executable>\n", argv[0]);
        exit(EXIT_FAILURE);
    }

    pid_t child_pid;
    if ((child_pid = fork()) == 0) {
        // Child process
        if (ptrace(PTRACE_TRACEME, 0, NULL, NULL) < 0) {
            perror("ptrace");
            exit(EXIT_FAILURE);
        }
        execvp(argv[1], argv + 1);
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
            // printf("Syscall number: %llu\n", regs.orig_rax);
            assert(regs.orig_rax < 448);
            printf("%s\n", syscall_names[regs.orig_rax]);
        }
    }

    return 0;
}
