#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/user.h>
#include <sys/syscall.h>
#include <assert.h>
#include <dlfcn.h>
#include <string>
#include <cstddef>

#include "gen/syscall_names.h"
#include "gen/syscall_num_params.h"

#define VERBOSE

#define OUTPUT_FD stdout
#define OUTPUT(...) fprintf(OUTPUT_FD, __VA_ARGS__)

using arch_reg_content_t = unsigned long long;

/* TODO
duplicated from linux/ptrace.h (and unsafe, as it might change for next kernel versions).

The reason is that including both sys/ptrace.h and linux/ptrace.h makes lots of conflicts.
*/
struct ptrace_syscall_info {
	uint8_t op;	/* PTRACE_SYSCALL_INFO_* */
	uint8_t pad[3];
	uint32_t arch;
	uint64_t instruction_pointer;
	uint64_t stack_pointer;
	union {
		struct {
			uint64_t nr;
			uint64_t args[6];
		} entry;
		struct {
			int64_t rval;
			uint8_t is_error;
		} exit;
		struct {
			uint64_t nr;
			uint64_t args[6];
			uint32_t ret_data;
		} seccomp;
	};
};
#include <sys/ptrace.h>

// state exposed
static pid_t tracee_pid = -1;

// state hidden
#define INVALID_SYSCALL_NUMBER -1
// invalid means that either we not yet observed any TRACE_SYSCALL event, or last observed one was SYSCALL_EXIT.
static arch_reg_content_t current_syscall_number = INVALID_SYSCALL_NUMBER;

static void mark_tracee_started_syscall(int syscall_number) {
    // assert (current_syscall_number == INVALID_SYSCALL_NUMBER);
    current_syscall_number = syscall_number;
}

static void mark_tracee_finished_syscall(int syscall_number) {
    // assert (current_syscall_number == syscall_number);
    current_syscall_number = INVALID_SYSCALL_NUMBER;
}

static bool is_tracee_in_syscall() {
    return current_syscall_number != INVALID_SYSCALL_NUMBER;
}


// TODO: move section below to a separate .h header, to be included by user library.
extern "C" {
pid_t
__attribute__((noinline, used))
get_tracee_pid() {
    return tracee_pid;
}
}

static int arch_abi_fun_call_params_order[6] = {
    offsetof(user_regs_struct, rdi),
    offsetof(user_regs_struct, rsi),
    offsetof(user_regs_struct, rdx),
    offsetof(user_regs_struct, rcx),
    offsetof(user_regs_struct, r8),
    offsetof(user_regs_struct, r9),
};


#define arch_fun_call_param_get(__user_regs, __i) *(arch_reg_content_t*)&(((char*) __user_regs)[arch_abi_fun_call_params_order[__i]])

static arch_reg_content_t* arch_pc(struct user_regs_struct* user_regs) {
    return &user_regs->rip;
}

static arch_reg_content_t* arch_ret_val(struct user_regs_struct* user_regs) {
    return &user_regs->rax;
}

static arch_reg_content_t* arch_syscall_number(struct user_regs_struct* user_regs) {
    return &user_regs->orig_rax;
}

static arch_reg_content_t* arch_syscall_ret_addr(struct user_regs_struct* user_regs) {
    // For x86, address of instruction following SYSCALL is stored in RCX (and RFLAGS in R11).
    // https://www.felixcloutier.com/x86/syscall
    return &user_regs->rcx;
}

long invoke_syscall_mock(void* mock_ptr, int num_params, struct user_regs_struct* user_regs) {
    assert(0 <= num_params <= 6);

    long hook_ret;

    if (num_params == 0) {
        hook_ret = ((long (*)()) mock_ptr)();
    } else if (num_params == 1) {
        hook_ret = ((long (*)(long)) mock_ptr)(arch_fun_call_param_get(user_regs, 0));
    } else if (num_params == 2) {
        hook_ret = ((long (*)(long, long)) mock_ptr)(arch_fun_call_param_get(user_regs, 0), arch_fun_call_param_get(user_regs, 1));
    } else if (num_params == 3) {
        hook_ret = ((long (*)(long, long, long)) mock_ptr)(arch_fun_call_param_get(user_regs, 0), arch_fun_call_param_get(user_regs, 1), arch_fun_call_param_get(user_regs, 2));
    } else if (num_params == 4) {
        hook_ret = ((long (*)(long, long, long, long)) mock_ptr)(arch_fun_call_param_get(user_regs, 0), arch_fun_call_param_get(user_regs, 1), arch_fun_call_param_get(user_regs, 2), arch_fun_call_param_get(user_regs, 3));
    } else if (num_params == 5) {
        hook_ret = ((long (*)(long, long, long, long, long)) mock_ptr)(arch_fun_call_param_get(user_regs, 0), arch_fun_call_param_get(user_regs, 1), arch_fun_call_param_get(user_regs, 2), arch_fun_call_param_get(user_regs, 3), arch_fun_call_param_get(user_regs, 4));
    } else if (num_params == 6) {
        hook_ret = ((long (*)(long, long, long, long, long, long)) mock_ptr)(arch_fun_call_param_get(user_regs, 0), arch_fun_call_param_get(user_regs, 1), arch_fun_call_param_get(user_regs, 2), arch_fun_call_param_get(user_regs, 3), arch_fun_call_param_get(user_regs, 4), arch_fun_call_param_get(user_regs, 5));
    }

    return hook_ret;
}

void check_child_alive_or_exit(int status) {
    if (WIFEXITED(status)) {
        printf("Child process exited with status %d\n", WEXITSTATUS(status));
        exit(0);
    }

    if (WIFSTOPPED(status) && ((WSTOPSIG(status) & 127) != SIGTRAP)) {
        printf("Tracee received unexpected signal: %d\n", WSTOPSIG(status));
        exit(1);
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
        printf("Usage: %s <./filterlib.so> <executable>\n", argv[0]);
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
        raise(SIGTRAP);
        execvp(argv[2], argv + 2); // TODO: +2 hardcoded
        perror("execvp"); exit(1);
    } else if (tracee_pid < 0) {
        perror("fork"); exit(1);
    } else {
        // Parent process
        int status;

        waitpid(tracee_pid, &status, 0);
        check_child_alive_or_exit(status);

        /*
        man ptrace

        In case of system call entry or exit stops, the data
        returned by PTRACE_GET_SYSCALL_INFO is limited to type
        PTRACE_SYSCALL_INFO_NONE unless PTRACE_O_TRACESYSGOOD
        option is set before the corresponding system call stop
        has occurred.
        */
        ptrace(PTRACE_SETOPTIONS, tracee_pid, NULL, PTRACE_O_TRACESYSGOOD);

        while (1) {

            // Wait for syscall entry/exit event.
            // In first iteration it is an entry to 'execve'.
            ptrace(PTRACE_SYSCALL, tracee_pid, NULL, NULL);
            waitpid(tracee_pid, &status, 0);
            check_child_alive_or_exit(status);

            // Syscall entered or exited?
            struct ptrace_syscall_info syscall_info;
            ptrace(PTRACE_GET_SYSCALL_INFO, tracee_pid, sizeof(ptrace_syscall_info), &syscall_info);
            if (syscall_info.op == PTRACE_SYSCALL_INFO_NONE) {
                static bool if_it_happened_only_once_then_its_fine = false;
                if (if_it_happened_only_once_then_its_fine) {
                    printf("syscall_info.op == PTRACE_SYSCALL_INFO_NONE happened twice!\n");
                    exit(1);
                }
                if_it_happened_only_once_then_its_fine = true;
                continue;
            }

            // Get some insights into what syscall tracee entered/exited.
            struct user_regs_struct user_regs;
            ptrace(PTRACE_GETREGS, tracee_pid, NULL, &user_regs);
            arch_reg_content_t syscall_number = *arch_syscall_number(&user_regs);
            if (syscall_number > max_syscall_number) {
                printf("Unexpected syscall number: 0x%llx\n", syscall_number);
                // exit(1);
                continue;
            }
            const char* syscall_name = syscall_names[syscall_number];

            auto& op = syscall_info.op;
            if (op == PTRACE_SYSCALL_INFO_ENTRY) {

                // Check whether user has defined asstrace_<syscall_name> symbol in libfilter.so
                static char filter_symbol_name[1024];
                snprintf(filter_symbol_name, 1023, "asstrace_%s", syscall_name);
                void* user_hook = dlsym(filter_lib_handle, filter_symbol_name);
                bool invoke_mock_syscall = user_hook != nullptr;
            
                if (invoke_mock_syscall) {

                    fprintf(stderr, "@ %s defined (mapped to %p), passing control..\n", filter_symbol_name, user_hook);
                    arch_reg_content_t hook_ret = invoke_syscall_mock(user_hook, syscall_num_params[syscall_number], &user_regs);
                    OUTPUT("intercepted %s. mock returned %llu", syscall_name, hook_ret);

                    // make the tracee think that it returned from real syscall.
                    *arch_pc(&user_regs) = *arch_syscall_ret_addr(&user_regs);
                    ptrace(PTRACE_SETREGS, tracee_pid, NULL, &user_regs);
                
                } else {
                    // don't interfere normal syscall execution. only log params.

                    mark_tracee_started_syscall(syscall_number);
                    OUTPUT("%s(", syscall_name);
                    for(int i = 0; i < syscall_num_params[syscall_number]; i++) {
                        OUTPUT("0x%llx, ", arch_fun_call_param_get(&user_regs, i));
                    }
                }

            } else if (op == PTRACE_SYSCALL_INFO_EXIT) {
                mark_tracee_finished_syscall(syscall_number);
                OUTPUT(") = 0x%llx\n", *arch_ret_val(&user_regs));
            } else {
                printf("PTRACE_GET_SYSCALL_INFO: Unknown op: %d\n", syscall_info.op);
                continue;
            }
        }
    }

    return 0;
}
