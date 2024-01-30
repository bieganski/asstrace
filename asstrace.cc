#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/user.h>
#include <sys/syscall.h>
#include <sys/uio.h>
#include <assert.h>
#include <dlfcn.h>
#include <string>
#include <cstddef>
#include <algorithm>

#define VERBOSE

#define OUTPUT_FD stderr 
// stdout
#define OUTPUT(...) fprintf(OUTPUT_FD, __VA_ARGS__)

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
#include <asm/ptrace.h>

// state exposed
static pid_t tracee_pid = -1;
static int tracee_argc = -1;
static char** tracee_argv = nullptr;
static bool user_requested_syscall_invocation_anyway = false;

#include "api.h"

void
__attribute__((noinline, used))
api_invoke_syscall_anyway() {
    user_requested_syscall_invocation_anyway = true;
}

pid_t
__attribute__((noinline, used))
api_get_tracee_pid() {
    return tracee_pid;
}

std::vector<std::string>
__attribute__((noinline, used))
api_get_tracee_cmdline() {
    std::vector<std::string> res;
    for(int i = 0; i < tracee_argc; i++)
        res.push_back(std::string(tracee_argv[i]));
    return res;
}

__attribute__((noinline, used))
void api_resolve_fd(pid_t pid, int fd, char* path_buf) {
    static char link_path[50] = {0};
    snprintf(link_path, 50, "/proc/%d/fd/%d", pid, fd);
    path_buf[0] = (char) 0;
    realpath(link_path, path_buf);
}

__attribute__((noinline, used))
void api_memcpy_to_tracee(pid_t pid, void* dst_tracee, void* src_tracer, size_t size) {
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

__attribute__((noinline, used))
void api_memcpy_from_tracee(pid_t pid, void* dst_tracer, void* src_tracee, size_t size) {
    // TODO - for non word-size-aligned 'count' we will write *less* bytes than expected.
    auto word_size = sizeof(arch_reg_content_t);
    auto iters = size / word_size;

    arch_reg_content_t* dst_buf = (arch_reg_content_t*) dst_tracer;
    arch_reg_content_t* src_buf = (arch_reg_content_t*) src_tracee;

    for (int i = 0; i < iters; i++) {
        arch_reg_content_t res = ptrace(PTRACE_PEEKTEXT, pid, src_buf, NULL);
        dst_buf[i] = res;
        src_buf++;
    }
}

// https://stackoverflow.com/a/66249936
#if defined(__x86_64__) || defined(_M_X64)
    #include "arch/x86_64.h"
    #include "gen/x86_64/syscall_names.h"
    #include "gen/x86_64/syscall_num_params.h"
#elif defined(__riscv__) || defined(__riscv)
    static_assert(__riscv_xlen == 64);
    #include "arch/riscv64.h"
    #include "gen/riscv64/syscall_names.h"
    #include "gen/riscv64/syscall_num_params.h"
#else
#error "Unknown architecture"
#endif

/*
syscall-like is a function to pointer of signature that
both params and return value is of 'arch_word_size' width, and number of params is <= 6.
*/
long invoke_syscall_like(void* mock_ptr, int num_params, struct user_regs_struct* user_regs) {
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
        int exit_code = WEXITSTATUS(status);
        if (exit_code)
            printf("Child process exited with status %d\n", exit_code);
        exit(exit_code);
    }

    if (WIFSTOPPED(status)) {
        auto signal = WSTOPSIG(status) & 127;
        std::vector<int> known_signals = {SIGTRAP, SIGCHLD};

        if (std::find(known_signals.begin(), known_signals.end(), signal) == known_signals.end()) {
            printf("Tracee received unexpected signal: %s (%d)\n", strsignal(WSTOPSIG(status)), WSTOPSIG(status));
            exit(1);
        }
    }
}

int get_sideeffectfree_syscall_number() {
    constexpr auto name = "getpid";
    // TODO array sizes should be auto-generated as well.
    auto num_elems = sizeof(syscall_names) / sizeof(syscall_names[0]);
    for (int i = 0; i < num_elems; i++) {
        if (strcmp(name, syscall_names[i]) == 0) {
            return i;
        }
    }
    assert(false);
}


#define NT_PRSTATUS 1 // from 'man ptrace': NT_PRSTATUS (with numerical value 1)

static void __ptrace_set_or_get_user_regs(pid_t pid, struct user_regs_struct* user_regs, bool set) {
    static struct iovec io;
    io.iov_base = user_regs;
    io.iov_len = sizeof(struct user_regs_struct);

    auto op = set ? PTRACE_SETREGSET : PTRACE_GETREGSET;

    ptrace(op, pid, (void*)NT_PRSTATUS, &io);
}

#define ptrace_set_user_regs(pid, ptr) ( __ptrace_set_or_get_user_regs(pid, ptr, true) )
#define ptrace_get_user_regs(pid, ptr) ( __ptrace_set_or_get_user_regs(pid, ptr, false) )

int main(int argc, char *argv[]) {

#ifndef VERBOSE
    close(2);
#endif

    // Perform gen/*.h sanity check.
    // TODO array sizes should be auto-generated as well.
    auto syscall_names_size = sizeof(syscall_names) / sizeof(syscall_names[0]);
    auto syscall_num_params_size = sizeof(syscall_names) / sizeof(syscall_names[0]);
    assert (syscall_names_size == syscall_num_params_size);
    int max_syscall_number = syscall_names_size - 1;

    // Check if command line arguments are valid.
    if (argc < 3) {
        printf("Usage: %s <./filterlib.so> <executable>\n", argv[0]);
        exit(1);
    }

    // Prepare state before fork.
    // NOTE: this must be done before 'dlopen', as it might have attribute((constructor))
    // that calls some API function.
    tracee_argc = argc - 2;
    tracee_argv = argv + 2; // TODO: +2 hardcoded

    // Try 'dlopen'.
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
        From 'man ptrace':

        In case of system call entry or exit stops, the data
        returned by PTRACE_GET_SYSCALL_INFO is limited to type
        PTRACE_SYSCALL_INFO_NONE unless PTRACE_O_TRACESYSGOOD
        option is set before the corresponding system call stop
        has occurred.

        NOTE: we want PTRACE_O_EXITKILL set unconditionally only until we implement
        equivalent of strace's '-p <pid>' option.
        */
        ptrace(PTRACE_SETOPTIONS, tracee_pid, NULL, PTRACE_O_TRACESYSGOOD | PTRACE_O_EXITKILL);


        // All dependency between consecutive iterations is stored in LoopState.
        struct LoopState {
            bool waiting_for_sideeffect_syscall_to_finish;
            arch_reg_content_t user_ret_val;
        };

        struct LoopState state {.waiting_for_sideeffect_syscall_to_finish = false};

        arch_reg_content_t syscall_number  = -1;

        while (1) {

            const int no_sideeffect_syscall = get_sideeffectfree_syscall_number();

            // Wait for syscall entry/exit event.
            // In first iteration it is an entry to 'execve'.
            ptrace(PTRACE_SYSCALL, tracee_pid, NULL, NULL);
            waitpid(tracee_pid, &status, 0);
            check_child_alive_or_exit(status);

            // Syscall entered or exited?
            struct ptrace_syscall_info syscall_info;
            ptrace(PTRACE_GET_SYSCALL_INFO, tracee_pid, sizeof(ptrace_syscall_info), &syscall_info);
            if (syscall_info.op == PTRACE_SYSCALL_INFO_NONE) {
                // non-syscall stop. probably tracee got a signal and stopped.
                continue;
            }

            // Get some insights into what syscall tracee entered/exited.
            struct user_regs_struct user_regs;
            ptrace_get_user_regs(tracee_pid, &user_regs);

            if (syscall_info.op == PTRACE_SYSCALL_INFO_EXIT) {
                if (syscall_number == -1) {
                    // TODO - Should only be possible to happen in ATTACH mode in first loop iteration, to be verified.
                    assert(false);
                    continue;
                }
            } else {
                assert (syscall_info.op == PTRACE_SYSCALL_INFO_ENTRY);
                syscall_number = syscall_info.entry.nr;
            }
            
            if (syscall_number > max_syscall_number) {
                printf("Unexpected syscall number: 0x%llx\n", syscall_number);
                exit(1);
            }
            const char* syscall_name = syscall_names[syscall_number];
            auto& op = syscall_info.op;

            if (state.waiting_for_sideeffect_syscall_to_finish) {
                assert (op == PTRACE_SYSCALL_INFO_EXIT);
                assert (syscall_number == no_sideeffect_syscall);
            }

            if (op == PTRACE_SYSCALL_INFO_ENTRY) {

                // Check whether user has defined asstrace_<syscall_name> symbol in libfilter.so
                static char filter_symbol_name[1024];
                snprintf(filter_symbol_name, 1023, "asstrace_%s", syscall_name);
                void* user_hook = dlsym(filter_lib_handle, filter_symbol_name);
                bool invoke_mock_syscall = user_hook != nullptr;
            
                if (invoke_mock_syscall) {

                    user_requested_syscall_invocation_anyway = false;
                    fprintf(stderr, "@ %s defined (mapped to %p), passing control..\n", filter_symbol_name, user_hook);
                    arch_reg_content_t hook_ret = invoke_syscall_like(user_hook, syscall_num_params[syscall_number], &user_regs);
                    OUTPUT("intercepted %s. mock returned %lld", syscall_name, hook_ret);

                    // In normal flow the syscall was intercepted by user library, and real syscall should not be invoked.
                    bool skip_real_syscall = !user_requested_syscall_invocation_anyway;

                    if (skip_real_syscall) {
                        // make the tracee think that it returned from a real syscall.

                       *arch_syscall_number(&user_regs) = no_sideeffect_syscall;

                       syscall_number = no_sideeffect_syscall;

                        state.waiting_for_sideeffect_syscall_to_finish = true;
                        state.user_ret_val = hook_ret;
                        // *arch_pc(&user_regs) = *arch_syscall_ret_addr(&user_regs);
                    } else {
                        /*
                            NOTE:
                            'ptrace' interface does not have a platform-agnostic way
                            to prevent syscall from executing. We can change syscall number to execute
                            a different one, but supported for avoiding call to any syscall at all
                            is implemented only for x86, via 'ptrace(PTRACE_SYSEMU, ..)'.
                            Since asstrace aims to work on any CPU platform, when the syscall is to be skipped,
                            we just call a side-effect-free 'getpid()', as User-Mode-Linux does as well.
                            See https://sysemu.sourceforge.net/
                        */

                       // TODO give user register tampering capabilities
                    }

                    // whatever 'skip_real_syscall' is, update tracee registers.
                    ptrace_set_user_regs(tracee_pid, &user_regs);
                
                } else {
                    // don't interfere normal syscall execution. only log params.

                    OUTPUT("%s(", syscall_name);
                    for(int i = 0; i < syscall_num_params[syscall_number]; i++) {
                        OUTPUT("0x%llx, ", arch_fun_call_param_get(&user_regs, i));
                    }
                }

            } else if (op == PTRACE_SYSCALL_INFO_EXIT) {

                if (state.waiting_for_sideeffect_syscall_to_finish) {
                    *arch_ret_val(&user_regs) = state.user_ret_val;
                    ptrace_set_user_regs(tracee_pid, &user_regs);
                    state.waiting_for_sideeffect_syscall_to_finish = false;
                }

                OUTPUT(") = 0x%llx\n", *arch_ret_val(&user_regs));
            } else {
                printf("PTRACE_GET_SYSCALL_INFO: Unknown op: %d\n", syscall_info.op);
                continue;
            }
        }
    }

    return 0;
}
