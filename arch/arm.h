#include <sys/user.h>
#include "../api.h"

#include <asm/ptrace.h>

// using user_regs_struct = struct pt_regs;
struct __mock_user_regs {
    uint64_t regs[31];
    uint64_t sp;
    uint64_t pc;
    uint64_t pstate;
};

#define user_regs_struct __mock_user_regs

int arch_abi_fun_call_params_order[8] = {
    offsetof(user_regs_struct, regs[0]),  // x0
    offsetof(user_regs_struct, regs[1]),  // x1
    offsetof(user_regs_struct, regs[2]),  // x2
    offsetof(user_regs_struct, regs[3]),  // x3
    offsetof(user_regs_struct, regs[4]),  // x4
    offsetof(user_regs_struct, regs[5]),  // x5
    offsetof(user_regs_struct, regs[6]),  // x6
    offsetof(user_regs_struct, regs[7]),  // x7
};

#define arch_fun_call_param_get(__user_regs, __i) *(arch_reg_content_t*)&(((char*) __user_regs)[arch_abi_fun_call_params_order[__i]])

static arch_reg_content_t* arch_pc(struct user_regs_struct* user_regs) {
    return &user_regs->pc;
}

static arch_reg_content_t* arch_ret_val(struct user_regs_struct* user_regs) {
    return &user_regs->regs[0];  // x0 contains return value
}

static arch_reg_content_t* arch_syscall_number(struct user_regs_struct* user_regs) {
    return &user_regs->regs[8];  // x8 contains syscall number
}

static arch_reg_content_t* arch_syscall_ret_addr(struct user_regs_struct* user_regs) {
    return &user_regs->regs[30];  // x30 (lr) contains return address for syscall
}
