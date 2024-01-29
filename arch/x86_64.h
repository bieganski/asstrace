
#include <sys/user.h>
#include "../api.h"

int arch_abi_fun_call_params_order[6] = {
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
