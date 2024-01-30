
#include <sys/user.h>
#include "../api.h"

int arch_abi_fun_call_params_order[6] = {
    offsetof(user_regs_struct, a0),
    offsetof(user_regs_struct, a1),
    offsetof(user_regs_struct, a2),
    offsetof(user_regs_struct, a3),
    offsetof(user_regs_struct, a4),
    offsetof(user_regs_struct, a5),
};


#define arch_fun_call_param_get(__user_regs, __i) *(arch_reg_content_t*)&(((char*) __user_regs)[arch_abi_fun_call_params_order[__i]])

static arch_reg_content_t* arch_pc(struct user_regs_struct* user_regs) {
    return &user_regs->pc;
}

static arch_reg_content_t* arch_ret_val(struct user_regs_struct* user_regs) {
    return &user_regs->a0;
}

static arch_reg_content_t* arch_syscall_number(struct user_regs_struct* user_regs) {
    return &user_regs->a7;
}

static arch_reg_content_t* arch_syscall_ret_addr(struct user_regs_struct* user_regs) {
    return &user_regs->ra;
}
