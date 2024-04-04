#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include "api.h"


#include <linux/bpf.h>      /* BPF_PROG_LOAD */

extern "C" {

#define offsetof( type, member ) ( (size_t) &( ( (type *) 0 )->member ) )

long asstrace_bpf(int cmd, union bpf_attr *__attr, unsigned int size) {
    if (cmd == BPF_PROG_LOAD) {
        bpf_attr attr;
        api_memcpy_from_tracee(api_get_tracee_pid(), &attr, __attr, sizeof(union bpf_attr));

        const int expected_insn_cnt = 102;
        static uint64_t insns[expected_insn_cnt] = {0};
        if (attr.insn_cnt == expected_insn_cnt) {
            auto off = offsetof(union bpf_attr, insns);
            auto user_instr_ptr = (void* ) attr.insns;
            api_memcpy_from_tracee(api_get_tracee_pid(), insns, user_instr_ptr, sizeof(insns));
            for (int i = 0; i < expected_insn_cnt; i++) {
                printf("%d:    %p, 0x%.16llx, \n",  i, &insns[i], insns[i]);
                // printf("0x%.16llx, ",  insns[i]);
            }
            printf(" SLEEP\n");
            sleep(1000);
        }
    }
    // bypass.
    api_invoke_syscall_anyway();
    return 0;
}

}