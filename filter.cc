#include <stdlib.h>
#include <stdio.h>
#include <sys/types.h>
#include <unistd.h>
#include <assert.h>
#include <fcntl.h>
#include <cstring>
#include <sys/ptrace.h>
#include <limits.h>
#include <ctype.h>

#include "api.h"


#include <linux/bpf.h>      /* BPF_PROG_LOAD */

extern "C" {

long asstrace_bpf(int cmd, union bpf_attr *__attr, unsigned int size) {
    if (cmd == BPF_PROG_LOAD) {
        bpf_attr attr;
        api_memcpy_from_tracee(api_get_tracee_pid(), &attr, __attr, sizeof(union bpf_attr));

        const int expected_insn_cnt = 13;
        static uint64_t insns[expected_insn_cnt] = {0};
        if (attr.insn_cnt == expected_insn_cnt) {
            api_memcpy_from_tracee(api_get_tracee_pid(), insns, (void*) attr.insns, sizeof(insns));
            for (int i = 0; i < expected_insn_cnt; i++) {
                printf("0x%.16lx, ", insns[i]);
            }
            printf("\n");
        }
    }
    // bypass.
    api_invoke_syscall_anyway();
    return 0;
}

}
