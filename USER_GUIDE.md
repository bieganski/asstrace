# API

There are serveral functions that names start with `api_` prefix. They are defined by framework, and user hooks can use them. Most important ones:

* `patch_tracee_syscall_params` - will jump to kernel with modified syscall arguments.
* `ptrace_set_regs_arch_agnostic` / `ptrace_set_regs_arch_agnostic` - access/modify registers, just before jumping to syscall kernel routine
* `ptrace_read_mem` / `ptrace_write_mem` - access/modify memory of tracee program
* `detach` - detach debugger. program will still run, and other debugger can connect (e.g. `gdb`).
* `register_hook` - change syscall's hook in runtime.
# Limitations

`asstrace` is in early stage of development and there are many features missing.
Below is a list with all entries possible (and often easy) to implement, but still missing:

* We can trace only single-process programs (missing `strace -f` equivalent)
* We miss any kind of syscall logging formatting (`strace`'s params like `-e`, `-y` and many many more). I'm not sure though if I would accept such change - it's probably out of scope of `asstrace`, as for debugging `strace` should be used - `asstrace` is meant to be binary compatibility layer.