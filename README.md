# About
`asstrace` stands for **a** **s**tateful **strace**-like - Linux syscall tampering-first `strace`-like tool.

As opposed to `strace`, `asstrace` alters binary behavior by being "man in the middle" of binary and operating system. If your goal is to understand why some black-box binary is not working as expected, then `strace` with all it's advanced features is the way to go.

`asstrace` is designed to **provide a convenient way of altering binary behavior and sharing it to other people**.

It doesn't change the binary itself, but allows for manipulating behavior of system calls that the binary executes.
`asstrace` is designed to work with `Linux`. Currently `x86` and `RISC-V` are supported.

# Example use cases

* legacy executable which source code is not available no longer works on modern workstations, as it assumes presence of some special files (sockets, device character special etc.). We can intercept all system calls touching that particular device and provide our own implementation that emulate the device (all the emulation is in user mode).

* black-box executable does not work because inside a binary there are IP address and port hardcoded, that are no longer accessible as the service moved to a different server. We can intercept network system calls that try to access non-existing address, and change it so that the new address is used.

* black-box executable does some computation, and as a result it creates a single output file. During computation it creates lots of meaningful temporary files, but unfortunately it deletes them all before output is produced. Using `asstrace` we can intercept all `unlink` system calls and cause them to do nothing. This way no temporary files get removed! [[go to example]](#unlink-example)

# `unlink` example

In this example we run `gcc`, but prevent it from deleting temporary files.

The command used: `echo "int main();" | ./asstrace.py -q  -ex 'unlink:nop:msg=prevented {path} from deletion' -- gcc  -o a.out -x c -c -`

![unlink example](jpg/unlink.png)


# `pathsubst` example

Often in order to get some functionality, we need to hook more than a single syscall. For such purpose `asstrace` defines concept of groups, available by `-g` CLI param.
Here we use `pathsubst`, that hooks `open`, `openat`, `faccessat2` and `statx`.

The command used is `./asstrace.py -qq  -g 'pathsubst:old=zeros,new=abc' -- cat zeros`

![pathsubst example](jpg/pathsubst.png)


# `count_lines` example

In this example we manipulate `ls -1` command, so that for each regular file that it prints it will include metadata: number of lines.

The command used: `./asstrace.py -qq -x examples/count_lines.py ls -1`

![count_lines example](jpg/count_lines.png)

The code of `write` syscall in `count_lines` example is slightly more complicated, thus not suitable for `--ex` as previously. Instead we have a Python file that can use `API` functionality:

```py
# examples/count_lines.py

from pathlib import Path
from asstrace import API

# defining function called asstrace_X will make a hook for syscall named 'X'.
# hook will be executed before each entry to 'X'.
def asstrace_write(fd, buf, num, *_):
    if fd != 1:
        # not interesting to use - we care about stdout only.
        API.invoke_syscall_anyway() # jump to 'write' with default params
        return
    path = Path(API.ptrace_read_mem(buf, num)[:-1].decode("ascii")) # strip '\n' and decode from bytes
    if not path.is_file():
        # probably a directory - follow default execution path
        API.invoke_syscall_anyway()
        return
    try:
        num_lines = len(path.read_text().splitlines())
    except UnicodeDecodeError:
        # raw-bytes file - number of lines doesn't make sense for it.
        API.invoke_syscall_anyway()
        return
    
    # if we are here, it means that our file is regular, UTF-8, and has 'num_lines' lines.
    # print it to stdout instead of default 'buf'.
    res_str = f"{path}({num_lines})\n"
    print(res_str, end="")

    # 'ls -1' program will think that it has written 'len(res_str)' characters,
    # as 'write' syscall returns number of characters really written (see 'man write').
    return len(res_str)

```

# Few more examples

```
-ex 'open,openat:delay:time=0.5'        - invoke each 'open' and 'openat' syscall as usual, but sleep for 0.5s before each invocation
-ex 'unlink:nop'                        - 'unlink' syscall will not have any effect. value '0' will be returned to userspace.
-ex 'mmap:nop:ret=-1'                   - 'mmap' syscall will not have any effect. value '-1' will be returned to userspace (fault injection; see 'man mmap').
-ex 'open:nop:ret=-1' -ex read:detach   - fail each open, detach on first read
```

# Verbose mode

When invoking without `-q` or `-qq` params `asstrace.py` will print all syscalls executed to stderr, in similar manner as `strace` do (but without fancy beautifying):

```bash
m.bieganski@test:~/github/asstrace$ ./asstrace.py ls
openat(0xffffff9c, 0x7f4883e8d660, 0x80000, 0x0, 0x80000, 0x7f4883e8d660) = 0x3
read(0x3, 0x7ffd70b6e9b8, 0x340, 0x0, 0x80000, 0x7f4883e8d660) = 0x340
pread64(0x3, 0x7ffd70b6e5c0, 0x310, 0x40, 0x7ffd70b6e5c0, 0x7f4883e8d660) = 0x310
pread64(0x3, 0x7ffd70b6e580, 0x30, 0x350, 0x7ffd70b6e5c0, 0x0) = 0x30
pread64(0x3, 0x7ffd70b6e530, 0x44, 0x380, 0x7ffd70b6e5c0, 0x0) = 0x44
newfstatat(0x3, 0x7f4883ebdee9, 0x7ffd70b6e850, 0x1000, 0x7f4883e8d660, 0x7f4883eca2e0) = 0x0
pread64(0x3, 0x7ffd70b6e490, 0x310, 0x40, 0xc0ff, 0x7f4883e8db08) = 0x310
mmap(0x0, 0x228e50, 0x1, 0x802, 0x3, 0x0) = 0x7f4883c00000
mprotect(0x7f4883c28000, 0x1ee000, 0x0, 0x802, 0x3, 0x0) = 0x0
...
```


# User Guide

See [user guide](./USER_GUIDE.md) for more details.

# Distribution

* MIT license
* to make `asstrace` run on your Linux only a single file is needed (`asstrace.py`)*
* no external Python dependencies - no need for `requirements.txt` etc.
* no native code - only CPython interpreter is required
* cross platform - adding a new target is as simple as defining CPU ABI:

```py
    CPU_Arch.riscv64: CPU_ABI(
        user_regs_struct_type=riscv64_user_regs_struct,
        syscall_args_registers_ordered=[f"a{i}" for i in range(6)],
        syscall_number="a7",
        syscall_ret_val="a0",
        syscall_ret_addr="ra",
        pc="pc",
    )
```

* the `*` gotcha is that it needs additionaly `syscall_names.csv`. It either seeks it locally (will fork if obtained `asstrace` via `git clone`) or downloads directly from GitHub (url is hardcoded in `asstrace.py`).