# About
`asstrace` stands for **a** **s**tateful **strace**-like - Linux syscall tampering-first `strace`-like tool.

As opposed to `strace`, `asstrace` is more of a framework tool than a debugging tool. If your goal is to see why some black-box binary is not working, then `strace` with all it's advanced features is the way to go.

`asstrace` is designed to **provide a convenient way of altering binary behavior and sharing it to other people**.

It doesn't change the binary itself, but allows for manipulating behavior of system calls that the binary executes.
`asstrace` is designed to work with `Linux`. For now only `x86_64` is supported, but `asstrace` is designed in a way that adding a new architecture is straightforward.

# Example use cases

* legacy executable which source code is not available no longer works on modern workstations, as it assumes presence of some special files (sockets, device character special etc.). We can intercept all system calls touching that particular device and provide our own implementation that emulate the device (all the emulation is in user mode).

* legacy black-box executable does not work because inside a binary there are IP address and port hardcoded, that are no longer accessible as the service moved to a different server. We can intercept network system calls that try to access non-existing address, and change it so that the new address is used.

* black-box executable does some computation, and as a result it creates a single output file. During computation it creates lots of meaningful temporary files, but unfortunately it deletes them all before output is produced. Using `asstrace` we can intercept all `unlink` system calls and cause them to do nothing. This way no temporary files get removed!

# Build

```bash
user@host:~/asstrace$ make
g++ -shared -fPIC filter.cc -o libfilter.so        # compile application-specific user library
g++ -rdynamic -fpermissive asstrace.cc -o asstrace # compile generic 'asstrace' engine
```

# Run `to_uppercase` example

We provide an example user library (`libfilter.so`) that is designed to cause `cat <filename>` program to show the contents of `<filename>`, but make it uppercase. It does the following steps:

* It intercepts only `read` syscalls.
* On each `read(fd, ...)`, it checks to which file `/proc/pid/fd` points to.
* If `fd` points to `<filename>` it does special action, otherwise it allows `cat` program to execute `read` as usual (it will talk to kernel as nothing happened)
* Special action goes as follows: If this is a first `read(fd, buf, count)` to that file then open the `<filename>` itself (otherwise is is already opened), and read up to `count` bytes from it to some temporary buffer. Then transform all the ASCII characters from that buffer to uppercase, then copy it back to `cat` program address space (using helper `api_memcpy_to_tracee`). The `cat` program returns from `read` syscall, and in it's buffer it has uppercase data from `<filename>`.


`make run` below will run `./asstrace ./libfilter.so cat asstrace.cc` twice, showing either `stdout` only or `stderr` only.

```
user@host:~/asstrace$ make run
./asstrace ./libfilter.so cat asstrace.cc 2>/dev/null | head
#INCLUDE <STDIO.H>
#INCLUDE <STDLIB.H>
#INCLUDE <STRING.H>
#INCLUDE <UNISTD.H>
#INCLUDE <SYS/TYPES.H>
#INCLUDE <SYS/WAIT.H>
#INCLUDE <SYS/USER.H>
#INCLUDE <SYS/SYSCALL.H>
#INCLUDE <ASSERT.H>
#INCLUDE <DLFCN.H>
-------------------------------------
./asstrace ./libfilter.so cat asstrace.cc 2>&1 >/dev/null | head
execve(0x7ffc0bc327e0, 0x7ffc0bc32dc8, 0x7ffc0bc32de0, ) = 0xfffffffffffffffe
execve(0x7ffc0bc327e0, 0x7ffc0bc32dc8, 0x7ffc0bc32de0, ) = 0xfffffffffffffffe
execve(0x7ffc0bc327e0, 0x7ffc0bc32dc8, 0x7ffc0bc32de0, ) = 0xfffffffffffffffe
execve(0x7ffc0bc327e0, 0x7ffc0bc32dc8, 0x7ffc0bc32de0, ) = 0xfffffffffffffffe
execve(0x7ffc0bc327e0, 0x7ffc0bc32dc8, 0x7ffc0bc32de0, ) = 0xfffffffffffffffe
execve(0x7ffc0bc327e0, 0x7ffc0bc32dc8, 0x7ffc0bc32de0, ) = 0xfffffffffffffffe
execve(0x7ffc0bc327e0, 0x7ffc0bc32dc8, 0x7ffc0bc32de0, ) = 0x0
brk(0x0, ) = 0x5600c1c0c000
arch_prctl(0x3001, 0x7ffc628086a0, ) = 0xffffffffffffffea
mmap(0x0, 0x2000, 0x3, 0x7fe9e6effcd7, 0xffffffff, 0x0, ) = 0x7fe9e6ed7000

```


# `to_uppercase` source code with explanations

```c++

#include "api.h"

static char resolved_target[PATH_MAX];
static char resolved_path[PATH_MAX];

/*
For demo purpose we run 'cat <filename>' program (see Makefile).
We capture and modify only writes to  <filename>, so resolve it on library load time,
and then in each 'read' call check if associated file descriptor corresponds to that resolved file.
*/
static void
__attribute__((constructor))
on_dlopen() {
    auto cmdline_vec = api_get_tracee_cmdline();
    assert (!cmdline_vec.empty());
    assert (realpath(cmdline_vec.back().c_str(), resolved_target));
}

static void buf_to_uppercase(char* buf, size_t size) {
    for (int i = 0; i < size; i++) {
        char& cur = buf[i];
        if (isalpha(cur))
            cur = toupper(cur);
    }
}


extern "C" {

long asstrace_read(unsigned int fd, char *buf, size_t count) {

    pid_t pid = api_get_tracee_pid();

    api_resolve_fd(pid, fd, resolved_path);

    bool should_bypass = (strncmp(resolved_path, resolved_target, PATH_MAX) != 0);

    if (should_bypass) {
        // tracee reads from file that we don't care about - let it go.
        api_invoke_syscall_anyway();
        return 1234; // return value won't be used in that case.
    }

    char* malloc_buf = (char*) malloc(count);
    assert (malloc_buf);

    // open only once ...
    static int my_fd = open(resolved_path, O_RDONLY);
    // ... read every time.
    int real_count = read(my_fd, malloc_buf, count);

    // transform all read bytes to uppercase.
    buf_to_uppercase(malloc_buf, real_count);

    api_memcpy_to_tracee(pid, buf, malloc_buf, real_count);

    free(malloc_buf);
    return real_count; // 'tracee' will see that value, as a result of it's call to 'read()'
}

}

```