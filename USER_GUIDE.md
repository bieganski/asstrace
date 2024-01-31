# Usage scenarios

```bash
# Spawn and trace 'head -n 1 /etc/passwd' in READ-ONLY mode (no syscalls are intercepted and mocked).
make empty_filter # creates empty_libfilter.so
./asstrace ./empty_libfilter.so head -n 1 /etc/passwd
```

```bash
# Spawn and trace 'head -n 1 /etc/passwd' with user-defined mocks.
./asstrace ./path/to/filter.so head -n 1 /etc/passwd
```

```bash
# Trace already running `ping` program (assuming that exactly one such is running).
./asstrace ./path/to/filter.so `pidof ping`
```

# `asstrace` internally
`asstrace` uses [`ptrace` system call](https://man7.org/linux/man-pages/man2/ptrace.2.html) to take control over specific process (they are called 'tracer' and 'tracee' respectively). This is the main limitation that it is bound to Linux (or any OS implementing `ptrace`). Similar tools, like `gdb` or `strace` use same `ptrace` interface to gain control over process.

`asstrace` consists of two main parts: engine (called **framework**) and user-provided library (called **filter**). Implementing an application requires user to make filter only, and let it be dynamically loaded by framework in runtime (via `dlopen` syscall).

For user convenience, filter is boilerplate-free (as much as C/C++ is). Empty filter file is a valid filter (try `echo "" > filter.cc; make -B ; make run`). In that case it exports no symbols (in particular no symbols that name starts with `asstrace_`), and no syscalls will be intercepted. The `asstrace` will run in read-only mode - just monitoring syscalls and logging it to stderr.

In order to capture `read` syscall, the filter library must expose `asstrace_read` symbol (called **mock** function). (NOTE: Due to `C++` name mangling `extern "C" {}` blocks are used). If framework will see that tracee is entering `read` syscall, it will first jump to `asstrace_read`, and then based on it's behavior either skip real `read` syscall or execute it anyway (possibly with modified parameters). Default behavior is that real syscall is skipped, unless mock called `api_invoke_syscall_anyway` function, to notify framework that 1) return value from mock should be discarded, 2) real syscall should be invoked. With default behavior the syscall return value that tracee sees is return value of mock invocation.

# API

There are serveral functions that names start with `api_` prefix. They are defined by framework, and filter can use them. Signatures are defined in [api.h](./api.h) file. Example API function is `memcpy`, either to tracee or from tracee. We need it as tracer and tracee are separate Linux processes, and pointer valid in tracee is not valid in tracer's address space.

# Limitations

`asstrace` is in early stage of development and there are many features missing.
Below is a list with all entries possible (and often easy) to implement, but still missing:

* We can trace only single-process programs (missing `strace -f` equivalent)
* We miss any kind of syscall logging formatting (`strace`'s params like `-e`, `-y` and many many more). I'm not sure though if I would accept such change - it's probably out of scope of `asstrace`, as for debugging `strace` should be used - `asstrace` is meant to be binary compatibility layer.