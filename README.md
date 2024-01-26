# About
`asstrace` stands for **a** **s**tateful **strace**-like - Linux syscall tampering-first `strace`-like tool.

As opposed to `strace`, `asstrace` is more of a framework tool than a debugging tool. If your goal is to see why some black-box binary is not working, then `strace` with all it's advanced features is the way to go.

`asstrace` is designed to **provide a convenient way of altering binary behavior and sharing it to other people**.

It doesn't change the binary itself, but allows for manipulating behavior of system calls that the binary executes.
`asstrace` is designed to work with `Linux`. For now only `x86_64` is supported, but `asstrace` is designed in a way that adding a new architecture is straightforward.

# Example use cases

* legacy executable which source code is not available no longer works on modern workstations, as it assumes presence of some special files (sockets, device character special etc.). We can intercept all system calls touching that particular device and provide our own implementation that emulate the device (all the emulation is in user mode).

* legacy black-box executable does not work because inside a binary there are IP address and port hardcoded, that are no longer accessible as the service moved to a different server. We can intercept network system calls that try to access non-existing address, and change it so that the new address is used.[[sample run]](#network_forwarding-example) [[source code]](./examples/network_forwarding.cc)

* black-box executable does some computation, and as a result it creates a single output file. During computation it creates lots of meaningful temporary files, but unfortunately it deletes them all before output is produced. Using `asstrace` we can intercept all `unlink` system calls and cause them to do nothing. This way no temporary files get removed! [[sample run]](#unlink-example) [[source code]](./examples/unlink.cc)

# `unlink` example

In this example we run `g++ ./asstrace.cc`, but prevent it from deleting temporary files.

```bash
myuser@myhost:~/asstrace$ make example_unlink
g++ -rdynamic -fpermissive asstrace.cc -o asstrace
make -C examples unlink
g++ -I.. -shared -fPIC unlink.cc -o libunlink.so
../asstrace ./libunlink.so g++ ../asstrace.cc 2>/dev/null | grep prevented
>> prevented /tmp/ccpiWX9G.res from removing!
>> prevented /tmp/cckCJl7b.o from removing!
>> prevented /tmp/ccVwSoa6.s from removing!
myuser@myhost:~/github/asstrace$
myuser@myhost:~/github/asstrace$ file /tmp/cckCJl7b.o
/tmp/cckCJl7b.o: ELF 64-bit LSB relocatable, x86-64, version 1 (SYSV), not stripped
```

We managed to prevent GCC from removing artifacts from `/tmp/` directory. [See source code](./examples/unlink.cc)

# `network_forwarding` example

In this example we run two processes: background `nc -l -p 8000` (server listening on `127.0.0.1:8000`), and a `echo payload | nc -N 1.1.1.1 80` that tries to connect to `1.1.1.1:80` and send it some payload.

Of course there is an address mismatch, so server won't receive any data, until we tamper client execution with `asstrace`.

```bash
myuser@myhost:~$ make example_net
g++ -rdynamic -fpermissive asstrace.cc -o asstrace
make -C examples network_forwarding
bash -c "nc -l -p 8000 ; echo NETCAT SERVER RECEIVED DATA!" &
g++ -I.. -shared -fPIC network_forwarding.cc -o libnet.so
echo "<I am the payload>" | ../asstrace ./libnet.so nc -N 1.1.1.1 80 2>/dev/null
>> network forwarding: 1.1.1.1:80 -> 127.0.0.1:8000
<I am the payload>
NETCAT SERVER RECEIVED DATA!
myuser@myhost:~$
myuser@myhost:~$
```

With `asstrace` in the loop server successfully read the data. [See source code](./examples/network_forwarding.cc).

# `to_uppercase` example


### Build

```bash
myuser@myhost:~/asstrace$ make
g++ -shared -fPIC filter.cc -o libfilter.so        # compile application-specific user library
g++ -rdynamic -fpermissive asstrace.cc -o asstrace # compile generic 'asstrace' engine
```

### Run

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

We provide an example user library (`libfilter.so`) that is designed to cause `cat <filename>` program to show the contents of `<filename>`, but make it uppercase. It does the following steps:

* It intercepts only `read` syscalls.
* On each `read(fd, ...)`, it checks to which file `/proc/pid/fd` points to.
* If `fd` points to `<filename>` it does special action, otherwise it allows `cat` program to execute `read` as usual (it will talk to kernel as nothing happened)
* Special action goes as follows: If this is a first `read(fd, buf, count)` to that file then open the `<filename>` itself (otherwise is is already opened), and read up to `count` bytes from it to some temporary buffer. Then transform all the ASCII characters from that buffer to uppercase, then copy it back to `cat` program address space (using helper `api_memcpy_to_tracee`). The `cat` program returns from `read` syscall, and in it's buffer it has uppercase data from `<filename>`.

[See source code](./filter.cc)

# User Guide

See [user guide](./USER_GUIDE.md) for more details.