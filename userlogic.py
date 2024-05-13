from pathlib import Path

from test import API as api

INTERCEPT_PATH = Path("/sys/kernel/btf/vmlinux").absolute()
REPLACEMENT_PATH = Path("/home/m.bieganski/vm").absolute()

# we must fit into the same buffer when overwriting path.
assert len(str(INTERCEPT_PATH)) >= len(str(REPLACEMENT_PATH)), (str(INTERCEPT_PATH), str(REPLACEMENT_PATH))

AT_FDCWD = 0xffffff9c

# def asstrace_write(fd, buf, size, *_):
#     path = api.tracee_resolve_fd(fd)
#     print(f"inside asstrace_write of size {size} to fd={fd} (that corresponds to {path})")
#     api.patch_tracee_syscall_params(size=2)
#     old_data = api.ptrace_read_mem(buf, size)
#     new_data = 'A' * size
#     print(f"replacing '{old_data}' with '{new_data}'")
#     api.ptrace_write_mem(buf, size, bytes(new_data, encoding="ascii"))
#     api.invoke_syscall_anyway()
#     return size

def generic_proxy(dfd, filename):
    assert dfd == AT_FDCWD
    path = api.ptrace_read_null_terminated(filename, 1024).decode("ascii")
    path = Path(path).absolute()
    if path != INTERCEPT_PATH:
        api.invoke_syscall_anyway()
        return
    api.ptrace_write_mem_null_terminated(filename, bytes(str(REPLACEMENT_PATH), encoding="ascii"))
    api.invoke_syscall_anyway()

def asstrace_faccessat2(dfd, filename, mode, flags, *args):
    return generic_proxy(dfd, filename)

def asstrace_open(*_):
    raise ValueError("Expected 'openat', not 'open'")

def asstrace_openat(dfd, filename, flags, *_):
    return generic_proxy(dfd, filename)
    
