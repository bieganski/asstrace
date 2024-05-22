from pathlib import Path

from asstrace import API as api, system_get_cpu_arch, CPU_Arch


if system_get_cpu_arch() == CPU_Arch.riscv64:
    intercept_replacement_pairs = [
        ("/sys/kernel/btf/vmlinux", "/root/asstrace/vm"),
    ]
elif system_get_cpu_arch() == CPU_Arch.x86_64:
    intercept_replacement_pairs = [
        # ("/sys/kernel/btf/vmlinux", "/home/m.bieganski/vm"),
    ]

for i, (a, b) in enumerate(intercept_replacement_pairs):
    
    if b is not None:
        # we must fit into the same buffer when overwriting path.
        assert len(b) <= len(a)

    intercept_replacement_pairs[i] = ( Path(a).absolute(), Path(b).absolute() )

intercept_replacement_pairs = dict(intercept_replacement_pairs)

# empirically checked, that AT_FDCWD is 
# 0xffffffffffffff9c on risc-v , 0xffffff9c on x86_64 for some reason.
AT_FDCWD_LOWER_4BYTES = 0xffffff9c

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

first = True

# def asstrace_read(fd, buf, size, *args):
#     global first
#     path = api.tracee_resolve_fd(fd)
#     if "/dev/null" in path:
#         print("AAAAAAAAAAAAAAAAAAAAAAAAAAA")
#     else:
#         api.invoke_syscall_anyway()
#         return
#     if first:

#         api.ptrace_write_mem(buf, "666\n")
#         first = False
#         return 4
#     else:
#         return 0
    

def generic_proxy(dfd, filename, mode):
    assert not ((dfd & 0xffff_ffff) ^ AT_FDCWD_LOWER_4BYTES)
    path = api.ptrace_read_null_terminated(filename, 1024).decode("ascii")
    path = Path(path).absolute()
    # print(f"generic_proxy: {path}, mode:{mode}")
    if path not in intercept_replacement_pairs:
        api.invoke_syscall_anyway()
        # print(f"generic_proxy: no replacement found.")
        return
    replacement = intercept_replacement_pairs[path]
    print(f">> generic_proxy: replacement {replacement}")
    if not Path(replacement).exists():
        raise ValueError(f"{replacement} does not exist! TODO: error might be false, if tracee is in different FS namespace.")
    api.ptrace_write_mem_null_terminated(filename, bytes(str(replacement), encoding="ascii"))
    api.invoke_syscall_anyway()

def asstrace_faccessat2(dfd, filename, mode, *_):
    return generic_proxy(dfd, filename, mode)

def asstrace_open(*_):
    raise ValueError("Expected 'openat', not 'open'")

def asstrace_openat(dfd, filename, flags, *_):
    global first
    first = True
    return generic_proxy(dfd, filename, flags)
    
