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