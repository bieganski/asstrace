from pathlib import Path
from asstrace import API

def asstrace_write(fd, buf, num, *_):
    if fd != 1:
        # capture stdout only
        return
    path = Path(API.ptrace_read_mem(buf, num)[:-1].decode("ascii")) # strip '\n' and decode from bytes
    if not path.is_file():
        API.invoke_syscall_anyway()
    else:
        num_lines = len(path.read_text().splitlines())
        res_str = f"{path}({num_lines})\n"
        print(res_str, end="")
        return len(res_str) # 'ls -1' program will think that it has written that many characters. 