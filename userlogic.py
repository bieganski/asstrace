from test import API

def asstrace_write(fd, buf, size, *args):
    API.invoke_syscall_anyway()