from test import API

def asstrace_clock_nanosleep(*args):
    print([hex(x) for x in args])
    return 0