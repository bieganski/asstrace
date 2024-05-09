#!/usr/bin/env python3

import subprocess
from pathlib import Path
import logging
from copy import copy
import signal
import ctypes
import sys
import os
import time
from types import ModuleType
from typing import Optional
import platform
from enum import Enum
from dataclasses import dataclass


logging.basicConfig(level=logging.INFO)

class ctypes_Struct_wrapper(ctypes.Structure):

    def __repr__(self) -> str:
        names = [x[0] for x in self._fields_]
        register_values = [getattr(self, name) for name in names]
        
        # adjust Array type.
        # TODO: make it sane.
        for i in range(len(register_values)):
            if not isinstance(register_values[i], int):
                register_values[i] = 0xdeafbeef

        return (",\n".join([f"{name}={hex(value)}" for name, value in zip(names, register_values) if value != 0]))

# class user_regs_wrapper(ctypes_Struct_wrapper):
#     def set() # TODO

class x86_64_user_regs_struct(ctypes_Struct_wrapper):
    _reg_names_ordered_ = ["r15", "r14", "r13", "r12", "rbp", "rbx", "r11", "r10", "r9", "r8", "rax", "rcx", "rdx", "rsi", "rdi", "orig_rax", "rip", "cs", "eflags", "rsp", "ss", "fs_base", "gs_base", "ds", "es", "fs", "gs"]
    _fields_ = [(x, ctypes.c_ulonglong) for x in _reg_names_ordered_]

class riscv64_user_regs_struct(ctypes_Struct_wrapper):
    _reg_names_ordered_ = ["pc", "ra", "sp", "gp", "tp", "t0", "t1", "t2", "s0", "s1", "a0", "a1", "a2", "a3", "a4", "a5", "a6", "a7", "s2", "s3", "s4", "s5", "s6", "s7", "s8", "s9", "s10", "s11", "t3", "t4", "t5", "t6"]
    _fields_ = [(x, ctypes.c_ulonglong) for x in _reg_names_ordered_]


class ptrace_syscall_info(ctypes_Struct_wrapper):
    _fields_ = [
        ("op", ctypes.c_uint8),
        ("pad", ctypes.c_uint8 * 3),
        ("arch", ctypes.c_uint32),
        ("instruction_pointer", ctypes.c_uint64),
        ("stack_pointer", ctypes.c_uint64),

        # actually below is union, but we only use syscall's part. 
        ("nr", ctypes.c_uint64),
        ("args", ctypes.c_uint64 * 6),
    ]


class iovec(ctypes_Struct_wrapper):
    _fields_ = [
        ("iov_base", ctypes.c_void_p),
        ("iov_len", ctypes.c_ulong)
    ]

PTRACE_PEEKTEXT   = 1
PTRACE_PEEKDATA   = 2
PTRACE_POKETEXT   = 4
PTRACE_POKEDATA   = 5
PTRACE_CONT       = 7
PTRACE_SINGLESTEP = 9
PTRACE_GETREGS    = 12
PTRACE_SETREGS    = 13
PTRACE_ATTACH     = 16
PTRACE_DETACH     = 17

PTRACE_SYSCALL = 24

PTRACE_GETREGSET = 0x4204
PTRACE_SETREGSET = 0x4205
PTRACE_SETOPTIONS = 0x4200
PTRACE_GET_SYSCALL_INFO = 0x420e

PTRACE_SYSCALL_INFO_NONE = 0
PTRACE_SYSCALL_INFO_ENTRY = 1
PTRACE_SYSCALL_INFO_EXIT = 2
PTRACE_SYSCALL_INFO_SECCOMP = 3

NT_PRSTATUS = 1 # from 'man ptrace': NT_PRSTATUS (with numerical value 1)

PTRACE_O_TRACESYSGOOD = 1
PTRACE_O_EXITKILL = 0x00100000

SIGTRAP = 5
SIGCHLD = 17
SIGSTOP = 19

class CPU_Arch(Enum):
    """
    NOTE: string value must be compatible with convention in gen/ directory.
    """
    x86_64 = "x86_64"
    riscv64 = "riscv64"
    arm = "arm"
    aarch64 = "aarch64"
    unknown = "unknown"


def system_get_cpu_arch() -> CPU_Arch:
    machine = platform.machine()
    return CPU_Arch(machine) # TODO: handle 'unknown'


@dataclass
class CPU_ABI:
    user_regs_struct_type : type[ctypes.Structure]
    syscall_args_registers_ordered: list[str]
    syscall_number: str
    syscall_ret_val: str
    syscall_ret_addr: str
    pc: str

KNOWN_ABI : dict[CPU_Arch, CPU_ABI] = {
    CPU_Arch.x86_64: CPU_ABI(
        user_regs_struct_type=x86_64_user_regs_struct,
        syscall_args_registers_ordered=["rdi", "rsi", "rdx", "rcx", "r8", "r9"],
        syscall_number="orig_rax",
        syscall_ret_val="rax",
        syscall_ret_addr="rcx", # For x86, address of instruction following SYSCALL is stored in RCX (and RFLAGS in R11). https://www.felixcloutier.com/x86/syscall
        pc="rip",
    ),

    CPU_Arch.riscv64: CPU_ABI(
        user_regs_struct_type=riscv64_user_regs_struct,
        syscall_args_registers_ordered=[f"a{i}" for i in range(6)],
        syscall_number="a7",
        syscall_ret_val="a0",
        syscall_ret_addr="ra",
        pc="pc",
    )
}

system_arch = system_get_cpu_arch()
system_abi = KNOWN_ABI[system_arch]
user_regs_struct = system_abi.user_regs_struct_type
syscall_params_getter = lambda user_regs: [getattr(user_regs, x) for x in system_abi.syscall_args_registers_ordered]

def load_maps(pid) -> list[dict]:
    handle = open('/proc/{}/maps'.format(pid), 'r')
    output = []
    for line in handle:
        line = line.strip()
        parts = line.split()
        (addr_start, addr_end) = map(lambda x: int(x, 16), parts[0].split('-'))
        permissions = parts[1]
        offset = int(parts[2], 16)
        device_id = parts[3]
        inode = parts[4]
        map_name = parts[5] if len(parts) > 5 else ''

        mapping = {
            'addr_start':  addr_start,
            'addr_end':    addr_end,
            'size':        addr_end - addr_start,
            'permissions': permissions,
            'offset':      offset,
            'device_id':   device_id,
            'inode':       inode,
            'map_name':    Path(map_name)
        }
        output.append(mapping)

    handle.close()
    return output

def system_find_self_lib(prefix: str) -> Path:
    regions = load_maps("self")
    matches = [r["map_name"] for r in regions if r["map_name"].name.startswith(prefix)]
    assert len(set(matches)) == 1
    return matches[0]

libdl = ctypes.CDLL(system_find_self_lib(prefix="ld-linux"))
libc = ctypes.CDLL(system_find_self_lib(prefix="libc"))

libc.dlopen.restype = ctypes.c_void_p
libc.dlsym.restype = ctypes.c_void_p
libc.ptrace.restype = ctypes.c_uint64
libc.ptrace.argtypes = [ctypes.c_uint64, ctypes.c_uint64, ctypes.c_void_p, ctypes.c_void_p]
ptrace = libc.ptrace


# def write_process_memory(pid, address, size, data):
#     bytes_buffer = ctypes.create_string_buffer('\x00'*size)
#     bytes_buffer.raw = data
#     local_iovec  = iovec(ctypes.cast(ctypes.byref(bytes_buffer), ctypes.c_void_p), size)
#     remote_iovec = iovec(ctypes.c_void_p(address), size)
#     bytes_transferred = libc.process_vm_writev(
#         pid, ctypes.byref(local_iovec), 1, ctypes.byref(remote_iovec), 1, 0
#     )

#     return bytes_transferred


def _ptrace_get_or_set_regs_arch_agnostic(pid: int, ref: user_regs_struct, do_set: bool):
    op = PTRACE_SETREGSET if do_set else PTRACE_GETREGSET
    v = iovec(ctypes.cast(ctypes.byref(ref), ctypes.c_void_p), ctypes.sizeof(ref))
    res = ptrace(op, pid, NT_PRSTATUS, ctypes.byref(v))
    assert res == 0, hex(res)

def ptrace_get_regs_arch_agnostic(pid: int, user_regs: user_regs_struct):
    return _ptrace_get_or_set_regs_arch_agnostic(pid=pid, ref=user_regs, do_set=False)

def ptrace_set_regs_arch_agnostic(pid: int, user_regs: user_regs_struct):
    return _ptrace_get_or_set_regs_arch_agnostic(pid=pid, ref=user_regs, do_set=True)


user_hook_requested_syscall_invocation: bool = False

def _user_api_invoke_syscall_anyway():
    global user_hook_requested_syscall_invocation
    user_hook_requested_syscall_invocation = True

class API:
    ptrace_set_regs_arch_agnostic = ptrace_set_regs_arch_agnostic
    ptrace_get_regs_arch_agnostic = ptrace_get_regs_arch_agnostic
    invoke_syscall_anyway = _user_api_invoke_syscall_anyway



def check_child_alive_or_exit(pid: int):
    stat = os.waitpid(pid, 0)
    status = stat[1]

    if os.WIFEXITED(status):
        if exit_code := os.WEXITSTATUS(status):
            print(f"Child process exited with status {exit_code}")
        exit(exit_code)
    
    if os.WIFSTOPPED(status):
        sig = os.WSTOPSIG(status) & 127
        if sig not in (known_signals := [SIGTRAP, SIGCHLD, SIGSTOP]):
            print(f"Tracee received unexpected signal: {signal.strsignal(sig)} ({sig})")
            exit(1)

def prepare_tracee(pid: int, no_fork_but_seize_running_process: bool):
    flags = PTRACE_O_TRACESYSGOOD
    if not no_fork_but_seize_running_process:
        flags |= PTRACE_O_EXITKILL
    ptrace(PTRACE_SETOPTIONS, pid, None, flags)

def get_sideeffectfree_syscall_number(arch_syscalls : dict[int, str]) -> int:
    name = "getpid"
    return dict((y, x) for x, y in arch_syscalls.items())[name]



def load_syscalls(arch : Optional[CPU_Arch] = None) -> dict[int, str]:
    """
    it will try to get it in various ways, with order as follows:
    1) check if CWD/gen/ARCH/syscall_names.csv exists
    2) download from github.com
    """

    arch = arch or system_get_cpu_arch()

    ##### try locally
    csv_to_dict = lambda lines: dict([(int(y), x) for x, y in map(lambda x: x.split(","), lines)])

    local_csv = Path(f"./gen/{arch.value}/syscall_names.csv")
    if local_csv.is_file():
        # success.
        return csv_to_dict(lines=local_csv.read_text().splitlines())

    ##### try Internet download
    url = f"https://raw.githubusercontent.com/bieganski/asstrace/main/gen/{arch.value}/syscall_names.csv"

    import requests
    response = requests.get(url)
    if response.ok:
        # success
        return csv_to_dict(response.content.decode("ascii").splitlines())

    # give up
    raise ValueError(f"Could not find syscall name,number mapping for arch {arch.value}")

if __name__ == "__main__":
    
    try:
        _, user_hooks_py_path, *args = sys.argv
    except ValueError:
        print(f"usage: {Path(__file__).name} <syscalls_to_be_intercepted.py> <command> [<arguments>]")
        exit(1)

    arch_syscalls : dict[int, str] = load_syscalls()

    import_module_str = str(Path(user_hooks_py_path).relative_to(Path("."))).removesuffix(".py").replace("/", ".")
    exec(f"import {import_module_str} as __user_hook")
    user_hook_module : ModuleType = globals()["__user_hook"] # make IDE happy.
    user_hook_names : list[str] = [x for x in dir(user_hook_module) if x.startswith("asstrace_")]

    logging.info(f"User-provided hooks: {user_hook_names}")
    
    process = subprocess.Popen(args)

    pid = process.pid

    res = ptrace(PTRACE_ATTACH, pid, None, None)

    check_child_alive_or_exit(pid)

    # TODO - implement SEIZE mode, not only spawning new process.
    # currently only supported in asstrace.cc
    no_fork_but_seize_running_process = False

    prepare_tracee(pid=pid, no_fork_but_seize_running_process=no_fork_but_seize_running_process)

    class loop_state:
        waiting_for_sideeffect_syscall_to_finish: bool = False
        user_ret_val: int = 0
    
    state = loop_state()
    sideeffectfree_syscall: int = get_sideeffectfree_syscall_number(arch_syscalls=arch_syscalls)

    while True:
        
        ptrace(PTRACE_SYSCALL, pid, None, None)
        time.sleep(0.001) # TODO: othewise sometimes PTRACE_GETREGSET fails for unknown reason.
    
        regs = user_regs_struct()
        check_child_alive_or_exit(pid)
        ptrace_get_regs_arch_agnostic(pid=pid, user_regs=regs)

        syscall_info = ptrace_syscall_info()
        ptrace(PTRACE_GET_SYSCALL_INFO, pid, ctypes.sizeof(ptrace_syscall_info), ctypes.byref(syscall_info))
        
        if syscall_info.op not in [PTRACE_SYSCALL_INFO_EXIT, PTRACE_SYSCALL_INFO_ENTRY]:
            print(f"PTRACE_GET_SYSCALL_INFO: unknown/unexpected op: {syscall_info.op}")
            continue
        
        if syscall_info.op == PTRACE_SYSCALL_INFO_ENTRY:
            
            syscall_name = arch_syscalls.get(syscall_info.nr, "unknown_syscall")

            if (user_hook_name := f"asstrace_{syscall_name}") in user_hook_names:
            
                # Reset some state.
                user_hook_requested_syscall_invocation = False

                # Actually invoke user hook.
                print(f"   @@ invoking user hook {user_hook_name}")
                user_hook_fn = getattr(user_hook_module, user_hook_name)
                hook_ret = user_hook_fn(*syscall_params_getter(regs))

                skip_real_syscall = not user_hook_requested_syscall_invocation
                
                if skip_real_syscall:
                    # Hook was invoked instead.
                    setattr(regs, system_abi.syscall_number, sideeffectfree_syscall)
                    
                    state.waiting_for_sideeffect_syscall_to_finish = True
                    state.user_ret_val = hook_ret
                else:
                    # Need to invoke real syscall as well as already invoked user hook.
                    # NOTE: the hook might have tampered with registers - need to write it back
                    pass
                
                # whatever 'skip_real_syscall' is, update tracee registers.
                ptrace_set_regs_arch_agnostic(pid, regs)
            else:
                # don't intercept a syscall - just log invocation params.
                print_end = '\n' if syscall_name.startswith("exit") else ''
                print(f"{syscall_name}({', '.join([hex(x) for x in syscall_info.args])}) = ", end=print_end, file=sys.stderr)
        
        elif syscall_info.op == PTRACE_SYSCALL_INFO_EXIT:
            if state.waiting_for_sideeffect_syscall_to_finish:
                if not isinstance(state.user_ret_val, int):
                    raise ValueError("User hook is obliged to return integer value, if real syscall is not executed")
                setattr(regs, system_abi.syscall_ret_val, state.user_ret_val)
                state.waiting_for_sideeffect_syscall_to_finish = False
            ptrace_set_regs_arch_agnostic(pid, regs)
            retval = getattr(regs, system_abi.syscall_ret_val)
            print(f"{hex(retval)}", file=sys.stderr)


    process.communicate()
    raise ValueError(process.pid)
