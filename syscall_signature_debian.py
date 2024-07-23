#!/usr/bin/env python3

from typing import Optional
import subprocess
from pathlib import Path
import logging
from enum import Enum
from dataclasses import dataclass

logging.basicConfig(level=logging.INFO)

from asstrace import Signature

@dataclass
class SyscallTblRecord:
    num: int
    name: str
    fun_name: str

    @staticmethod
    def from_line(line: str) -> Optional["SyscallTblRecord"]:
        line = line.strip()
        if line.startswith("#"):
            return None
        if len(line.split()) == 3:
            logging.debug(f"Skipping unimplemented syscall {line}")
            return None
        if len(line.split()) != 4:
            logging.debug(f"Skipping bad line: '{line}'")
            return None
        num, is_x32, name, fun_name = line.split()

        if is_x32 == "x32": # legacy syscall numbers, (hopefully) not used
            return None

        if not fun_name.startswith(("sys_", "compat_")):
            logging.info(f"fun_name was expecting sys_* or compat_*, got {fun_name} instead")
        return SyscallTblRecord(num=num, name=name, fun_name=fun_name)

def parse_syscall_tbl(contents: str) -> list[SyscallTblRecord]:
    lines = contents.splitlines()
    res = [SyscallTblRecord.from_line(line) for line in lines]
    return [x for x in res if x is not None]

class SyscallCsvField(Enum):
    NAME = "name" # e.g mmap
    NUM_PARAMS = "num_params"  # e.g. 2 for syscall(a, b, c)
    NUMBER = "number"  # value of 'a' for syscall(a, ...)
    FULL = "full"  # full sginature string


def run_shell(cmd: str) -> tuple[str, str]:
    process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True, universal_newlines=True)
    stdout, stderr = process.communicate()
    if (ecode := process.returncode):
        raise ValueError(f"Command <{cmd}> exited with {ecode}")
    return stdout, stderr

def system_find_linux_headers_dir() -> Path:
    stdout, _ = run_shell(f"dpkg -S linux-headers-`uname -r`")
    lines = stdout.splitlines()
    words = [x.split() for x in lines]

    # Output contains only lines like that one below:
    # linux-headers-6.2.0-36-generic: /usr/src/linux-headers-6.2.0-36-generic/include/config/INFINIBAND_QIB_DCA
    assert all([2 == len(w) for w in words])

    # Drop 'linux-headers-6.2.0-36-generic:' part.
    words = [w[1] for w in words]

    # And '/usr/src/linux-headers-<KERNEL_VERSION_STRING>' prefix should be common for each line.
    assert all([w.startswith("/usr/src/linux-headers-")] for w in words)
    
    top_dir = Path("/".join(words[0].split("/")[:4]))

    return top_dir


def system_find_files_w_syscall_signatures() -> list[Path]:
    top_dir = system_find_linux_headers_dir()
    paths = [ (top_dir / "include/linux" / p) for p in ("syscalls.h", "compat.h") ]
    for p in paths:
        if not p.exists():
            raise ValueError(f"{p} does not exist")
        logging.debug(f"File with syscall signatures found: {p}")
    return paths

def _find_start_line(syscall: str, lines: list[str]) -> Optional[int]:
    """
    NOTE: Should work as expected if syscall == "".
    """
    for i, line in enumerate(lines):
        if line.startswith("asmlinkage") and not f"ksys_{syscall}" in line:
            # if  f"sys_{syscall}" in line or f"compat_{syscall}" in line:  <- not always is in the same line unfortunately.
            return i
    return None

def _find_end_line(start_line: int, lines: list[str]) -> int:
    for i, line in enumerate(lines[start_line:]):
        if ";" in line:
            return start_line + i
    else:
        raise ValueError("find_end_line: internal logic error")

def system_find_signature(tbl: list[SyscallTblRecord], syscall_name: str) -> Signature:
    all_signatures = system_find_all_signatures()
    matches = [x for x in tbl if x.name == syscall_name]
    assert len(matches) == 1
    return find_matching_signature(record=matches[0], signatures=all_signatures)

def system_find_all_signatures() -> list[Signature]:
    paths = system_find_files_w_syscall_signatures()
    lines = "\n".join(p.read_text() for p in paths).splitlines()
    
    cur_line, signatures = 0, []
    
    while len(lines):
        start = _find_start_line(syscall="", lines=lines)
        if start is None:
            break
        end = _find_end_line(start_line=start, lines=lines)
        signatures.append(Signature.from_line(" ".join(lines[start:(end + 1)])))
        cur_line = end + 1
        lines = lines[cur_line:]
    
    return signatures


def find_matching_signature(record: SyscallTblRecord, signatures: list[Signature]) -> Signature:
    """
    raises if no matching signature found, or if found more than one.
    """
    if record.fun_name == "sys_mmap":
        matches = [x for x in signatures if x.basename(with_sys_prefix=True) == "sys_mmap_pgoff"]
    else:
        matches = [x for x in signatures if x.basename(with_sys_prefix=True) == record.fun_name]
    if len(matches) == 1:
        return matches[0]
    logging.info(f"Was expecting to find one matching signature named {record.fun_name}, got {len(matches)} instead")
    return signatures[0]

def list_syscalls(tbl: list[SyscallTblRecord], fmt: list[SyscallCsvField]):
    all_signatures = system_find_all_signatures()
    signatures_tbl_ordered = [find_matching_signature(r, all_signatures) for r in tbl]

    res = [ [] for _ in range(len(tbl)) ]

    for fmt_variant in fmt:
        for lst, rec, sig in zip(res, tbl, signatures_tbl_ordered):
            
            match fmt_variant:
                case SyscallCsvField.NAME:
                    addend = rec.name
                case SyscallCsvField.NUM_PARAMS:
                    addend = f"{sig.num_params}"
                case SyscallCsvField.NUMBER:
                    addend = rec.num
                case SyscallCsvField.FULL:
                    addend = " ".join(sig._orig.split()).replace("asmlinkage ", "").replace("sys_io_", "").replace("sys_", "")
                
            lst.append(addend)

    for lst in res:
        print(",".join(lst))


"""
IMPORTANT NOTE:

for syscall number we use different ground truth file than for signatures.

asm/unistd_64.h only contains mapping RAX -> syscall name.
To find a signature I needed to parse include/linux/syscalls.h.

The thing is that there are discrepancies between those two, e.g the second one contains ifdefs.

Here we assume (this is true on my machine) that all syscalls from unistd64.h are included in syscalls.h,
but in syscalls.h are redundant ones.

All syscall present in unistd_64.h are present in syscalls.h.

Sometimes there is naming discrepancy between those two - e.g. 'mmap' vs 'mmap_pgoff'.
"""
if __name__ == "__main__":
    from argparse import ArgumentParser
    parser = ArgumentParser(usage="Print syscall signature to stdout.")
    parser.add_argument("-t", "--tbl", type=Path, default=Path(__file__).parent / "syscall_64.tbl")
    subparsers = parser.add_subparsers(dest='cmd', required=True)

    find = subparsers.add_parser("find", help="find chosen syscall's signature.")
    find.add_argument(dest="syscall_name", help="syscall name: e.g write, poll, etc.")
    
    list = subparsers.add_parser("list", help="write all syscalls to stdout (one word per line).")
    list.add_argument("-f", "--fmt", type=SyscallCsvField, nargs="+", choices=[x for x in SyscallCsvField], required=True)

    args = vars(parser.parse_args())
    cmd = args.pop("cmd")
    
    tbl : Path = args.pop("tbl")
    if not tbl.exists():
        raise ValueError(f"Table {tbl} does not exist!")
    
    args["tbl"] = parse_syscall_tbl(contents=tbl.read_text())
    
    if cmd == "find":
        signature = system_find_signature(**args)
        print(signature.fmt())
    elif cmd == "list":
        list_syscalls(**args)