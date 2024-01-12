#!/usr/bin/env python3

from typing import Optional
import subprocess
from pathlib import Path
import logging

logging.basicConfig(level=logging.INFO)

def run_shell(cmd: str) -> tuple[str, str]:
    process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True, universal_newlines=True)
    stdout, stderr = process.communicate()
    if (ecode := process.returncode):
        raise ValueError(f"Command <{cmd}> exited with {ecode}")
    return stdout, stderr

def main(syscall: str):
    stdout, _ = run_shell(f"dpkg -S linux-headers-`uname -r`")
    lines = stdout.splitlines()
    words = [x.split() for x in lines]

    # Output contains only lines like that one below:
    # linux-headers-6.2.0-36-generic: /usr/src/linux-headers-6.2.0-36-generic/include/config/INFINIBAND_QIB_DCA
    assert all([2 == len(w) for w in words])

    words = [w[1] for w in words]

    # And '/usr/src/linux-headers-<KERNEL_VERSION_STRING>' prefix should be common for each line.
    assert all([w.startswith("/usr/src/linux-headers-")] for w in words)
    
    top_dir = Path("/".join(words[0].split("/")[:4]))
    syscall_signatures = top_dir / "include" / "linux" / "syscalls.h"

    assert syscall_signatures.exists()

    del lines, words

    lines = syscall_signatures.read_text().splitlines()

    def find_start_line(syscall: str, lines: list[str]) -> Optional[int]:
        for i, line in enumerate(lines):
            if line.startswith("asmlinkage") and f"sys_{syscall}(" in line and not f"ksys_{syscall}(" in line:
                return i
        return None

    def find_end_line(start_line: int, lines: list[str]) -> int:
        for i, line in enumerate(lines[start_line:]):
            if ";" in line:
                return start_line + i
        else:
            raise ValueError("find_end_line: internal logic error")

    syscall = syscall[4:] if syscall.startswith("sys_") else syscall
    start = find_start_line(syscall, lines)
    if start is None:
        raise ValueError(f"Could not find syscall {syscall} in {syscall_signatures}")
    end = find_end_line(start, lines)
    

    signature = " ".join(lines[start:(end + 1)])

    def fmt_signature(signature: str):
        assert len(signature.splitlines()) == 1
        words = signature.split()
        
        assert words[0] == "asmlinkage"
        assert words[2].startswith("sys_")

        # Apply transformations.
        words[2] = words[2][4:]
        words = words[1:]
        words = [x for x in words if x != "__user"]
        return " ".join(words)

    print(fmt_signature(signature))

    
if __name__ == "__main__":
    from argparse import ArgumentParser
    parser = ArgumentParser(usage="Print syscall signature to stdout.")
    parser.add_argument(dest="syscall", help="syscall name: e.g write, poll, etc.")
    main(**vars(parser.parse_args()))
