#!/usr/bin/env python3

import subprocess
from pathlib import Path
import logging
import sys

sys.path.append(str(Path(__file__).parent.parent.resolve()))

from find_pattern_offset import file_pattern_match_find_single_offset
from objdump_wrapper import system_invoke_objdump_or_use_cached, parse_objdump_output, addr2line
from asstrace import _read_or_write_process_memory

logging.basicConfig(level=logging.INFO)

def run_shell(cmd: str) -> tuple[str, str]:
    process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True, universal_newlines=True)
    stdout, stderr = process.communicate()
    if (ecode := process.returncode):
        raise ValueError(f"Command <{cmd}> exited with {ecode}")
    return stdout, stderr

def pid_read_enough_to_identify(pid: int, vaddr: int) -> bytes:
    num_bytes_enough = 32
    return _read_or_write_process_memory(address=vaddr, size=num_bytes_enough, data=bytes(), pid=pid, do_write=False)

def main(pid: int, vaddr: int, elf: Path, objdump_executable: Path):
    if not elf.exists():
        raise ValueError(f"{elf} does not exist")

    # signature matching is low effort (and error-prone) solution - proper one should parse /proc/pid/maps.
    signature = pid_read_enough_to_identify(pid=pid, vaddr=vaddr)
    file_offset = file_pattern_match_find_single_offset(content=elf.read_bytes(), pattern=signature)

    objdump_raw_output = system_invoke_objdump_or_use_cached(objdump_executable=objdump_executable, elf_file=elf)
    objdump_parsed_output = parse_objdump_output(objdump_raw_output)

    f = addr2line(file_offset=file_offset, objdump_output=objdump_parsed_output)
    print(f)

if __name__ == "__main__":
    from argparse import ArgumentParser
    parser = ArgumentParser(usage="XXX")
    parser.add_argument("pid", type=int)
    parser.add_argument("vaddr", type=lambda x: int(x, 16))
    parser.add_argument("elf", type=Path)
    parser.add_argument("-d", "--objdump-executable", type=Path, help="path to 'objdump' executable, useful if using one from cross-toolchain (e.g. RISC-V)", default="objdump")
    main(**vars(parser.parse_args()))
