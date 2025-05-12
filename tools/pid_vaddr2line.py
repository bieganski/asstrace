#!/usr/bin/env python3

import subprocess
from pathlib import Path
import logging
import sys

sys.path.append(str(Path(__file__).parent.parent.resolve()))

from find_pattern_offset import file_pattern_match_find_single_offset
from objdump_wrapper import system_invoke_objdump_or_use_cached, parse_objdump_output, addr2line

logging.basicConfig(level=logging.INFO)

def run_shell(cmd: str) -> tuple[str, str]:
    process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True, universal_newlines=True)
    stdout, stderr = process.communicate()
    if (ecode := process.returncode):
        raise ValueError(f"Command <{cmd}> exited with {ecode}")
    return stdout, stderr

Map_proc_pid_maps = dict[tuple[int, int], tuple[Path, int]]

def system_proc_pid_maps_get_regions(pid: int) -> dict[tuple[int, int], tuple[Path, int]]:
    """
    NOTE: whenever anything more functionality from /proc/PID/maps will be needed,
    # please do not reinvent the wheel and use proper parsing, for example https://gist.github.com/fxthomas/3c915909bbf84bc14782cb6adef0f915 instead.

    returns a mapping from (start, end) to (path, file offset).
    """
    res = dict()
    lines = Path(f"/proc/{pid}/maps").read_text().splitlines()
    for l in lines:
        tokens = l.split()
        if len(tokens) < 6:
            continue # don't care about anonymous mappings
        start, end = tokens[0].split("-")
        start, end = int(start, 16), int(end, 16)
        offset = int(tokens[2], 16)
        # XXX: here we assume path not to contain spaces
        res[(start, end)] = (Path(tokens[-1]), offset)
    return res

def find_offset_within_elf(map: Map_proc_pid_maps, vaddr: int) -> tuple[Path, int]:
    """
    for a given @vaddr and /proc/PID/maps @map representation, returns both a path to ELF whose segment was mmapped and contains @offset
    and a file offset corresponding to @vaddr.
    """
    matches = []
    for region in map:
        start, end = region
        if start <= vaddr < end:
            matches.append(region)

    if len(matches) != 1:
        raise RuntimeError(f"Was expecting exactly one match, got {len(matches)} instead")

    region = matches[0]
    start, end = region
    elf, file_offset = map[region]

    # @start corresponds to @file_offset, and we are @(vaddr - start) bytes above.
    seeked_file_offset = file_offset + (vaddr - start)
    logging.info(f"vaddr={hex(vaddr)} corresponds to file_off={hex(seeked_file_offset)} in {elf}")
    return elf, seeked_file_offset


def main(pid: int, vaddr: int, objdump_executable: Path):

    vaddr_elf, file_offset = find_offset_within_elf(map=system_proc_pid_maps_get_regions(pid=pid), vaddr=vaddr)

    objdump_raw_output = system_invoke_objdump_or_use_cached(objdump_executable=objdump_executable, elf_file=vaddr_elf)
    objdump_parsed_output = parse_objdump_output(objdump_raw_output)

    f = addr2line(file_offset=file_offset, objdump_output=objdump_parsed_output)
    print(f)

if __name__ == "__main__":
    from argparse import ArgumentParser
    parser = ArgumentParser(usage="XXX")
    parser.add_argument("pid", type=int)
    parser.add_argument("vaddr", type=lambda x: int(x, 16))
    parser.add_argument("-d", "--objdump-executable", type=Path, help="path to 'objdump' executable, useful if using one from cross-toolchain (e.g. RISC-V)", default="objdump")
    main(**vars(parser.parse_args()))
