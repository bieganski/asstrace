#!/usr/bin/env python3

from pathlib import Path
import logging
import re

logging.basicConfig(level=logging.INFO)

def bytes_pattern_match(pattern: bytes, content: bytes) -> list[int]:
    """
    returns all (potentially none) matches offsets.
    """
    matches = list(re.finditer(pattern=pattern, string=content))
    return [x.start() for x in matches]

def file_pattern_match_find_single_offset(content: bytes, pattern: bytes) -> int:
    res = bytes_pattern_match(pattern=pattern, content=content)
    if len(res) != 1:
        msg = f"Was expecting exactly one match, got {len(res)} instead!"
        if len(pattern) <= 16:
            msg += f" pattern checked: {pattern}"
        raise RuntimeError(msg)
    return res[0]


if __name__ == "__main__":
    from argparse import ArgumentParser
    parser = ArgumentParser(usage="will raise if could not find exactly one pattern match. on success will print a single hex number, which is file offset of start of the pattern.")
    parser.add_argument("content_file", type=Path, help="path containing a single-line human-readable hex data (e.g. 'ab00ff')")
    parser.add_argument("pattern_file", type=Path, help="blob file to match against")

    args = parser.parse_args()

    content = args.content_file.read_bytes()
    pattern = bytes.fromhex(args.pattern_file.read_text().strip())

    print(hex(file_pattern_match_find_single_offset(content=content, pattern=pattern) ))
