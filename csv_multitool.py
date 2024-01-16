#!/usr/bin/env python3

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


def read_1_or_2_csv(path: Path) -> tuple[dict[int | str, int]  ,  type]:
    lines = path.read_text().splitlines()
    assert len(lines) > 0

    tokens = [x.split(",") for x in lines]

    num_tokens_unique = set(len(x) for x in tokens)

    # Number of commas in each line is the same.
    assert len(num_tokens_unique) == 1, num_tokens_unique

    num_tokens = num_tokens_unique.pop()
    del num_tokens_unique

    assert num_tokens in [1,2]

    if num_tokens == 1:
        tokens = [[*t, i] for i, t in enumerate(tokens)]
    elif num_tokens == 2:
        tokens = [[t1, int(t2)] for t1, t2 in tokens]
    
    for pair in tokens:
        if len(pair) != 2:
            raise ValueError(f"csv malformed for line: <{','.join(pair)}>. Was expecting two fields.")
    
    try:
        tokens = [(int(x), y) for x, y in tokens]
        data_type = int
    except Exception:
        data_type = str
    
    return dict(tokens), data_type
    

def toc(path: Path, array_name: str, comment: bool):
    """
    a,2
    b,3
    c,5

    will create {0: "NULL_VALUE", 1: "NULL_VALUE", 2: "a", 3: "b", 4: "NULL_VALUE", 5: "c"}

    a
    b
    c

    will create {0: "a", 1: "b", 2: "c"}
    """
    tokens, ttype = read_1_or_2_csv(path)

    if ttype == str:
        tokens = dict([(v, k) for k, v in tokens.items()])

    if ttype == int:
        data_type, null_value = "int", -1
    elif ttype == str:
        logging.info("at least one second-column field is not a 10-based integer. assuming <const char*> type.")
        data_type, null_value = "const char*", "NULL_VALUE"
    else:
        assert False

    res = [ f"{data_type} {array_name}[] = {{" ]
    for i in range(max(tokens.keys()) + 1):
        val = str(tokens.get(i, null_value))
        if data_type == "const char*":
            val = f'"{val}"' # escape if type is string.
        res.append(f"{val}, {'' if not comment else f'/* {i} */'}")
    res.append("};")

    print("\n".join(res))


if __name__ == "__main__":
    from argparse import ArgumentParser
    parser = ArgumentParser(usage="XXX")
    
    subparsers = parser.add_subparsers(dest='cmd', required=True)

    toc_parser = subparsers.add_parser("toc", help="Convert 1 or 2-column csv to C source. Print to stdout.")
    toc_parser.add_argument("-p", "--path", type=Path, required=True, help="input .csv path")
    toc_parser.add_argument("-a", "--array_name", default="data")
    toc_parser.add_argument("-c", "--comment", action="store_true")

    args = vars(parser.parse_args())
    cmd = args.pop("cmd")

    if cmd == "toc":
        toc(**args)
    else:
        assert False