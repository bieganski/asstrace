#!/usr/bin/env python3

import argparse
import sys
from pathlib import Path

sys.path.append(str(Path(__file__).parent.parent.resolve()))
from asstrace import _read_or_write_process_memory

def main():
    parser = argparse.ArgumentParser(description="CLI frontend for memory read/write operations.")
    
    parser.add_argument(
        "operation", choices=["read", "write"], help="Operation to perform: read or write."
    )
    parser.add_argument(
        "pid", type=int, help="Process ID (PID) of the target process."
    )
    parser.add_argument(
        "address", type=lambda x: int(x, 16), help="Memory address in hexadecimal format (e.g., 0x1234)."
    )
    parser.add_argument(
        "value", type=str, help=(
            "Hexadecimal string for data (write operation) or count (read operation). "
            "If performing a write, provide a hex string like '0a0b15'. "
            "If performing a read, provide the count in hex format, e.g., '0x10'."
        )
    )

    args = parser.parse_args()

    pid = args.pid
    address = args.address
    operation = args.operation

    if operation == "write":
        # Ensure the provided data is a valid hex string.
        try:
            data = bytes.fromhex(args.value)
        except ValueError:
            print("Error: Invalid hex string for data.", file=sys.stderr)
            sys.exit(1)

        _read_or_write_process_memory(address, len(data), data, pid, do_write=True)
    elif operation == "read":
        # Parse the count as a hexadecimal number.
        try:
            if not args.value.startswith("0x"):
                raise ValueError()
            size = int(args.value, 16)
        except ValueError:
            print("Error: Invalid hex string for count.", file=sys.stderr)
            sys.exit(1)

        data = _read_or_write_process_memory(address, size, bytes(), pid, do_write=False)
        print(data.hex())

if __name__ == "__main__":
    main()