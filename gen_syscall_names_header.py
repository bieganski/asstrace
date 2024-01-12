#!/usr/bin/env python3

from pathlib import Path

defs = Path("/usr/include/x86_64-linux-gnu/asm/unistd_64.h")
assert defs.exists()

lines = defs.read_text().splitlines()

defs = [x.split() for x in lines if x.startswith("#define ") and 3 == len(x.split())]
assert len(defs) > 200
assert all(x[1].startswith("__NR_") for x in defs)

m = dict((int(num), name[5:]) for _, name, num in defs)

joined_str = ",\n".join(f'"{m.get(x, "")}" /* {x} */' for x in range(max(m.keys())))

print(
    f"""
const char* syscall_names[] = {{
{joined_str}
}};
    """
)