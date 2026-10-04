#!/usr/bin/env python3
"""Safe file writer for pasting content that contains special characters.

Usage: python scripts/safe_write.py <dest> < content.txt

Reads stdin, strips any leading '> ' continuation prompts that bash may have
inadvertently saved, and writes to <dest>.
"""
import sys
from pathlib import Path

if len(sys.argv) != 2:
    print("usage: safe_write.py <destination>", file=sys.stderr)
    sys.exit(1)

dest = Path(sys.argv[1])
lines = sys.stdin.read().splitlines()
cleaned = []
for line in lines:
    # strip bash PS2 continuation prompt if present
    if line.startswith('> '):
        line = line[2:]
    elif line == '>':
        line = ''
    cleaned.append(line)

dest.parent.mkdir(parents=True, exist_ok=True)
dest.write_text('\n'.join(cleaned) + '\n')
print(f"wrote {dest} ({len(cleaned)} lines)")
