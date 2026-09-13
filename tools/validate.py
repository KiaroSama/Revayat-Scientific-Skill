#!/usr/bin/env python3
"""Check tracked text encoding, Python syntax, file limits and local links."""
import ast
import json
from pathlib import Path
import re
import subprocess

ROOT = Path(__file__).resolve().parents[1]
TEXT = {'.py', '.ps1', '.sh', '.md', '.json', '.yaml', '.yml', '.tex', '.html', '.tsv', '.txt'}


def main():
    files = subprocess.check_output(['git', 'ls-files', '-z'], cwd=ROOT).decode('utf-8').split('\0')
    if not any(files):
        raise ValueError('no tracked files to validate')
    for name in filter(None, files):
        path = ROOT / name
        if path.suffix not in TEXT:
            continue
        text = path.read_text(encoding='utf-8-sig')
        if path.suffix in {'.py', '.sh', '.ps1'} and len(text.splitlines()) > 800:
            raise ValueError(f'{name}: exceeds 800 lines')
        if path.suffix == '.py':
            ast.parse(text, filename=name)
        if path.suffix == '.json':
            json.loads(text)
        if path.suffix == '.md':
            for target in re.findall(r'\]\(([^)]+)\)', text):
                target = target.split('#')[0]
                if target and '://' not in target and not target.startswith(('mailto:', '$')):
                    if not (path.parent / target).exists():
                        raise ValueError(f'{name}: missing link {target}')
    print('Tracked text, syntax, file lengths and local links are valid.')


if __name__ == '__main__':
    main()
