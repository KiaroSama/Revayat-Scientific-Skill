#!/usr/bin/env python3
"""Check tracked text encoding, Python syntax, file limits and local links."""
import ast
import json
from pathlib import Path
import re
import subprocess

ROOT = Path(__file__).resolve().parents[1]
TEXT = {'.py', '.ps1', '.sh', '.md', '.json', '.yaml', '.yml', '.tex', '.html', '.tsv', '.txt'}


def validate_family_layout():
    sections = {
        'README.md': ['Install', 'Use', 'Without a shell', 'How it works',
                      'What it is honest about', 'Documentation', 'Development',
                      'Credits', 'Donate', 'Author', 'License'],
        'README.fa.md': ['نصب', 'استفاده', 'بدون پوسته', 'معماری', 'آنچه صادقانه باید گفت',
                         'مستندات', 'توسعه', 'سپاس', 'حمایت مالی', 'نویسنده', 'مجوز'],
    }
    for name, expected in sections.items():
        text = (ROOT / name).read_text(encoding='utf-8')
        headings = re.findall(r'^## (.+)$', text, re.M)
        if headings[1:] != expected:
            raise ValueError(f'{name}: Revayat section order changed')
        if text.count('<div ') != text.count('</div>'):
            raise ValueError(f'{name}: unbalanced direction/alignment containers')
    persian = (ROOT / 'README.fa.md').read_text(encoding='utf-8')
    if not persian.startswith('<div dir="rtl">') or '<div dir="ltr">' not in persian:
        raise ValueError('Persian README requires RTL prose and LTR command blocks')
    skill = (ROOT / 'skills/revayat-scientific/SKILL.md').read_text(encoding='utf-8')
    if re.findall(r'^## Step (\d+) ', skill, re.M) != [str(n) for n in range(1, 10)]:
        raise ValueError('Scientific skill requires nine ordered Revayat stages')
    for name in ['translate-paper.md', 'revayat-scientific-resume.md', 'revayat-scientific-qa.md']:
        if not (ROOT / 'commands' / name).is_file():
            raise ValueError(f'Missing workflow command: {name}')


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
    validate_family_layout()
    print('Tracked text, syntax, file lengths, local links and Revayat layout are valid.')


if __name__ == '__main__':
    main()
