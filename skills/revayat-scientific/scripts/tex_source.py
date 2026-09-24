"""Bounded literal TeX closure and prose extraction, without executing TeX."""
from bisect import bisect_right
from dataclasses import dataclass
from pathlib import Path
import re

MAX_FILES = 128
MAX_DEPTH = 32
MAX_BYTES = 16 * 1024 * 1024


def masked_tex(text):
    """Mask comments/verbatim with spaces, retaining offsets and newlines."""
    chars = list(text)
    pattern = re.compile(r'\\begin\{(verbatim\*?|Verbatim|lstlisting|minted)\}'
                         r'.*?\\end\{\1\}|\\verb\*?(?P<delim>[^\w\s]).*?(?P=delim)'
                         r'|\\.|%[^\n]*', re.S)
    for match in pattern.finditer(text):
        token = match.group()
        if token.startswith('%') or token.startswith(('\\begin', '\\verb')):
            for index in range(match.start(), match.end()):
                if chars[index] != '\n':
                    chars[index] = ' '
    return ''.join(chars)


@dataclass
class SourceClosure:
    text: str
    segments: list
    sources: tuple

    def location(self, offset):
        if not self.segments:
            return self.sources[0], 1
        starts = [segment[0] for segment in self.segments]
        start, path, original_offset, original = self.segments[max(0, bisect_right(starts, offset) - 1)]
        return path, original.count('\n', 0, original_offset + offset - start) + 1


def source_closure(source, *, root=None):
    source = Path(source).resolve()
    root = Path(root).resolve() if root is not None else source.parent
    chunks, segments, sources = [], [], []
    length = used_bytes = visits = 0

    def append(text, path, original_offset, original):
        nonlocal length
        if text:
            segments.append((length, path, original_offset, original))
            chunks.append(text)
            length += len(text)

    def expand(path, stack):
        nonlocal used_bytes, visits
        path = path.resolve()
        if not path.is_relative_to(root):
            raise ValueError('TeX include leaves the approved job root')
        if path in stack:
            raise ValueError('TeX include cycle detected')
        if len(stack) >= MAX_DEPTH:
            raise ValueError('TeX include depth exceeds 32')
        visits += 1
        if visits > MAX_FILES:
            raise ValueError('TeX closure exceeds 128 file visits')
        if not path.is_file():
            raise ValueError('missing literal TeX include: ' + str(path))
        size = path.stat().st_size
        if size > MAX_BYTES - used_bytes:
            raise ValueError('TeX closure exceeds 16 MiB')
        raw = path.read_bytes()
        used_bytes += len(raw)
        if used_bytes > MAX_BYTES:
            raise ValueError('TeX closure exceeds 16 MiB')
        text = raw.decode('utf-8')
        sources.append(path)
        masked = masked_tex(text)
        pattern = re.compile(r'(?<!\\)\\(input|include|includeonly)\b')
        cursor = 0
        for match in pattern.finditer(masked):
            if match.start() < cursor:
                continue
            if match.group(1) == 'includeonly':
                raise ValueError('includeonly requires an explicit reviewed source closure')
            argument = re.match(r'\s*(?:\{([^{}]*)\}|([^\s{}]+))', masked[match.end():])
            if argument is None:
                raise ValueError('unsupported dynamic or missing TeX include')
            name = (argument.group(1) or argument.group(2) or '').strip()
            if not name or any(char in name for char in '\\#$%~^&'):
                raise ValueError('unsupported dynamic TeX include')
            child = Path(name)
            if not child.suffix:
                child = child.with_suffix('.tex')
            if child.suffix.lower() not in ('.tex', '.ltx'):
                raise ValueError('unsupported TeX include type')
            append(text[cursor:match.start()], path, cursor, text)
            expand(root / child, (*stack, path))
            cursor = match.end() + argument.end()
        append(text[cursor:], path, cursor, text)

    expand(source, ())
    return SourceClosure(''.join(chunks), segments, tuple(dict.fromkeys(sources)))


def plain_tex(text):
    """Keep nested formatted prose; discard mathematical and literal code spans."""
    text = masked_tex(text)
    body = re.search(r'\\begin\{document\}', text)
    if body:
        text = text[body.end():]
    text = re.sub(r'\\begin\{(latin|equation\*?|align\*?|displaymath|math)\}'
                  r'.*?\\end\{\1\}', ' ', text, flags=re.S)
    text = re.sub(r'(?<!\\)\$\$.*?(?<!\\)\$\$|(?<!\\)\$.*?(?<!\\)\$'
                  r'|\\\[.*?\\\]|\\\(.*?\\\)', ' ', text, flags=re.S)
    discard = {'en', 'lr', 'textenglish', 'texttt', 'url', 'label', 'ref',
               'eqref', 'cite', 'includegraphics', 'begin', 'end'}
    command_pattern = re.compile(r'\\([A-Za-z@]+)\*?(?:\[[^\]]*\])?\s*')

    def unwrap(value, depth=0):
        if depth >= MAX_DEPTH:
            raise ValueError('TeX formatting depth exceeds 32')
        result = []
        pos = 0
        while pos < len(value):
            command = command_pattern.match(value, pos)
            if command:
                name = command.group(1)
                pos = command.end()
                if pos < len(value) and value[pos] == '{':
                    start = pos + 1
                    nesting = 1
                    pos += 1
                    while pos < len(value) and nesting:
                        if value[pos] == '\\':
                            pos += 2
                            continue
                        nesting += (value[pos] == '{') - (value[pos] == '}')
                        pos += 1
                    if nesting:
                        raise ValueError('unbalanced TeX prose argument')
                    result.append(' ' if name in discard else unwrap(value[start:pos - 1], depth + 1))
                else:
                    result.append(' ')
            else:
                result.append(' ' if value[pos] in '{}\\' else value[pos])
                pos += 1
        return ''.join(result)

    return re.sub(r'\s+', ' ', unwrap(text)).strip()
