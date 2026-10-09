"""Bounded literal TeX closure and prose extraction, without executing TeX."""
from array import array
from bisect import bisect_left, bisect_right
from dataclasses import dataclass, field
from pathlib import Path
import re

MAX_FILES = 128
MAX_DEPTH = 32
MAX_BYTES = 16 * 1024 * 1024


def tex_ignored_regions(text):
    """Yield comment/literal spans using one escape-aware lexical scan."""
    environments = r'verbatim\*?|Verbatim|lstlisting|minted'
    pattern = re.compile(
        r'\\begin\{(' + environments + r')\}.*?\\end\{\1\}'
        r'|\\verb(?![A-Za-z])\*?(?P<delim>[^\s])[^\r\n]*?(?P=delim)'
        r'|(?P<invalid>\\verb(?![A-Za-z])|\\begin\{(?:' + environments + r')\})'
        r'|\\.|%[^\r\n]*', re.S)
    for match in pattern.finditer(text):
        if match.group('invalid'):
            raise ValueError('unterminated or invalid literal TeX region')
        token = match.group()
        if token.startswith('%'):
            yield match.start(), match.end(), 'comment'
        elif token.startswith(('\\begin', '\\verb')):
            yield match.start(), match.end(), 'literal'


def masked_tex(text):
    """Mask comments/verbatim with spaces, retaining offsets and newlines."""
    chars = list(text)
    for start, end, _ in tex_ignored_regions(text):
        for index in range(start, end):
            if chars[index] not in '\r\n':
                chars[index] = ' '
    return ''.join(chars)


def live_tex(text):
    """Mask ignored regions and paired control symbols without moving offsets."""
    return re.sub(r'\\\\', '  ', masked_tex(text))


@dataclass
class SourceClosure:
    text: str
    segments: list
    sources: tuple

    _segment_starts: tuple = field(init=False, repr=False)
    _line_breaks: dict = field(init=False, repr=False)

    def __post_init__(self):
        # A closure is a completed snapshot. Index each original text object once;
        # the same path can occur with a different snapshot in a constructed closure.
        self._segment_starts = tuple(segment[0] for segment in self.segments)
        self._line_breaks = {}
        for _, _, _, original in self.segments:
            identity = id(original)
            if identity not in self._line_breaks:
                self._line_breaks[identity] = array(
                    'I' if len(original) <= 0xFFFFFFFF else 'Q',
                    (match.start() for match in re.finditer('\n', original)))

    def location(self, offset):
        if not self.segments:
            return self.sources[0], 1
        index = max(0, bisect_right(self._segment_starts, offset) - 1)
        start, path, original_offset, original = self.segments[index]
        position = original_offset + offset - start
        # Match str.count's slice endpoint, including its negative/clamped bounds.
        position = max(0, len(original) + position) if position < 0 else min(position, len(original))
        return path, bisect_left(self._line_breaks[id(original)], position) + 1


def source_closure(source, *, root=None):
    source = Path(source).resolve()
    root = Path(root).resolve() if root is not None else source.parent
    chunks, segments, sources = [], [], []
    length = used_bytes = visits = 0
    document_started = document_ended = False

    def append(text, path, original_offset, original):
        nonlocal length
        if text:
            segments.append((length, path, original_offset, original))
            chunks.append(text)
            length += len(text)

    def expand(path, stack):
        nonlocal used_bytes, visits, document_started, document_ended
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
        # TeX control words end before any nonletter, including a digit or underscore.
        pattern = re.compile(r'(?<!\\)(?:\\\\)*\\(?:(input|include|includeonly)(?![A-Za-z])'
                             r'|(begin|end)\{document\})')
        cursor = 0
        for match in pattern.finditer(masked):
            if document_ended:
                break
            if match.group(2):
                if match.group(2) == 'begin':
                    document_started = True
                elif document_started:
                    document_ended = True
                continue
            # Paired backslashes are TeX linebreaks, not escapes of the next command.
            command_start = match.end() - len(match.group(1)) - 1
            if command_start < cursor:
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
            append(text[cursor:command_start], path, cursor, text)
            expand(root / child, (*stack, path))
            cursor = match.end() + argument.end()
        append(text[cursor:], path, cursor, text)
        if stack and text and not text.endswith(('\n', '\r')):
            # TeX ends an input's final logical line at EOF. In particular, a
            # trailing comment must never consume resumed parent-file content.
            append('\n', path, len(text), text)

    expand(source, ())
    return SourceClosure(''.join(chunks), segments, tuple(dict.fromkeys(sources)))


def document_extent(live):
    """Return the literal live body extent; standalone fragments keep their tail."""
    begin = re.search(r'\\begin\{document\}', live)
    if begin is None:
        return 0, len(live)
    end = re.search(r'\\end\{document\}', live[begin.end():])
    return begin.end(), begin.end() + end.start() if end else len(live)


def plain_tex(text):
    """Keep nested formatted prose; discard mathematical and literal code spans."""
    text = live_tex(text)
    start, end = document_extent(text)
    text = text[start:end]
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
