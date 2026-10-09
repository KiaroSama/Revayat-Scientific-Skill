"""Source text and protected regions shared by scientific lint rules."""
import bisect
from pathlib import Path
import re
from html_source import ParsedHTML
from tex_source import source_closure, live_tex, tex_ignored_regions, document_extent, MAX_BYTES

class Source:
    """A translation file plus the regions where prose rules do not apply."""

    def __init__(self, path: Path):
        self.path = path
        if path.stat().st_size > MAX_BYTES:
            raise ValueError('source exceeds 16 MiB')
        self.closure = source_closure(path) if path.suffix.lower() == '.tex' else None
        self.text = self.closure.text if self.closure else path.read_text(encoding="utf-8")
        self.kind = "tex" if path.suffix.lower() == ".tex" else "html"
        self.line_starts = [0] + [
            m.end() for m in re.finditer(r"\n", self.text)
        ]
        self.lines = self.text.splitlines()
        self.protected: list[tuple[int, int]] = []
        self.comments: list[tuple[int, int]] = []
        self.literals: list[tuple[int, int]] = []
        self.isolates: list[tuple[int, int, str]] = []
        self.identity = []
        self.preamble_end = 0
        self.body_end = len(self.text)
        self._scan()

    def line_of(self, pos: int) -> int:
        if hasattr(self, 'html'):
            pos = self.html.original_offset(pos)
        return bisect.bisect_right(self.line_starts, pos)

    def in_preamble(self, pos: int) -> bool:
        return pos < self.preamble_end

    def inert(self, pos: int) -> bool:
        """Ignore comments and literal contents, not a real listing's opener.

        Code-direction checks must still inspect a genuine listing boundary.
        A fake opener inside an inline or block literal remains inert, while
        prose checks protect the entire literal through is_protected().
        """
        if pos < self.preamble_end or pos >= self.body_end:
            return True
        if any(start <= pos < end for start, end in self.comments):
            return True
        for start, end in self.literals:
            if start <= pos < end:
                return not (self.kind == 'tex' and pos == start and self.text.startswith(r'\begin{', start))
        return False

    def excerpt(self, pos: int, width: int = 60) -> str:
        start = max(0, pos - width // 3)
        return self.text[start:start + width].replace("\n", " ").strip()

    def is_protected(self, pos: int) -> bool:
        index = bisect.bisect_right(self.protected_starts, pos) - 1
        return index >= 0 and pos < self.protected_ranges[index][1]

    def prose_matches(self, pattern, flags=0):
        if self.kind == 'html':
            for match in re.finditer(pattern, self.prose_text, flags):
                index = bisect.bisect_right(self.prose_starts, match.start()) - 1
                start, original = self.prose_segments[index]
                yield match, original + match.start() - start
        else:
            for match in re.finditer(pattern, self.text, flags):
                if not self.is_protected(match.start()):
                    yield match, match.start()

    def suppressed(self, pos: int, check: str) -> bool:
        path, line = self.location(pos)
        allowed = self.waivers.get((path, line), set()) | self.waivers.get((path, line - 1), set())
        return check in allowed or 'all' in allowed

    def location(self, pos):
        return self.closure.location(pos) if self.closure else (self.path, self.line_of(pos))

    def in_direction_scope(self, pos, *names):
        return any(start <= pos < end for name in names
                   for start, end in self.direction_scopes[name])

    def image_references(self):
        """Return located graphics references using the checked document syntax."""
        if self.kind == 'html':
            return [(node['start'], node['attrs']['src']) for node in self.html.nodes
                    if node['tag'] == 'img' and node['attrs'].get('src')]
        return [(match.start(), match.group(1).strip()) for match in re.finditer(
            r'\\includegraphics\*?\s*(?:\[[^\]]*\]\s*)?\{([^{}]+)\}', self.tex_live)
            if not self.inert(match.start())]

    # -- region scanning ---------------------------------------------------

    def _protect(self, start: int, end: int) -> None:
        if end > start:
            self.protected.append((start, end))

    def _match_brace(self, open_pos: int) -> int:
        depth = 0
        i = open_pos
        while i < len(self.tex_live):
            ch = self.tex_live[i]
            if ch == "\\":
                i += 2
                continue
            if ch == "{":
                depth += 1
            elif ch == "}":
                depth -= 1
                if depth == 0:
                    return i
            i += 1
        return len(self.text)

    def _scan(self) -> None:
        if self.kind == "tex":
            self._scan_tex()
        else:
            self._scan_html()
        self.protected.sort()
        self.protected_ranges = []
        for start, end in self.protected:
            if self.protected_ranges and start <= self.protected_ranges[-1][1]:
                previous, stop = self.protected_ranges[-1]
                self.protected_ranges[-1] = previous, max(stop, end)
            else:
                self.protected_ranges.append((start, end))
        self.protected_starts = [start for start, _ in self.protected_ranges]
        self.waivers = {}
        for start, end in self.comments:
            for match in re.finditer(r'fa-lint:\s*allow\s+([\w-]+)', self.text[start:end]):
                key = self.location(start + match.start())
                self.waivers.setdefault(key, set()).add(match.group(1))

    def _scan_tex(self) -> None:
        for start, end, kind in tex_ignored_regions(self.text):
            self._protect(start, end)
            (self.comments if kind == 'comment' else self.literals).append((start, end))
        # A paired backslash is a control symbol, not the start of the next word.
        # Keep offsets stable while preventing escaped commands from becoming live.
        self.tex_live = live_tex(self.text)
        structural = list(self.tex_live)
        for start, _end in self.literals:
            if self.text.startswith(r'\begin{', start):
                opener_end = self.text.index('}', start) + 1
                structural[start:opener_end] = self.text[start:opener_end]
        self.structural_text = ''.join(structural)
        self.direction_scopes = {'latin': [], 'LTR': [], 'LR': []}
        stack = []
        for match in re.finditer(r'\\(begin|end)\{([^{}]+)\}', self.tex_live):
            action, env = match.groups()
            if action == 'begin':
                stack.append((env, match.end()))
            elif stack and stack[-1][0] == env:
                _env, start = stack.pop()
                if env in self.direction_scopes:
                    self.direction_scopes[env].append((start, match.start()))
        for match in re.finditer(r'\\LR(?![A-Za-z])\s*\{', self.tex_live):
            opening = match.end() - 1
            closing = self._match_brace(opening)
            if closing < len(self.tex_live):
                self.direction_scopes['LR'].append((opening + 1, closing))
        self.preamble_end, self.body_end = document_extent(self.tex_live)
        self._protect(0, self.preamble_end)
        self._protect(self.body_end, len(self.text))

        for env in ("verbatim", "Verbatim", "lstlisting", "latin",
                    "equation", "equation*", "align", "align*", "minted"):
            pattern = re.compile(
                r"\\begin\{" + re.escape(env) + r"\}.*?\\end\{"
                + re.escape(env) + r"\}", re.S)
            for m in pattern.finditer(self.tex_live):
                self._protect(m.start(), m.end())
                if env == 'latin':
                    self.identity.append((m.start(), m.end()))

        for m in re.finditer(r"\$\$.*?\$\$|(?<!\\)\$.*?(?<!\\)\$"
                             r"|\\\[.*?\\\]|\\\(.*?\\\)", self.tex_live, re.S):
            self._protect(m.start(), m.end())

        arg_only = ("begin", "end", "label", "ref", "eqref", "cite", "url",
                    "href", "input", "include", "includegraphics", "bibitem",
                    "bibliography", "usepackage", "documentclass",
                    "settextfont", "setlatintextfont", "setmonofont",
                    "setdigitfont", "hypersetup", "setlength", "hspace",
                    "vspace", "rule", "newcommand", "renewcommand", "texttt", "citetitle",
                    "definecolor", "geometry", "addcontentsline",
                    "pdfstringdefDisableCommands", "IfFontExistsTF")
        # Optional arguments (`[width=0.92\linewidth]`) are plumbing, not
        # prose; otherwise unisolated-number fires on every includegraphics.
        for m in re.finditer(r"\\[A-Za-z@]+\*?\s*\[", self.tex_live):
            start = m.end() - 1
            depth = 0
            i = start
            while i < len(self.tex_live):
                ch = self.tex_live[i]
                if ch == "[":
                    depth += 1
                elif ch == "]":
                    depth -= 1
                    if depth == 0:
                        self._protect(start, i + 1)
                        break
                i += 1
        for m in re.finditer(r"\\([A-Za-z@]+)\*?\s*(\[[^\]]*\])?\s*\{",
                             self.tex_live):
            if self.inert(m.start()):
                continue
            name = m.group(1)
            open_pos = m.end() - 1
            close = self._match_brace(open_pos)
            if name in ("lr", "en", "textenglish", "lasttext"):
                self._protect(open_pos + 1, close)
                if any(s <= m.start() < e for s, e in self.comments):
                    continue
                # Whole `\en{…}` so the gap between two isolates is only
                # the characters *between* the constructs, not `\en{`.
                self.isolates.append((m.start(), close + 1,
                                      self.tex_live[open_pos + 1:close]))
            elif name in arg_only:
                self._protect(m.start(), close + 1)
            else:
                # Protect only the macro name, never its Persian argument.
                self._protect(m.start(), m.end() - 1)

        for m in re.finditer(r"\\[A-Za-z@]+\*?", self.tex_live):
            self._protect(m.start(), m.end())

    def _scan_html(self) -> None:
        self.html = ParsedHTML(self.text)
        self.text = self.html.text
        self.protected.extend(self.html.protected)
        self.comments.extend(self.html.comments)
        self.literals.extend(self.html.literals)
        self.isolates.extend(self.html.isolates)
        self.identity.extend(self.html.identity)
        self.prose_text, self.prose_segments = self.html.lint_prose()
        self.prose_starts = [start for start, _ in self.prose_segments]
