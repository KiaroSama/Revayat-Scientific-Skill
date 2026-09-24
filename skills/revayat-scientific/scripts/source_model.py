"""Source text and protected regions shared by scientific lint rules."""
import bisect
from pathlib import Path
import re
from html_source import ParsedHTML
from tex_source import source_closure, MAX_BYTES

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
        self.isolates: list[tuple[int, int, str]] = []
        self.identity = []
        self.preamble_end = 0
        self._scan()

    def line_of(self, pos: int) -> int:
        if hasattr(self, 'html'):
            pos = self.html.original_offset(pos)
        return bisect.bisect_right(self.line_starts, pos)

    def in_preamble(self, pos: int) -> bool:
        return pos < self.preamble_end

    def inert(self, pos: int) -> bool:
        """Preamble or comment: structural checks must not fire here.

        Templates and real documents both carry commented-out examples and
        `% TODO(ambiguity)` markers; those are not output.
        """
        if pos < self.preamble_end:
            return True
        return any(start <= pos < end for start, end in self.comments)

    def excerpt(self, pos: int, width: int = 60) -> str:
        start = max(0, pos - width // 3)
        return self.text[start:start + width].replace("\n", " ").strip()

    def is_protected(self, pos: int) -> bool:
        for start, end in self.protected:
            if start <= pos < end:
                return True
        return False

    def suppressed(self, pos: int, check: str) -> bool:
        path, line = self.location(pos)
        for start, end in self.comments:
            for m in re.finditer(r"fa-lint:\s*allow\s+([\w-]+)", self.text[start:end]):
                comment_path, comment_line = self.location(start + m.start())
                if comment_path == path and comment_line in (line, line - 1) and m.group(1) in (check, 'all'):
                    return True
        return False

    def location(self, pos):
        return self.closure.location(pos) if self.closure else (self.path, self.line_of(pos))

    def image_references(self):
        """Return located graphics references using the checked document syntax."""
        if self.kind == 'html':
            return [(node['start'], node['attrs']['src']) for node in self.html.nodes
                    if node['tag'] == 'img' and node['attrs'].get('src')]
        return [(match.start(), match.group(1).strip()) for match in re.finditer(
            r'\\includegraphics\*?\s*(?:\[[^\]]*\]\s*)?\{([^{}]+)\}', self.text)
            if not self.inert(match.start())]

    # -- region scanning ---------------------------------------------------

    def _protect(self, start: int, end: int) -> None:
        if end > start:
            self.protected.append((start, end))

    def _match_brace(self, open_pos: int) -> int:
        depth = 0
        i = open_pos
        while i < len(self.text):
            ch = self.text[i]
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

    def _scan_tex(self) -> None:
        body = re.search(r"\\begin\{document\}", self.text)
        if body:
            self.preamble_end = body.end()
            self._protect(0, body.end())

        for m in re.finditer(r"(?<!\\)%.*$", self.text, re.M):
            self._protect(m.start(), m.end())
            self.comments.append((m.start(), m.end()))

        for env in ("verbatim", "Verbatim", "lstlisting", "latin",
                    "equation", "equation*", "align", "align*", "minted"):
            pattern = re.compile(
                r"\\begin\{" + re.escape(env) + r"\}.*?\\end\{"
                + re.escape(env) + r"\}", re.S)
            for m in pattern.finditer(self.text):
                self._protect(m.start(), m.end())
                if env == 'latin':
                    self.identity.append((m.start(), m.end()))

        for m in re.finditer(r"\$\$.*?\$\$|(?<!\\)\$.*?(?<!\\)\$"
                             r"|\\\[.*?\\\]|\\\(.*?\\\)", self.text, re.S):
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
        for m in re.finditer(r"\\[A-Za-z@]+\*?\s*\[", self.text):
            start = m.end() - 1
            depth = 0
            i = start
            while i < len(self.text):
                ch = self.text[i]
                if ch == "[":
                    depth += 1
                elif ch == "]":
                    depth -= 1
                    if depth == 0:
                        self._protect(start, i + 1)
                        break
                i += 1
        for m in re.finditer(r"\\([A-Za-z@]+)\*?\s*(\[[^\]]*\])?\s*\{",
                             self.text):
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
                                      self.text[open_pos + 1:close]))
            elif name in arg_only:
                self._protect(m.start(), close + 1)
            else:
                # Protect only the macro name, never its Persian argument.
                self._protect(m.start(), m.end() - 1)

        for m in re.finditer(r"\\[A-Za-z@]+\*?", self.text):
            self._protect(m.start(), m.end())

    def _scan_html(self) -> None:
        self.html = ParsedHTML(self.text)
        self.text = self.html.text
        self.protected.extend(self.html.protected)
        self.comments.extend(self.html.comments)
        self.isolates.extend(self.html.isolates)
        self.identity.extend(self.html.identity)
