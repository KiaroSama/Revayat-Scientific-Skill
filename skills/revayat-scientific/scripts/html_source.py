"""Parse live HTML nodes and visible entities without executing document content."""
from html import unescape
from html.parser import HTMLParser
from bisect import bisect_right
import re
from html_scopes import before_start, before_text, close_from, end_index, FORMATTING

VOID = {'area', 'base', 'br', 'col', 'embed', 'hr', 'img', 'input', 'link', 'meta',
        'param', 'source', 'track', 'wbr'}
INERT = {'script', 'style', 'head', 'title', 'pre', 'code', 'kbd', 'samp', 'math'}
TEXT_EXCLUDED = {'head', 'title', 'script', 'style'}
TEXT_BREAKS = {'address', 'article', 'aside', 'blockquote', 'br', 'caption', 'dd',
               'div', 'dl', 'dt', 'fieldset', 'figcaption', 'figure', 'footer',
               'form', 'h1', 'h2', 'h3', 'h4', 'h5', 'h6', 'header', 'hr', 'li',
               'main', 'nav', 'ol', 'option', 'p', 'pre', 'section', 'table',
               'tbody', 'td', 'textarea', 'tfoot', 'th', 'thead', 'tr', 'ul', 'xmp'}
RCDATA = {'textarea', 'title'}
RAWTEXT = {'script', 'style', 'xmp', 'iframe', 'noembed', 'noframes'}
CHARREF = re.compile(r'&(?:\#[xX][0-9A-Fa-f]+;?|\#[0-9]+;?|[A-Za-z][A-Za-z0-9]{0,31};?)')
FOREIGN_BREAKOUT = {'b', 'big', 'blockquote', 'body', 'br', 'center', 'code', 'dd',
                    'div', 'dl', 'dt', 'em', 'embed', 'h1', 'h2', 'h3', 'h4', 'h5',
                    'h6', 'head', 'hr', 'i', 'img', 'li', 'listing', 'menu', 'meta',
                    'nobr', 'ol', 'p', 'pre', 'ruby', 's', 'small', 'span', 'strong',
                    'strike', 'sub', 'sup', 'table', 'tt', 'u', 'ul', 'var'}


class ParsedHTML(HTMLParser):
    # Force a stable raw-token path on Python versions both before and after
    # native RCDATA support. Character references in RCDATA are decoded below.
    CDATA_CONTENT_ELEMENTS = tuple(sorted(RAWTEXT | RCDATA))

    def __init__(self, text):
        super().__init__(convert_charrefs=False)
        self.raw = text
        self.entities = []
        self.starts = [0] + [match.end() for match in re.finditer('\n', text)]
        self.nodes, self.comments, self.protected, self.isolates = [], [], [], []
        self.identity = []
        self.literals, self.markup, self.markup_starts = [], [], []
        self.stack = []
        self.text_tokens = []
        self.feed(text)
        self.close()
        if self.cdata_elem is not None:
            raise ValueError('unterminated HTML raw-text or RCDATA element')
        for node in reversed(self.stack):
            self.finish(node, len(text), len(text))
        self.stack.clear()
        chunks, cursor, size = [], 0, 0
        self.entity_ranges = []
        for start, end, decoded in self.entities:
            chunk = text[cursor:start]
            chunks.extend((chunk, decoded))
            size += len(chunk)
            self.entity_ranges.append((start, end, size, size + len(decoded)))
            size += len(decoded)
            cursor = end
        chunks.append(text[cursor:])
        self.text = ''.join(chunks)
        self.raw_starts = [item[0] for item in self.entity_ranges]
        self.decoded_starts = [item[2] for item in self.entity_ranges]
        for name in ('comments', 'protected', 'identity', 'literals'):
            setattr(self, name, [(self.normalized_offset(a), self.normalized_offset(b))
                                for a, b in getattr(self, name)])
        self.isolates = [(self.normalized_offset(a), self.normalized_offset(b), body)
                         for a, b, body in self.isolates]
        for node in self.nodes:
            node['start'] = self.normalized_offset(node['start'])
            node['content'] = self.normalized_offset(node['content'])

    def normalized_offset(self, offset):
        index = bisect_right(self.raw_starts, offset) - 1
        if index < 0:
            return offset
        start, end, decoded_start, decoded_end = self.entity_ranges[index]
        return decoded_start if offset < end else offset + decoded_end - end

    def original_offset(self, offset):
        index = bisect_right(self.decoded_starts, offset) - 1
        if index < 0:
            return offset
        start, end, decoded_start, decoded_end = self.entity_ranges[index]
        return start if offset < decoded_end else offset + end - decoded_end

    def position(self):
        line, column = self.getpos()
        return self.starts[line - 1] + column

    def namespace_for(self, tag):
        parent = self.stack[-1] if self.stack else None
        namespace = parent['namespace'] if parent else 'html'
        if parent and namespace == 'svg' and parent['tag'] in ('foreignobject', 'desc', 'title'):
            namespace = 'html'
        if parent and namespace == 'math':
            integration = (parent['tag'] in ('mi', 'mo', 'mn', 'ms', 'mtext')
                           and tag not in ('mglyph', 'malignmark'))
            annotation = (parent['tag'] == 'annotation-xml'
                          and (parent['attrs'].get('encoding') or '').lower()
                          in ('text/html', 'application/xhtml+xml'))
            if integration or annotation:
                namespace = 'html'
        if namespace == 'html' and tag in ('svg', 'math'):
            namespace = tag
        return namespace

    def set_cdata_mode(self, elem, **_options):
        if not self.stack or self.stack[-1]['namespace'] != 'html':
            return
        if elem not in RAWTEXT | RCDATA:
            raise ValueError('unsupported HTML text tokenizer state')
        # Passing no new keywords also supports older Python HTMLParser versions.
        super().set_cdata_mode(elem)
        self.interesting = re.compile(r'</' + re.escape(elem) + r'(?=[\t\n\r\f />])',
                                      re.I | re.ASCII)

    def parse_endtag(self, index):
        if self.cdata_elem is None:
            return super().parse_endtag(index)
        # HTML ignores end-tag attributes. Recognize the same terminator on old
        # and new runtimes, retaining '>' characters inside quoted attributes.
        match = self.interesting.match(self.rawdata, index)
        if match is None:
            raise ValueError('unexpected HTML raw-text terminator')
        state = 'name'
        quote = None
        for stop in range(match.end(), len(self.rawdata)):
            char = self.rawdata[stop]
            if quote:
                if char == quote:
                    quote = None
                    state = 'after-value'
                continue
            if char == '>':
                self.handle_endtag(self.cdata_elem, self.position() + stop + 1 - index)
                self.clear_cdata_mode()
                return stop + 1
            if state == 'value':
                if char in '\t\n\r\f ':
                    continue
                if char in "\"'":
                    quote = char
                state = 'unquoted'
            elif state == 'unquoted':
                if char in '\t\n\r\f ':
                    state = 'before-name'
            elif char == '=' and state in ('name', 'after-name'):
                state = 'value'
            elif char in '\t\n\r\f ':
                state = 'after-name' if state == 'name' else 'before-name'
            elif char == '/':
                state = 'before-name'
            else:
                state = 'name'
        return -1

    def record_text(self, start, end):
        if not self.stack or not self.stack[-1]['text_excluded']:
            self.text_tokens.append((start, end))

    def text_content(self):
        """Located text tokens, not markup. This does not evaluate external CSS layout."""
        chunks = [self.text[self.normalized_offset(a):self.normalized_offset(b)] if a != b else ' '
                  for a, b in self.text_tokens]
        return re.sub(r'\s+', ' ', ''.join(chunks)).strip()

    def handle_data(self, data):
        before_text(self, data, self.position())
        self.record_text(self.position(), self.position() + len(data))
        if self.cdata_elem in RCDATA:
            start = self.position()
            for match in CHARREF.finditer(data):
                token = match.group()
                self.entities.append((start + match.start(), start + match.end(), unescape(token)))

    def record_markup(self, start, end):
        self.markup.append((start, end))
        self.markup_starts.append(start)
        self.protected.append((start, end))

    def handle_starttag(self, tag, attrs):
        start = self.position()
        end = start + len(self.get_starttag_text())
        attributes = {}
        for name, value in attrs:
            attributes.setdefault(name, value)
        if (self.namespace_for(tag) != 'html'
                and (tag in FOREIGN_BREAKOUT or
                     (tag == 'font' and any(name in attributes for name in ('color', 'face', 'size'))))):
            while self.stack and self.namespace_for(tag) != 'html':
                self.finish(self.stack.pop(), start, start)
        before_start(self, tag, start)
        parent = self.stack[-1] if self.stack else None
        language = attributes.get('lang', parent['language'] if parent else 'fa') or 'fa'
        classes = set((attributes.get('class') or '').split())
        isolate = ((attributes.get('dir') or '').lower() == 'ltr' or bool(classes & {'ltr', 'en', 'num', 'refs'}))
        identity = (tag in INERT or tag in {'cite', 'q', 'blockquote'} or 'refs' in classes
                    or attributes.get('data-source-identity') == 'true'
                    or (parent is not None and parent['identity']))
        namespace = self.namespace_for(tag)
        if namespace == 'html' and tag in ('template', 'plaintext'):
            # Template rendering is not equivalent across the supported engines;
            # plaintext consumes the rest of an HTML stream. Neither can silently
            # change which source text, assets or directives receive validation.
            raise ValueError('HTML template/plaintext requires an explicitly reviewed static document')
        node = {'namespace': namespace, 'tag': tag, 'attrs': attributes, 'start': start, 'content': end,
                'language': language.lower(), 'isolate': isolate, 'identity': identity,
                'text_excluded': tag in TEXT_EXCLUDED or 'hidden' in attributes
                                 or (parent is not None and parent['text_excluded']),
                'protected': tag in INERT or isolate or language.lower() not in ('fa', 'fa-ir')
                             or 'hidden' in attributes
                             or (parent is not None and parent['protected'])}
        self.nodes.append(node)
        if tag in TEXT_BREAKS and not node['text_excluded']:
            self.text_tokens.append((start, start))
        self.record_markup(start, end)
        if namespace != 'html' or tag not in VOID:
            self.stack.append(node)

    def handle_startendtag(self, tag, attrs):
        self.handle_starttag(tag, attrs)
        if self.nodes[-1]['namespace'] != 'html':
            end = self.position() + len(self.get_starttag_text())
            self.finish(self.stack.pop(), end, end)
        elif tag in RAWTEXT | RCDATA:
            # The slash on an HTML nonvoid element does not close that element.
            # HTMLParser does not set its tokenizer state on the startend path.
            self.set_cdata_mode(tag)

    def finish(self, node, content_end, end):
        if node['tag'] in TEXT_BREAKS and not node['text_excluded']:
            self.text_tokens.append((end, end))
        if node['namespace'] == 'html' and node['tag'] in RCDATA:
            self.literals.append((node['content'], content_end))
        if node['protected']:
            self.protected.append((node['content'], content_end))
        if node['isolate'] and not node['identity']:
            # Child code/quotes retain literal wording even inside a prose isolate.
            chunks, cursor = [], node['content']
            left = max(0, bisect_right(self.markup_starts, node['content']) - 1)
            right = bisect_right(self.markup_starts, content_end)
            ignored = self.identity + self.markup[left:right]
            for start, stop in sorted(ignored):
                if stop <= cursor or start >= content_end:
                    continue
                chunks.extend((self.raw[cursor:max(cursor, start)], ' '))
                cursor = min(content_end, stop)
            chunks.append(self.raw[cursor:content_end])
            body = unescape(''.join(chunks))
            self.isolates.append((node['start'], end, body))
        if node['identity'] or node['language'] not in ('fa', 'fa-ir', 'en', 'en-us', 'en-gb'):
            self.identity.append((node['start'], end))

    def handle_endtag(self, tag, token_end=None):
        start = self.position()
        close = self.raw.find('>', start)
        end = token_end if token_end is not None else (len(self.raw) if close < 0 else close + 1)
        self.record_markup(start, end)
        index = end_index(self, tag)
        if index is not None:
            if tag in FORMATTING and index != len(self.stack) - 1:
                raise ValueError('HTML formatting adoption requires explicitly nested markup')
            close_from(self, index, start, end)

    def parse_comment(self, index, report=True):
        # Older stdlib patches accepted whitespace inside a comment terminator.
        # Own this small boundary so renderer-hidden tails cannot become prose.
        start = index + 4
        abrupt = re.match(r'>|->', self.rawdata[start:])
        closing = abrupt or re.search(r'--!?>', self.rawdata[start:])
        content_end = start + closing.start() if closing else len(self.rawdata)
        end = start + closing.end() if closing else len(self.rawdata)
        if report:
            self.handle_comment(self.rawdata[start:content_end])
        return end

    def handle_comment(self, data):
        start = self.position()
        normal = self.raw.startswith('<!--', start)
        content_start = start + (4 if normal else 2)
        closing = self.raw.find('>', content_start + len(data))
        end = len(self.raw) if closing < 0 else closing + 1
        if normal:
            self.comments.append((start, end))
        self.record_markup(start, end)

    def handle_decl(self, decl):
        start = self.position()
        self.record_markup(start, start + len(decl) + 3)

    def decode_entity(self, token):
        start = self.position()
        decoded = unescape(token)
        before_text(self, decoded, start)
        self.entities.append((start, start + len(token), decoded))
        self.record_text(start, start + len(token))

    def handle_entityref(self, name):
        self.decode_entity('&' + name + (';' if self.raw[self.position() + len(name) + 1:self.position() + len(name) + 2] == ';' else ''))

    def handle_charref(self, name):
        self.decode_entity('&#' + name + (';' if self.raw[self.position() + len(name) + 2:self.position() + len(name) + 3] == ';' else ''))
