"""Parse live HTML nodes and visible entities without executing document content."""
from html import unescape
from html.parser import HTMLParser
from bisect import bisect_right
import re

VOID = {'area', 'base', 'br', 'col', 'embed', 'hr', 'img', 'input', 'link', 'meta',
        'param', 'source', 'track', 'wbr'}
INERT = {'script', 'style', 'head', 'title', 'pre', 'code', 'kbd', 'samp', 'math'}


class ParsedHTML(HTMLParser):
    def __init__(self, text):
        super().__init__(convert_charrefs=False)
        self.raw = text
        self.entities = []
        self.starts = [0] + [match.end() for match in re.finditer('\n', text)]
        self.nodes, self.comments, self.protected, self.isolates = [], [], [], []
        self.identity = []
        self.stack = []
        self.feed(text)
        self.close()
        for node in reversed(self.stack):
            self.finish(node, len(text), len(text))
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
        for name in ('comments', 'protected', 'identity'):
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

    def handle_starttag(self, tag, attrs):
        start = self.position()
        end = start + len(self.get_starttag_text())
        attributes = {}
        for name, value in attrs:
            attributes.setdefault(name, value)
        parent = self.stack[-1] if self.stack else None
        language = attributes.get('lang', parent['language'] if parent else 'fa') or 'fa'
        classes = set((attributes.get('class') or '').split())
        isolate = ((attributes.get('dir') or '').lower() == 'ltr' or bool(classes & {'ltr', 'en', 'num', 'refs'}))
        identity = (tag in INERT or tag in {'cite', 'q', 'blockquote'} or 'refs' in classes
                    or attributes.get('data-source-identity') == 'true'
                    or (parent is not None and parent['identity']))
        node = {'tag': tag, 'attrs': attributes, 'start': start, 'content': end,
                'language': language.lower(), 'isolate': isolate, 'identity': identity,
                'protected': tag in INERT or isolate or language.lower() not in ('fa', 'fa-ir')
                             or 'hidden' in attributes
                             or (parent is not None and parent['protected'])}
        self.nodes.append(node)
        self.protected.append((start, end))
        if tag not in VOID:
            self.stack.append(node)

    def handle_startendtag(self, tag, attrs):
        self.handle_starttag(tag, attrs)
        if tag not in VOID:
            self.finish(self.stack.pop(), self.position() + len(self.get_starttag_text()),
                        self.position() + len(self.get_starttag_text()))

    def finish(self, node, content_end, end):
        if node['protected']:
            self.protected.append((node['content'], content_end))
        if node['isolate'] and not node['identity']:
            # Child code/quotes retain literal wording even inside a prose isolate.
            chunks, cursor = [], node['content']
            for start, stop in sorted(self.identity):
                if stop <= cursor or start >= content_end:
                    continue
                chunks.extend((self.raw[cursor:max(cursor, start)], ' '))
                cursor = min(content_end, stop)
            chunks.append(self.raw[cursor:content_end])
            body = unescape(re.sub('<[^>]*>', '', ''.join(chunks)))
            self.isolates.append((node['start'], end, body))
        if node['identity'] or node['language'] not in ('fa', 'fa-ir', 'en', 'en-us', 'en-gb'):
            self.identity.append((node['start'], end))

    def handle_endtag(self, tag):
        start = self.position()
        close = self.raw.find('>', start)
        end = len(self.raw) if close < 0 else close + 1
        self.protected.append((start, end))
        for index in range(len(self.stack) - 1, -1, -1):
            if self.stack[index]['tag'] == tag:
                for node in reversed(self.stack[index:]):
                    self.finish(node, start, end)
                del self.stack[index:]
                break

    def handle_comment(self, data):
        start = self.position()
        end = min(len(self.raw), start + len(data) + 7)
        self.comments.append((start, end))
        self.protected.append((start, end))

    def handle_decl(self, decl):
        start = self.position()
        self.protected.append((start, start + len(decl) + 3))

    def decode_entity(self, token):
        start = self.position()
        decoded = unescape(token)
        self.entities.append((start, start + len(token), decoded))

    def handle_entityref(self, name):
        self.decode_entity('&' + name + (';' if self.raw[self.position() + len(name) + 1:self.position() + len(name) + 2] == ';' else ''))

    def handle_charref(self, name):
        self.decode_entity('&#' + name + (';' if self.raw[self.position() + len(name) + 2:self.position() + len(name) + 3] == ';' else ''))
