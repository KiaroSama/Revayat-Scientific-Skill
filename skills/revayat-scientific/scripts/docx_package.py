"""Bounded OOXML inspection and byte-preserving text-node edits.

No archive member is extracted and no relationship is fetched. This validates
the supported package structure, not the entire ECMA-376 schema or pagination.
"""
import hashlib
from pathlib import Path, PurePosixPath
import posixpath
import re
import stat
import tempfile
from urllib.parse import unquote, urlsplit
import xml.etree.ElementTree as ET
from xml.parsers import expat
from xml.sax.saxutils import escape
import zipfile

from publication import publish_files, validate_destination

W = 'http://schemas.openxmlformats.org/wordprocessingml/2006/main'
R = 'http://schemas.openxmlformats.org/package/2006/relationships'
C = 'http://schemas.openxmlformats.org/package/2006/content-types'
MAIN_TYPE = 'application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml'
STORY = re.compile(r'word/(document|header[0-9]+|footer[0-9]+|footnotes|endnotes|comments)\.xml\Z')
MAX_TOTAL = 256 * 1024 * 1024
MAX_MEMBER = 64 * 1024 * 1024
MAX_XML = 16 * 1024 * 1024


def _xml(data):
    if len(data) > MAX_XML:
        raise ValueError('XML part exceeds 16 MiB limit')
    text = data.decode('utf-8-sig')
    if re.search(r'<!\s*(?:DOCTYPE|ENTITY)', text, re.I):
        raise ValueError('DTD and entity declarations are not supported')
    declaration = re.match(r'<\?xml\s+[^?]*encoding=["\']([^"\']+)', text)
    if declaration and declaration[1].lower() not in ('utf-8', 'utf8'):
        raise ValueError('XML parts must use UTF-8; convert a copy before editing')
    return ET.fromstring(data)


def _safe_name(name):
    parts = PurePosixPath(name).parts
    return (bool(name) and not name.startswith('/') and '\\' not in name
            and ':' not in name and all(part not in ('', '.', '..') for part in name.split('/'))
            and str(PurePosixPath(name)) == name and bool(parts))


def read_package(path):
    path = Path(path)
    if not path.is_file() or path.stat().st_size > 128 * 1024 * 1024:
        raise ValueError('DOCX must be a regular ZIP file no larger than 128 MiB')
    with zipfile.ZipFile(path) as archive:
        entries = archive.infolist()
        if not entries or len(entries) > 4096:
            raise ValueError('DOCX must contain 1 to 4096 archive members')
        seen, total = set(), 0
        for entry in entries:
            name = entry.filename
            if not _safe_name(name.rstrip('/') if entry.is_dir() else name) or name.casefold() in seen:
                raise ValueError('unsafe or duplicate archive member name')
            seen.add(name.casefold())
            if (entry.flag_bits & 1 or stat.S_ISLNK(entry.external_attr >> 16)
                    or entry.compress_type not in (zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED)):
                raise ValueError('encrypted, linked or unsupported ZIP member')
            total += entry.file_size
            if (entry.file_size > MAX_MEMBER or total > MAX_TOTAL
                    or entry.file_size > max(1, entry.compress_size) * 1000):
                raise ValueError('DOCX exceeds archive expansion limits')
        # Reading checks the CRC; the directory limits above bound allocation.
        members = {entry.filename: archive.read(entry) for entry in entries}
        comment = archive.comment
    roots = {name: _xml(data) for name, data in members.items()
             if name.endswith(('.xml', '.rels'))}
    required = ('[Content_Types].xml', '_rels/.rels', 'word/document.xml')
    if any(name not in roots for name in required):
        raise ValueError('DOCX is missing required package parts')
    if roots['[Content_Types].xml'].tag != '{' + C + '}Types':
        raise ValueError('invalid package content types root')
    document = roots['word/document.xml']
    if document.tag != '{' + W + '}document' or document.find('{' + W + '}body') is None:
        raise ValueError('unsupported WordprocessingML; convert Strict OOXML to a Transitional copy')
    types = {node.get('PartName'): node.get('ContentType')
             for node in roots['[Content_Types].xml'] if node.tag == '{' + C + '}Override'}
    defaults = {node.get('Extension'): node.get('ContentType')
                for node in roots['[Content_Types].xml'] if node.tag == '{' + C + '}Default'}
    for name in members:
        if (name != '[Content_Types].xml' and not name.endswith('/')
                and not types.get('/' + name) and not defaults.get(name.rsplit('.', 1)[-1])):
            raise ValueError('archive member has no declared content type')
    main_type = types.get('/word/document.xml', '')
    if main_type not in (MAIN_TYPE, 'application/vnd.ms-word.document.macroEnabled.main+xml'):
        raise ValueError('unsupported main document content type')
    relationships = []
    for name, root in roots.items():
        if not name.endswith('.rels'):
            continue
        if root.tag != '{' + R + '}Relationships':
            raise ValueError('invalid relationships root')
        ids = set()
        owner = '' if name == '_rels/.rels' else str(PurePosixPath(name).parent.parent)
        for rel in root:
            identifier, target = rel.get('Id'), rel.get('Target')
            if (rel.tag != '{' + R + '}Relationship' or not identifier or identifier in ids
                    or not target or not rel.get('Type')):
                raise ValueError('invalid or duplicate relationship')
            ids.add(identifier)
            mode = rel.get('TargetMode', 'Internal')
            if mode not in ('Internal', 'External'):
                raise ValueError('unknown relationship target mode')
            resolved = None
            if mode == 'Internal':
                parsed = urlsplit(target)
                decoded = unquote(parsed.path)
                if parsed.scheme or parsed.netloc or '\\' in decoded:
                    raise ValueError('unsafe internal relationship')
                resolved = posixpath.normpath(decoded.lstrip('/') if decoded.startswith('/')
                                             else posixpath.join(owner, decoded))
                if not _safe_name(resolved) or resolved not in members:
                    raise ValueError('missing or escaping internal relationship')
            relationships.append({'part': name, 'id': identifier, 'type': rel.get('Type'),
                                  'target': target, 'mode': mode, 'resolved': resolved})
    if not any(rel['part'] == '_rels/.rels' and rel['resolved'] == 'word/document.xml'
               and rel['type'].endswith('/officeDocument') for rel in relationships):
        raise ValueError('DOCX has no main document relationship')
    unsupported = []
    if any('vba' in name.lower() for name in members) or 'macroEnabled' in main_type:
        unsupported.append('macros')
    if any(name.lower().startswith('_xmlsignatures/') for name in members):
        unsupported.append('digital-signatures')
    if any(rel['type'].endswith(('/oleObject', '/package', '/aFChunk')) for rel in relationships):
        unsupported.append('embedded-or-alternate-content')
    return entries, members, roots, relationships, unsupported, comment


def inspect_package(path):
    _, members, roots, relationships, unsupported, _ = read_package(path)
    nodes, sections, structures = [], [], {}
    counted = ('tbl', 'drawing', 'fldSimple', 'fldChar', 'ins', 'del', 'commentReference',
               'footnoteReference', 'endnoteReference', 'hyperlink', 'oMath')
    for part, root in roots.items():
        if STORY.fullmatch(part):
            for index, node in enumerate(root.iter('{' + W + '}t')):
                nodes.append({'part': part, 'index': index, 'text': node.text or ''})
        for node in root.iter():
            local = node.tag.rsplit('}', 1)[-1]
            if local in counted:
                structures[local] = structures.get(local, 0) + 1
            if node.tag == '{' + W + '}sectPr':
                geometry = {}
                for field in ('pgSz', 'pgMar', 'cols'):
                    element = node.find('{' + W + '}' + field)
                    if element is not None:
                        geometry[field] = {key.rsplit('}', 1)[-1]: value
                                           for key, value in element.attrib.items()}
                sections.append({'part': part, 'geometry_twips': geometry})
    media = [{'part': name, 'bytes': len(data), 'sha256': hashlib.sha256(data).hexdigest()}
             for name, data in members.items() if name.startswith('word/media/')]
    return {'format': 'docx', 'validation': 'structural-only', 'render_status': 'not-performed',
            'text_nodes': nodes, 'sections': sections, 'relationships': relationships,
            'media': media, 'structures': structures, 'unsupported': unsupported}


def require_editable(unsupported):
    if unsupported:
        raise ValueError('unsupported DOCX features: ' + ', '.join(unsupported)
                         + '; retain the original and convert/review a separate copy')


def _tag_end(data, start):
    quote = None
    for index in range(start, len(data)):
        value = data[index]
        if quote:
            if value == quote:
                quote = None
        elif value in (34, 39):
            quote = value
        elif value == 62:
            return index + 1
    raise ValueError('unterminated XML tag')


def _text_spans(data):
    parser = expat.ParserCreate(namespace_separator='}')
    spans, active = [], []

    def start(name, attrs):
        if active:
            raise ValueError('nested markup inside a text node is unsupported')
        if name == W + '}t':
            first = parser.CurrentByteIndex
            end = _tag_end(data, first)
            active.append((first, end, data[first:end].rstrip().endswith(b'/>')))

    def end(name):
        if name == W + '}t':
            first, content, empty = active.pop()
            spans.append((first, content, content if empty else parser.CurrentByteIndex, empty))

    def markup(*_):
        if active:
            raise ValueError('comments or processing instructions inside text nodes are unsupported')

    parser.StartElementHandler, parser.EndElementHandler = start, end
    parser.CommentHandler = parser.ProcessingInstructionHandler = markup
    parser.Parse(data, True)
    return spans


def _replacement(data, span, text):
    first, start, end, empty = span
    tag = data[first:start]
    if empty:
        tag = tag.rstrip()[:-2] + b'>'
    # Preserve every untouched byte, including namespace prefixes and markup
    # compatibility declarations that a generic XML serializer may invalidate.
    if text != text.strip():
        space = re.compile(rb'\bxml:space\s*=\s*(["\']).*?\1')
        tag = space.sub(b'xml:space="preserve"', tag) if space.search(tag) else tag[:-1] + b' xml:space="preserve">'
    value = tag + escape(text).encode('utf-8')
    if empty:
        prefix = re.match(rb'<([^\s/>]+)', tag)[1]
        value += b'</' + prefix + b'>'
    return first, end, value


def edit_package(source, destination, patches, protected_sources=()):
    protected_sources = (source, *protected_sources)
    destination = validate_destination(destination, protected_sources)
    entries, members, roots, _, unsupported, comment = read_package(source)
    require_editable(unsupported)
    if not isinstance(patches, list) or not patches or len(patches) > 100000:
        raise ValueError('patch must be a nonempty array of at most 100000 edits')
    edits, seen, node_index = {}, set(), {}
    for patch in patches:
        if not isinstance(patch, dict) or set(patch) != {'part', 'index', 'expected', 'text'}:
            raise ValueError('patch needs exactly part, index, expected and text')
        part, index, expected, text = (patch[key] for key in ('part', 'index', 'expected', 'text'))
        if (not isinstance(part, str) or not STORY.fullmatch(part) or part not in roots
                or type(index) is not int or index < 0
                or not isinstance(expected, str) or not isinstance(text, str)):
            raise ValueError('invalid patch address or text type')
        if (part, index) in seen:
            raise ValueError('duplicate patch address')
        seen.add((part, index))
        if part not in node_index:
            node_index[part] = list(roots[part].iter('{' + W + '}t'))
        nodes = node_index[part]
        if index >= len(nodes) or (nodes[index].text or '') != expected:
            raise ValueError('stale patch: expected text does not match addressed node')
        if any(ord(char) < 32 for char in text) or any(0xD800 <= ord(char) <= 0xDFFF or ord(char) in (0xFFFE, 0xFFFF) for char in text):
            raise ValueError('patch text contains unsupported control/XML characters')
        edits.setdefault(part, []).append((index, text))
    changed = {}
    for part, items in edits.items():
        data = members[part]
        spans = _text_spans(data)
        replacements = [_replacement(data, spans[index], text) for index, text in items]
        output_size = len(data) + sum(len(value) - (end - start)
                                      for start, end, value in replacements)
        if output_size > MAX_XML:
            raise ValueError('XML part exceeds 16 MiB limit')
        # Rebuild once in source order. Repeated whole-part slices make a large
        # valid translation quadratic in both edit count and document size.
        chunks, cursor = [], 0
        for start, end, value in sorted(replacements):
            chunks.extend((data[cursor:start], value))
            cursor = end
        chunks.append(data[cursor:])
        data = b''.join(chunks)
        _xml(data)
        changed[part] = data
    with tempfile.TemporaryDirectory(prefix='.revayat-docx-', dir=destination.parent) as directory:
        staged = Path(directory) / 'document.docx'
        with zipfile.ZipFile(staged, 'w') as archive:
            archive.comment = comment
            for entry in entries:
                archive.writestr(entry, changed.get(entry.filename, members[entry.filename]))
        read_package(staged)
        publish_files([(staged, destination)], protected_sources=protected_sources)
