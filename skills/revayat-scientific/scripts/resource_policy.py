"""Local scientific-render resources, with no implicit network or attachment access."""
import base64
import binascii
import hashlib
import mimetypes
from pathlib import Path
from urllib.parse import unquote, unquote_to_bytes, urlsplit
from urllib.request import url2pathname

from html_source import ParsedHTML

ORIGIN = 'https://revayat.invalid'
MAX_RESOURCE_BYTES = 64 * 1024 * 1024
MAX_TOTAL_BYTES = 256 * 1024 * 1024
ALLOWED = {'.css', '.png', '.jpg', '.jpeg', '.gif', '.webp', '.svg', '.ttf',
           '.otf', '.woff', '.woff2', '.ico', '.pdf'}


class ResourcePolicy:
    def __init__(self, source):
        self.source = Path(source).resolve()
        self.root = self.source.parent
        if not self.source.is_file() or self.source.stat().st_size > MAX_RESOURCE_BYTES:
            raise ValueError('HTML source is unavailable or exceeds 64 MiB')
        with self.source.open('rb') as handle:
            self.source_bytes = handle.read(MAX_RESOURCE_BYTES + 1)
        if len(self.source_bytes) > MAX_RESOURCE_BYTES:
            raise ValueError('HTML source exceeds 64 MiB')
        self.source_text = self.source_bytes.decode('utf-8')
        self.resources = {str(self.source): hashlib.sha256(self.source_bytes).hexdigest()}
        model = ParsedHTML(self.source_text)
        for node in model.nodes:
            attrs = node['attrs']
            if 'attachment' in (attrs.get('rel') or '').lower().split():
                raise ValueError('PDF attachment requires explicit authorization; omitted by this renderer')
            if (node['tag'] in {'script', 'iframe', 'object', 'embed', 'base'}
                    or (node['tag'] == 'meta' and (attrs.get('http-equiv') or '').lower() == 'refresh')):
                raise ValueError('active HTML content is not supported for scientific rendering')
        self.denied = False
        self.total = 0
        self.requests = 0

    def fetch(self, url):
        try:
            self.requests += 1
            if self.requests > 2048:
                raise ValueError('render resource count exceeds 2048')
            parsed = urlsplit(url)
            if parsed.scheme == 'data':
                header, encoded = url.split(',', 1)
                mime = header[5:].split(';', 1)[0]
                if mime not in {'image/png', 'image/jpeg', 'image/gif', 'image/webp', 'image/svg+xml'}:
                    raise ValueError('unsupported embedded resource type')
                if len(encoded) > MAX_RESOURCE_BYTES * 2:
                    raise ValueError('embedded resource is too large')
                data = (base64.b64decode(encoded, validate=True) if header.endswith(';base64')
                        else unquote_to_bytes(encoded))
            else:
                if parsed.scheme == 'https' and parsed.netloc == 'revayat.invalid':
                    path = self.root / unquote(parsed.path).lstrip('/')
                elif parsed.scheme == 'file' and parsed.netloc in ('', 'localhost'):
                    path = Path(url2pathname(parsed.path))
                else:
                    raise ValueError('network and unapproved URL schemes are denied')
                resolved = path.resolve()
                if (not resolved.is_relative_to(self.root) or not resolved.is_file()
                        or (resolved != self.source and resolved.suffix.lower() not in ALLOWED)):
                    raise ValueError('resource is outside the approved document asset boundary')
                if resolved.stat().st_size > MAX_RESOURCE_BYTES:
                    raise ValueError('render resource exceeds 64 MiB')
                if resolved == self.source:
                    data = self.source_bytes
                else:
                    with resolved.open('rb') as handle:
                        data = handle.read(MAX_RESOURCE_BYTES + 1)
                digest = hashlib.sha256(data).hexdigest()
                if str(resolved) in self.resources and self.resources[str(resolved)] != digest:
                    raise ValueError('resource changed during rendering')
                self.resources[str(resolved)] = digest
                mime = mimetypes.guess_type(resolved.name)[0] or 'application/octet-stream'
            self.total += len(data)
            if len(data) > MAX_RESOURCE_BYTES or self.total > MAX_TOTAL_BYTES:
                raise ValueError('render resource byte limit exceeded')
            return data, mime
        except (OSError, ValueError, binascii.Error):
            self.denied = True
            raise
