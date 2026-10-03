"""Shared bounded PDF admission; transformations refuse restricted inputs."""
from contextlib import contextmanager
from pathlib import Path

from pdf_forms import ensure_transformable

MAX_PDF_BYTES = 512 * 1024 * 1024
MAX_PDF_PAGES = 10000
MAX_PDF_OBJECTS = 200000


@contextmanager
def open_pdf(path, *, transform=False, memory=False):
    import pymupdf
    path = Path(path)
    if not path.is_file() or path.stat().st_size > MAX_PDF_BYTES:
        raise ValueError('PDF input must be a file no larger than 512 MiB')
    opened = pymupdf.open(stream=path.read_bytes(), filetype='pdf') if memory else pymupdf.open(path)
    with opened as document:
        if not document.is_pdf or document.needs_pass or document.is_encrypted:
            raise ValueError('input must be an unencrypted PDF; decrypt an authorized separate copy first')
        if document.metadata.get('encryption'):
            raise ValueError('encrypted PDFs, including empty user passwords, require an authorized decrypted copy')
        if not 1 <= document.page_count <= MAX_PDF_PAGES or document.xref_length() > MAX_PDF_OBJECTS:
            raise ValueError('PDF exceeds page/object limits or has no pages')
        if document.is_repaired:
            raise ValueError('PDF required parser repair; validate a separately repaired copy first')
        if transform:
            ensure_transformable(document)
        yield document
