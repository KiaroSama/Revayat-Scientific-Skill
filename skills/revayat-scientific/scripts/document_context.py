"""Resolve document-local terminology, inventory and asset boundaries."""
from dataclasses import dataclass
from pathlib import Path
import re
from urllib.parse import unquote, urlsplit

from terminology_data import load_pairs, load_terms_pairs


def select_source(source, requested_engine, available):
    """Resolve the source that will really render before any lint or asset gate."""
    source = Path(source).resolve()
    if not source.is_file() or source.suffix.lower() not in ('.tex', '.html', '.htm'):
        raise ValueError('expected an existing .tex or .html source')
    if requested_engine and requested_engine not in ('tex', 'chromium', 'weasyprint'):
        raise ValueError('unknown PDF engine')
    if requested_engine and requested_engine not in available:
        raise ValueError('explicit PDF engine is unavailable: ' + requested_engine)
    if source.suffix.lower() != '.tex' and requested_engine == 'tex':
        raise ValueError('tex engine requires a TeX source')
    if source.suffix.lower() == '.tex':
        if requested_engine == 'tex' or (not requested_engine and 'tex' in available):
            return source, 'tex'
        source = source.with_suffix('.html')
        if not source.is_file():
            raise ValueError('HTML rendering requires an existing sibling .html source')
    engine = requested_engine or next((name for name in ('chromium', 'weasyprint')
                                       if name in available), None)
    if engine is None:
        raise ValueError('no compatible PDF renderer is available')
    return source, engine


@dataclass
class DocumentContext:
    source: Path
    root: Path
    pairs: list
    manifest: list | None

    @classmethod
    def load(cls, source, *, house, level='system-docs', pairs=None,
             terms=None, manifest=None, strict=False):
        source = Path(source).resolve()
        if not source.is_file() or source.suffix.lower() not in ('.tex', '.html', '.htm'):
            raise ValueError('expected an existing .tex or .html source')
        if pairs is not None and not Path(pairs).is_file():
            raise ValueError('explicit --pairs file is missing')
        rows = load_pairs([Path(house)] + ([Path(pairs)] if pairs is not None else []), level)
        root = source.parent
        terms_path = Path(terms) if terms is not None else root / 'terms.tsv'
        manifest_path = Path(manifest) if manifest is not None else root / 'manifest.txt'
        if strict or terms is not None or terms_path.exists():
            if not terms_path.is_file():
                raise ValueError('--strict requires --terms FILE (or terms.tsv next to the source)')
            extra, errors = load_terms_pairs(terms_path)
            if errors:
                raise ValueError('terms-calque: ' + '; '.join(errors))
            seen = {(row[0], row[1]) for row in rows}
            rows += [row for row in extra if (row[0], row[1]) not in seen]
        names = None
        if strict or manifest is not None or manifest_path.exists():
            if not manifest_path.is_file():
                raise ValueError('--strict requires --manifest FILE (or manifest.txt next to the source)')
            names = [line.strip() for line in manifest_path.read_text(encoding='utf-8').splitlines()
                     if line.strip() and not line.lstrip().startswith('#')]
        return cls(source, root, rows, names)

    def asset(self, reference):
        parsed = urlsplit(reference)
        if parsed.scheme or parsed.netloc:
            raise ValueError('document assets must be approved local files')
        relative = unquote(parsed.path)
        if '\x00' in relative:
            raise ValueError('invalid asset path')
        candidate = self.root / relative
        paths = [candidate]
        if not candidate.suffix:
            paths += [candidate.with_suffix(ext) for ext in ('.pdf', '.png', '.jpg', '.jpeg', '.eps')]
        matches = [path.resolve() for path in paths if path.is_file()]
        if len(matches) != 1:
            raise ValueError('asset is missing or ambiguous: ' + reference)
        if not matches[0].is_relative_to(self.root):
            raise ValueError('asset leaves the approved job root')
        return matches[0]
