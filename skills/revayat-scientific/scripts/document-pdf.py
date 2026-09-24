#!/usr/bin/env python3
"""Native PDF inspection, extraction, forms, merging and OCR derivatives."""
import argparse
from contextlib import contextmanager, ExitStack, redirect_stdout, redirect_stderr
import hashlib
import io
import json
import math
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile

from pdf_forms import inventory, ensure_transformable, signature_present, plan_fill, apply_fill, verify_fill
from publication import publish_files, validate_destination
from pdf_outlines import outline_plan, apply_outlines, verify_outlines
from runtime import operation_log, run_command


@contextmanager
def open_pdf(path, *, transform=False, memory=False):
    import pymupdf
    path = Path(path)
    if not path.is_file() or path.stat().st_size > 512 * 1024 * 1024:
        raise ValueError('PDF input must be a file no larger than 512 MiB')
    opened = pymupdf.open(stream=path.read_bytes(), filetype='pdf') if memory else pymupdf.open(path)
    with opened as document:
        if not document.is_pdf or document.needs_pass or document.is_encrypted:
            raise ValueError('input must be an unencrypted PDF; decrypt an authorized separate copy first')
        if document.metadata.get('encryption'):
            raise ValueError('encrypted PDFs, including empty user passwords, require an authorized decrypted copy')
        if not 1 <= document.page_count <= 10000 or document.xref_length() > 200000:
            raise ValueError('PDF exceeds page/object limits or has no pages')
        if document.is_repaired:
            raise ValueError('PDF required parser repair; validate a separately repaired copy first')
        if transform:
            ensure_transformable(document)
        yield document


def geometry(document):
    return [{'page': page.number + 1, 'mediabox': list(page.mediabox),
             'cropbox': list(page.cropbox), 'rect': list(page.rect), 'rotation': page.rotation}
            for page in document]


def _json_bytes(value):
    return (json.dumps(value, ensure_ascii=False, indent=2, allow_nan=False) + '\n').encode('utf-8')


def write_report(value, destination, sources):
    destination = validate_destination(destination, sources)
    with tempfile.TemporaryDirectory(prefix='.revayat-pdf-', dir=destination.parent) as directory:
        stage = Path(directory) / 'report.json'
        stage.write_bytes(_json_bytes(value))
        json.loads(stage.read_text(encoding='utf-8'))
        publish_files([(stage, destination)], protected_sources=sources)


def inspect_pdf(source):
    with open_pdf(source) as document:
        return {'format': 'pdf', 'pages': geometry(document), 'fields': inventory(document),
                'signature_bearing': signature_present(document),
                'xfa': document.xref_get_key(document.pdf_catalog(), 'AcroForm/XFA')[0] != 'null',
                'embedded_file_count': document.embfile_count(),
                'validation': 'parsed-structure', 'visual_review': 'not-performed'}


def extract_text(source, destination):
    with open_pdf(source) as document:
        pages = [{'page': page.number + 1, 'rect': list(page.rect),
                  'text': page.get_text('text', sort=False)} for page in document]
    write_report({'format': 'pdf-text', 'order': 'source-stream', 'pages': pages,
                  'semantic_completeness': 'not-verified'}, destination, (source,))


def extract_tables(source, destination):
    pages = []
    with open_pdf(source) as document:
        for page in document:
            found = page.find_tables()
            tables = [{'index': index, 'bbox': list(table.bbox),
                       'row_count': table.row_count, 'column_count': table.col_count,
                       'cells': table.extract()}
                      for index, table in enumerate(found.tables)]
            pages.append({'page': page.number + 1, 'tables': tables})
    write_report({'format': 'pdf-tables', 'detection': 'heuristic-review-required',
                  'pages': pages}, destination, (source,))


def extract_images(source, directory):
    directory = Path(directory).absolute()
    # Validate the parent chain even when no image occurs in the document.
    validate_destination(directory / 'images.json', (source,))
    if directory.exists() and not directory.is_dir():
        raise ValueError('image destination must be a directory')
    outputs, images, placements = {}, {}, []
    with open_pdf(source) as document:
        for page in document:
            for info in page.get_image_info(xrefs=True):
                xref = info['xref']
                if not xref:
                    raise ValueError('inline image has no standalone original stream; use reviewed page extraction')
                if info['width'] * info['height'] > 50_000_000:
                    raise ValueError('embedded image exceeds 50 million pixels')
                placements.append({'page': page.number + 1, 'xref': xref,
                                   'bbox': list(info['bbox']), 'transform': list(info['transform'])})
                images[xref] = None
        pending = list(images)
        for xref in pending:
            dimensions = [document.xref_get_key(xref, key) for key in ('Width', 'Height')]
            if any(kind != 'int' for kind, _ in dimensions) or math.prod(int(value) for _, value in dimensions) > 50_000_000:
                raise ValueError('image or mask dimensions exceed supported limits')
            image = document.extract_image(xref)
            if not image or not re.fullmatch(r'[a-z0-9]{1,8}', image.get('ext', '')):
                raise ValueError('embedded image could not be extracted in a supported format')
            name = 'image-' + str(xref) + '.' + image['ext']
            stream_name = 'image-' + str(xref) + '.stream'
            raw = document.xref_stream_raw(xref)
            if raw is None:
                raise ValueError('embedded image has no retrievable original stream')
            outputs[name] = image['image']
            outputs[stream_name] = raw
            mask = image.get('smask', 0)
            images[xref] = {key: value for key, value in image.items() if key != 'image'}
            images[xref].update({'xref': xref, 'file': name, 'original_stream': stream_name,
                                'original_stream_sha256': hashlib.sha256(raw).hexdigest(),
                                'extracted_sha256': hashlib.sha256(image['image']).hexdigest(),
                                'pdf_dictionary': document.xref_object(xref, compressed=False)})
            if mask and mask not in images:
                images[mask] = None
                pending.append(mask)
            if sum(map(len, outputs.values())) > 512 * 1024 * 1024:
                raise ValueError('image batch exceeds 512 MiB output limit')
        outputs['images.json'] = _json_bytes({'format': 'pdf-images', 'images': list(images.values()),
                                             'placements': placements, 'pages': geometry(document)})
    for name in outputs:
        validate_destination(directory / name, (source,))
    created = not directory.exists()
    directory.mkdir(parents=True, exist_ok=True)
    try:
        with tempfile.TemporaryDirectory(prefix='.revayat-pdf-', dir=directory) as staging:
            plan = []
            for name, data in outputs.items():
                stage = Path(staging) / name
                stage.write_bytes(data)
                if stage.read_bytes() != data:
                    raise ValueError('staged image bytes failed validation')
                plan.append((stage, directory / name))
            publish_files(plan, protected_sources=(source,))
    except BaseException:
        if created and directory.exists() and not any(directory.iterdir()):
            directory.rmdir()
        raise


def _save_document(document, destination, sources, expected_geometry, validator=None):
    destination = validate_destination(destination, sources)
    with tempfile.TemporaryDirectory(prefix='.revayat-pdf-', dir=destination.parent) as directory:
        stage = Path(directory) / 'result.pdf'
        # Keep xref identities stable for the form-value verification plan.
        document.save(stage, garbage=0, deflate=True)
        with open_pdf(stage) as reopened:
            if geometry(reopened) != expected_geometry:
                raise ValueError('staged PDF changed page count or geometry')
            if validator:
                validator(reopened)
        publish_files([(stage, destination)], protected_sources=sources)


def merge_pdfs(sources, destination):
    import pymupdf
    if not 1 <= len(sources) <= 1000:
        raise ValueError('merge needs 1 to 1000 input PDFs')
    validate_destination(destination, sources)
    with ExitStack() as stack:
        documents = [stack.enter_context(open_pdf(source, transform=True)) for source in sources]
        if sum(document.page_count for document in documents) > 10000:
            raise ValueError('merged PDF exceeds 10000 pages')
        # Merging forms would create cross-document field-name collisions; this
        # operation preserves ordinary page content and refuses that ambiguity.
        if any(document.is_form_pdf or document.embfile_count() for document in documents):
            raise ValueError('merge does not support forms or attachments; prepare reviewed page-only copies')
        expected = []
        with pymupdf.open() as result:
            toc = []
            for document in documents:
                offset = result.page_count
                result.insert_pdf(document)
                toc.extend(outline_plan(document, offset))
                expected.extend(geometry(document))
            for index, page in enumerate(expected):
                page['page'] = index + 1
            if toc:
                apply_outlines(result, toc)
            _save_document(result, destination, sources, expected,
                           validator=lambda output: verify_outlines(output, toc))


def fill_pdf(source, destination, values, protected_sources=()):
    sources = (source, *protected_sources)
    validate_destination(destination, sources)
    with open_pdf(source, transform=True) as document:
        expected = geometry(document)
        plan = plan_fill(document, values)
        apply_fill(document, plan)
        _save_document(document, destination, sources, expected,
                       validator=lambda result: verify_fill(result, plan))


def _capture(command, timeout, logger):
    stdout, stderr = io.StringIO(), io.StringIO()
    with redirect_stdout(stdout), redirect_stderr(stderr):
        status = run_command(command, timeout, logger)
    if status != 0:
        raise RuntimeError('Tesseract subprocess failed; no derivative published')
    return stdout.getvalue()


def find_tesseract():
    configured = os.environ.get('TESSERACT_CMD')
    if configured:
        executable = Path(configured)
        if not executable.is_absolute() or not executable.is_file():
            raise ValueError('TESSERACT_CMD must name an existing absolute executable path')
        return str(executable)
    found = shutil.which('tesseract')
    if found:
        return found
    if os.name == 'nt':
        for variable, suffix in (('ProgramFiles', 'Tesseract-OCR/tesseract.exe'),
                                 ('ProgramFiles(x86)', 'Tesseract-OCR/tesseract.exe'),
                                 ('LOCALAPPDATA', 'Programs/Tesseract-OCR/tesseract.exe')):
            base = os.environ.get(variable)
            if base:
                candidate = Path(base) / suffix
                if candidate.is_file():
                    return str(candidate)
    return None


def ocr_pdf(source, destination, language, dpi, timeout, logger):
    import pymupdf
    if (not re.fullmatch(r'[A-Za-z][A-Za-z0-9_]*(?:\+[A-Za-z][A-Za-z0-9_]*)*', language)
            or len(language) > 256):
        raise ValueError('OCR language must be installed names joined by +, such as fas+eng')
    if type(dpi) is not int or not 72 <= dpi <= 600 or not 1 <= timeout <= 600:
        raise ValueError('OCR DPI must be 72..600 and page timeout 1..600 seconds')
    destination = validate_destination(destination, (source,))
    executable = find_tesseract()
    if not executable:
        raise ValueError('Tesseract unavailable through TESSERACT_CMD, PATH or standard install locations; configure it and install requested language data')
    available = set(_capture([executable, '--list-langs'], min(timeout, 30), logger).splitlines())
    if not set(language.split('+')) <= available:
        raise ValueError('one or more requested OCR languages are not installed')
    with open_pdf(source, transform=True) as document:
        expected = geometry(document)
        plan = []
        for page in document:
            if page.get_text('text').strip():
                continue
            pixels = math.ceil(page.rect.width * dpi / 72) * math.ceil(page.rect.height * dpi / 72)
            if pixels > 50_000_000:
                raise ValueError('OCR page rendering exceeds 50 million pixels')
            plan.append(page.number)
        logger.info('ocr planned_pages=%d already_text_pages=%d', len(plan), document.page_count - len(plan))
        with tempfile.TemporaryDirectory(prefix='.revayat-ocr-', dir=destination.parent) as directory:
            work = Path(directory)
            recognized = 0
            for page_number in plan:
                page = document[page_number]
                rotation = page.rotation
                page.set_rotation(0)
                try:
                    image = work / 'page.png'
                    page.get_pixmap(dpi=dpi, colorspace=pymupdf.csRGB, alpha=False).save(image)
                    output = work / 'recognized'
                    text_pdf = output.with_suffix('.pdf')
                    text_pdf.unlink(missing_ok=True)
                    _capture([executable, str(image), str(output), '-l', language,
                              '--dpi', str(dpi), '-c', 'textonly_pdf=1', 'pdf'], timeout, logger)
                    if not text_pdf.is_file():
                        raise RuntimeError('Tesseract did not produce a fresh text-layer PDF')
                    # show_pdf_page retains native graft-map references until the
                    # destination closes. A memory-backed layer cannot lock the
                    # temporary file on Windows during the next OCR page/cleanup.
                    with open_pdf(text_pdf, memory=True) as layer:
                        if layer.page_count != 1 or layer[0].get_images():
                            raise ValueError('OCR backend did not produce one text-only page')
                        if (abs(layer[0].rect.width - page.rect.width) > 1
                                or abs(layer[0].rect.height - page.rect.height) > 1):
                            raise ValueError('OCR text layer does not match source page dimensions')
                        traces = layer[0].get_texttrace()
                        if any(span['type'] != 3 for span in traces):
                            raise ValueError('OCR text layer contains visible text')
                        if layer[0].get_text('text').strip():
                            page.show_pdf_page(page.rect, layer, 0, keep_proportion=False)
                            recognized += 1
                        else:
                            logger.warning('ocr_no_text page=%d; manual review required', page_number + 1)
                finally:
                    page.set_rotation(rotation)
                logger.info('ocr_page_complete page=%d', page_number + 1)
            if plan and not recognized:
                raise ValueError('OCR recognized no text; no derivative published')
            _save_document(document, destination, (source,), expected)
            logger.info('ocr_recognized_pages=%d; language accuracy requires manual review', recognized)


def _fields(path):
    if path.stat().st_size > 8 * 1024 * 1024:
        raise ValueError('fields JSON exceeds 8 MiB limit')

    def unique(pairs):
        values = {}
        for key, value in pairs:
            if key in values:
                raise ValueError('duplicate field name in JSON')
            values[key] = value
        return values

    return json.loads(path.read_text(encoding='utf-8'), object_pairs_hook=unique)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest='command', required=True)
    inspect = commands.add_parser('inspect')
    inspect.add_argument('input', type=Path)
    inspect.add_argument('--output', required=True, type=Path)
    for name in ('text', 'tables', 'images', 'fill', 'ocr'):
        command = commands.add_parser(name)
        command.add_argument('input', type=Path)
        command.add_argument('output', type=Path)
        if name == 'fill':
            command.add_argument('--fields', required=True, type=Path)
        if name == 'ocr':
            command.add_argument('--language', required=True)
            command.add_argument('--dpi', type=int, default=300)
            command.add_argument('--page-timeout', type=int, default=120)
    merge = commands.add_parser('merge')
    merge.add_argument('output', type=Path)
    merge.add_argument('inputs', nargs='+', type=Path)
    args = parser.parse_args(argv)
    try:
        with operation_log('document-pdf', Path(__file__).resolve().parent / 'logs') as logger:
            logger.debug('operation=%s', args.command)
            if args.command == 'inspect':
                write_report(inspect_pdf(args.input), args.output, (args.input,))
            elif args.command == 'text':
                extract_text(args.input, args.output)
            elif args.command == 'tables':
                extract_tables(args.input, args.output)
            elif args.command == 'images':
                extract_images(args.input, args.output)
            elif args.command == 'merge':
                merge_pdfs(args.inputs, args.output)
            elif args.command == 'fill':
                fill_pdf(args.input, args.output, _fields(args.fields), (args.fields,))
            else:
                ocr_pdf(args.input, args.output, args.language, args.dpi, args.page_timeout, logger)
            logger.info('completed operation=%s; content and visual review remain separate', args.command)
            print('PDF operation completed; review extracted content and rendered output separately.')
            return 0
    except ImportError:
        print('document-pdf: install the skill requirements; PyMuPDF is required.', file=sys.stderr)
        return 2
    except ValueError as error:
        print('document-pdf: ' + (str(error) if type(error) is ValueError else 'invalid input encoding or JSON'), file=sys.stderr)
        return 2
    except subprocess.TimeoutExpired:
        print('document-pdf: OCR timed out; owned process tree terminated.', file=sys.stderr)
        return 124
    except KeyboardInterrupt:
        print('document-pdf: cancelled.', file=sys.stderr)
        return 130
    except (OSError, RuntimeError) as error:
        message = str(error) if str(error).startswith('publication rollback needs recovery: ') else type(error).__name__
        print('document-pdf: operation failed (' + message + '); source inputs preserved.', file=sys.stderr)
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
