#!/usr/bin/env python3
"""Shared source selection, asset checks and delivery for both native adapters."""
import argparse
import json
from pathlib import Path
import shutil
import sys
import tempfile

from build_guard import create_guard, check_guard, file_hash
from document_context import DocumentContext, select_source
from publication import publish_files, validate_destination
from runtime import operation_log, run_command
from source_model import Source

HERE = Path(__file__).resolve().parent


def source_assets(source):
    model = Source(source)
    context = DocumentContext(Path(source).resolve(), Path(source).resolve().parent, [], None)
    return list(dict.fromkeys(context.asset(reference) for _, reference in model.image_references()))


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest='command', required=True)
    selection = commands.add_parser('select')
    selection.add_argument('source', type=Path)
    selection.add_argument('--engine', default='auto')
    selection.add_argument('--available', default='')
    assets = commands.add_parser('assets')
    assets.add_argument('source', type=Path)
    destination = commands.add_parser('destination')
    destination.add_argument('output', type=Path)
    destination.add_argument('sources', nargs='+', type=Path)
    publish = commands.add_parser('publish')
    publish.add_argument('source', type=Path)
    publish.add_argument('output', type=Path)
    publish.add_argument('--guard', type=Path)
    guard = commands.add_parser('guard')
    guard.add_argument('record', type=Path)
    for name in ('source', 'requested', 'terms', 'manifest', 'working', 'output'):
        guard.add_argument('--' + name, required=True, type=Path)
    guard.add_argument('--sample', action='append', default=[], type=Path)
    checking = commands.add_parser('guard-check')
    checking.add_argument('record', type=Path)
    samples = commands.add_parser('samples')
    samples.add_argument('record', type=Path)
    samples.add_argument('stages', nargs='+', type=Path)
    args = parser.parse_args(argv)
    with operation_log('build-support', HERE / 'logs') as logger:
        logger.info('stage=%s', args.command)
        if args.command == 'guard':
            record = create_guard(args.record, args.source, args.working, args.output,
                terms=args.terms, manifest=args.manifest, requested=args.requested, samples=args.sample)
            logger.info('build_guard_created checked_inputs=%d outputs=%d', len(record['inputs']), len(record['outputs']))
        elif args.command == 'guard-check':
            check_guard(args.record)
        elif args.command == 'samples':
            from PIL import Image
            record = check_guard(args.record)
            if not record['rendered']:
                raise ValueError('preview publication requires a sealed rendered PDF')
            destinations = {Path(name).name: Path(name) for name in record['outputs'][2:]}
            if (len(args.stages) != len(destinations)
                    or {stage.name for stage in args.stages} != set(destinations)):
                raise ValueError('verification requires the complete planned preview set')
            planned = []
            for stage in args.stages:
                if (stage.absolute().parent != args.record.absolute().parent
                        or stage.name not in destinations or stage.is_symlink() or not stage.is_file()):
                    raise ValueError('unexpected or missing verification sample')
                with Image.open(stage) as image:
                    if image.format != 'PNG' or image.width * image.height > 50_000_000:
                        raise ValueError('invalid or oversized verification sample')
                    image.verify()
                planned.append((stage, destinations[stage.name]))
            check_guard(args.record)
            publish_files(planned, protected_sources=[args.record, *map(Path, record['inputs']), *map(Path, record['rendered'])])
            logger.info('verification_samples_published count=%d', len(planned))
        elif args.command == 'select':
            source, engine = select_source(args.source,
                None if args.engine == 'auto' else args.engine, set(args.available.split(',')))
            print(json.dumps({'source': str(source), 'engine': engine}))
        elif args.command == 'destination':
            validate_destination(args.output, args.sources)
        elif args.command == 'assets':
            files = source_assets(args.source)
            rasters = [path for path in files if path.suffix.lower() in
                       {'.png', '.jpg', '.jpeg', '.tif', '.tiff', '.webp', '.gif'}]
            if rasters:
                return run_command([sys.executable, str(HERE / 'prepare-figures.py'),
                                    *map(str, rasters), '--check'], 90, logger)
            logger.info('required_assets=%d raster_assets=0', len(files))
        else:
            record = check_guard(args.guard) if args.guard else None
            protected = [args.source]
            if record:
                if (str(args.source.absolute()) != record['outputs'][0]
                        or str(args.output.absolute()) != record['outputs'][1]
                        or not record['rendered']):
                    raise ValueError('delivery does not match the sealed build plan')
                protected.extend([args.guard, *map(Path, record['inputs'])])
            validate_destination(args.output, protected)
            args.output.parent.mkdir(parents=True, exist_ok=True)
            with tempfile.TemporaryDirectory(prefix='.revayat-delivery-', dir=args.output.parent) as directory:
                stage = Path(directory) / 'document.pdf'
                shutil.copyfile(args.source, stage)
                # Byte equality binds publication to the PDF the caller verified.
                if stage.read_bytes() != args.source.read_bytes():
                    raise ValueError('PDF changed during delivery staging')
                if record:
                    check_guard(args.guard)
                    if file_hash(stage) != record['rendered'][record['outputs'][0]]:
                        raise ValueError('delivery bytes differ from the checked rendered PDF')
                publish_files([(stage, args.output)], protected_sources=protected)
        return 0


if __name__ == '__main__':
    try:
        raise SystemExit(main())
    except (OSError, ValueError, RuntimeError) as error:
        print(f'build-support: {error}', file=sys.stderr)
        raise SystemExit(1)
