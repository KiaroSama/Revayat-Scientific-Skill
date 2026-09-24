#!/usr/bin/env python3
"""Shared source selection, asset checks and delivery for both native adapters."""
import argparse
import json
from pathlib import Path
import shutil
import sys
import tempfile

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
    args = parser.parse_args(argv)
    with operation_log('build-support', HERE / 'logs') as logger:
        logger.info('stage=%s', args.command)
        if args.command == 'select':
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
            validate_destination(args.output, [args.source])
            args.output.parent.mkdir(parents=True, exist_ok=True)
            with tempfile.TemporaryDirectory(prefix='.revayat-delivery-', dir=args.output.parent) as directory:
                stage = Path(directory) / 'document.pdf'
                shutil.copyfile(args.source, stage)
                # Byte equality binds publication to the PDF the caller verified.
                if stage.read_bytes() != args.source.read_bytes():
                    raise ValueError('PDF changed during delivery staging')
                publish_files([(stage, args.output)], protected_sources=[args.source])
        return 0


if __name__ == '__main__':
    try:
        raise SystemExit(main())
    except (OSError, ValueError, RuntimeError) as error:
        print(f'build-support: {error}', file=sys.stderr)
        raise SystemExit(1)
