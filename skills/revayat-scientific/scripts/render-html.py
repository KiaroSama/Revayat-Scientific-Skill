#!/usr/bin/env python3
"""Render static HTML through a restricted resource loader and owned process tree."""
import argparse
import hashlib
import json
from pathlib import Path
import sys
import tempfile
from urllib.parse import quote, urlsplit

from publication import publish_files, validate_destination
from resource_policy import MAX_RESOURCE_BYTES, ORIGIN, ResourcePolicy
from runtime import operation_log, run_command

HERE = Path(__file__).resolve().parent


def chromium(policy, destination, executable):
    from playwright.sync_api import sync_playwright

    failures = []
    with tempfile.TemporaryDirectory(prefix='browser-', dir=destination.parent) as profile, sync_playwright() as playwright:
        context = playwright.chromium.launch_persistent_context(profile,
            executable_path=executable, headless=True, chromium_sandbox=True,
            java_script_enabled=False, service_workers='block', accept_downloads=False,
            timeout=45000)
        try:
            context.set_default_timeout(45000)

            def route_resource(route):
                try:
                    if route.request.method != 'GET':
                        raise ValueError('only read-only resource requests are supported')
                    if urlsplit(route.request.url).path == '/favicon.ico':
                        route.fulfill(status=204, body='')
                        return
                    data, mime = policy.fetch(route.request.url)
                    route.fulfill(body=data, content_type=mime,
                        headers={'Content-Security-Policy': "script-src 'none'; object-src 'none'; frame-src 'none'; base-uri 'none'; form-action 'none'"})
                except (OSError, ValueError):
                    failures.append('denied or unavailable document resource')
                    route.abort('blockedbyclient')

            context.route('**/*', route_resource)
            page = context.new_page()
            page.on('requestfailed', lambda request: failures.append('resource request failed'))
            page.goto(ORIGIN + '/' + quote(policy.source.name), wait_until='load', timeout=45000)
            page.evaluate('document.fonts.ready')
            if failures or policy.denied:
                raise ValueError('render resource access was denied or failed')
            page.pdf(path=str(destination), print_background=True, prefer_css_page_size=True)
            if failures or policy.denied:
                raise ValueError('render resource access was denied or failed')
        finally:
            context.close()


def weasyprint(policy, destination):
    from weasyprint import HTML
    from weasyprint.urls import URLFetcher, URLFetcherResponse, FatalURLFetchingError

    class LocalFetcher(URLFetcher):
        def fetch(self, url, headers=None):
            try:
                data, mime = policy.fetch(url)
                return URLFetcherResponse(url, data, {'Content-Type': mime})
            except (OSError, ValueError) as error:
                raise FatalURLFetchingError('document resource denied') from error

    try:
        HTML(string=policy.source_text, base_url=policy.source.as_uri(),
             url_fetcher=LocalFetcher()).write_pdf(destination)
    except FatalURLFetchingError as error:
        raise ValueError('render resource access was denied') from error
    if policy.denied:
        raise ValueError('render resource access was denied')


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('source', type=Path)
    parser.add_argument('output', type=Path)
    parser.add_argument('--engine', required=True, choices=('chromium', 'weasyprint'))
    parser.add_argument('--browser')
    parser.add_argument('--worker', action='store_true', help=argparse.SUPPRESS)
    args = parser.parse_args(argv)
    with operation_log('render-html', HERE / 'logs') as logger:
        validate_destination(args.output, [args.source])
        args.output.parent.mkdir(parents=True, exist_ok=True)
        if args.worker:
            policy = ResourcePolicy(args.source)
            if args.engine == 'chromium':
                if not args.browser:
                    raise ValueError('Chromium executable must be explicitly resolved')
                chromium(policy, args.output, args.browser)
            else:
                weasyprint(policy, args.output)
            args.output.with_suffix('.resources.json').write_text(
                json.dumps(policy.resources, ensure_ascii=False), encoding='utf-8')
            logger.info('render_complete engine=%s resources=%d', args.engine, policy.requests)
            return 0
        with tempfile.TemporaryDirectory(prefix='.revayat-render-', dir=args.output.parent) as directory:
            stage = Path(directory) / 'document.pdf'
            command = [sys.executable, str(Path(__file__).resolve()), str(args.source),
                       str(stage), '--engine', args.engine, '--worker']
            if args.browser:
                command += ['--browser', args.browser]
            code = run_command(command, 120, logger)
            if code:
                return code
            resources = json.loads(stage.with_suffix('.resources.json').read_text(encoding='utf-8'))
            for name, digest in resources.items():
                resource = Path(name)
                if (not resource.resolve().is_relative_to(args.source.resolve().parent)
                        or resource.stat().st_size > MAX_RESOURCE_BYTES):
                    raise ValueError('document resource changed before publication')
                with resource.open('rb') as handle:
                    data = handle.read(MAX_RESOURCE_BYTES + 1)
                if len(data) > MAX_RESOURCE_BYTES or hashlib.sha256(data).hexdigest() != digest:
                    raise ValueError('document resource changed before publication')
            import pymupdf
            with pymupdf.open(stage) as document:
                if not document.is_pdf or document.needs_pass or document.page_count < 1 or document.is_repaired:
                    raise ValueError('renderer did not produce a complete valid PDF')
            publish_files([(stage, args.output)], protected_sources=[args.source, *map(Path, resources)])
        return 0


if __name__ == '__main__':
    try:
        raise SystemExit(main())
    except Exception as error:
        print(f'render-html: {type(error).__name__}: {error}', file=sys.stderr)
        raise SystemExit(1)
