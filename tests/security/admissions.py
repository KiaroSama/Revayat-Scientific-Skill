"""Finite authored admission cases; called only after effective isolation probes."""
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest.mock
import zipfile

TARGET = Path('/target') if sys.platform.startswith('linux') else Path(os.environ['REVAYAT_SECURITY_TARGET'])
SCRIPTS = TARGET / 'skills/revayat-scientific/scripts'


def module(name):
    spec = importlib.util.spec_from_file_location(name.replace('-', '_'), SCRIPTS / (name + '.py'))
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


def expect_refusal(operation, label, diagnostic=None):
    try:
        operation()
    except ValueError as error:
        if diagnostic is not None and diagnostic not in str(error):
            raise AssertionError(label + ': unrelated refusal: ' + str(error)) from error
        return
    raise AssertionError(label + ': unsafe input was accepted')


def package(path, suffix='rels', directory='_rels', restricted=False, external=False):
    c = 'http://schemas.openxmlformats.org/package/2006/content-types'
    p = 'http://schemas.openxmlformats.org/package/2006/relationships'
    w = 'http://schemas.openxmlformats.org/wordprocessingml/2006/main'
    r = 'http://schemas.openxmlformats.org/officeDocument/2006/relationships'
    relation = 'word/' + directory + '/document.xml.' + suffix
    kind = r + ('/aFChunk' if restricted else '/hyperlink')
    mode = ' TargetMode="External"' if external else ''
    members = {
        '[Content_Types].xml': f'<Types xmlns="{c}"><Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/><Default Extension="xml" ContentType="application/xml"/><Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/><Override PartName="/{relation}" ContentType="application/vnd.openxmlformats-package.relationships+xml"/><Override PartName="/word/fragment.html" ContentType="text/html"/></Types>',
        '_rels/.rels': f'<Relationships xmlns="{p}"><Relationship Id="rId1" Type="{r}/officeDocument" Target="word/document.xml"/></Relationships>',
        'word/document.xml': f'<w:document xmlns:w="{w}" xmlns:r="{r}"><w:body><w:p><w:r><w:t>original</w:t></w:r></w:p>' + ('<w:altChunk r:id="rId2"/>' if restricted else '') + '</w:body></w:document>',
        relation: f'<Relationships xmlns="{p}"><Relationship Id="rId2" Type="{kind}" Target="' + ('https://example.invalid/public' if external else 'fragment.html') + f'"{mode}/></Relationships>',
        'word/fragment.html': '<html><body><p>public harmless alternate text</p></body></html>',
    }
    with zipfile.ZipFile(path, 'w') as archive:
        for name, data in members.items():
            archive.writestr(name, data.encode('utf-8'))
    return relation


def docx_cases(work):
    import docx_package
    patches = [{'part': 'word/document.xml', 'index': 0, 'expected': 'original', 'text': 'changed'}]
    outputs = []
    for suffix, directory in (('rels', '_rels'), ('RELS', '_rels'), ('rels', '_RELS'), ('ReLs', '_ReLs')):
        source = work / (suffix + directory + '.docx')
        package(source, suffix, directory, restricted=True)
        original = source.read_bytes()
        destination = work / 'previous.docx'
        destination.write_bytes(b'previous valid sentinel')
        expect_refusal(lambda: docx_package.edit_package(source, destination, patches), 'restricted relationship identity')
        assert source.read_bytes() == original and destination.read_bytes() == b'previous valid sentinel'
        outputs.append('restricted-' + suffix + '-' + directory)
    for external in (False, True):
        source = work / ('ordinary-' + str(external) + '.docx')
        package(source, external=external)
        destination = work / ('edited-' + str(external) + '.docx')
        docx_package.edit_package(source, destination, patches)
        assert docx_package.read_package(destination)[2]['word/document.xml'].find('.//{http://schemas.openxmlformats.org/wordprocessingml/2006/main}t').text == 'changed'
        outputs.append('ordinary-external-' + str(external))
    return outputs


def html_cases(work):
    from html_source import ParsedHTML
    from source_model import Source
    from resource_policy import ResourcePolicy
    from build_guard import document_inputs
    text_order = module('check-pdf-text-order')
    build = module('build-support')
    renderer = module('render-html')

    def render_entry(path, *, rejected):
        output = work / ('render-' + path.stem + '.pdf')
        output.write_bytes(b'previous render sentinel')
        original = path.read_bytes()
        sidecar = output.with_suffix('.resources.json')
        with unittest.mock.patch.object(renderer, 'chromium') as backend:
            try:
                renderer.main([str(path), str(output), '--engine', 'chromium',
                               '--browser', '/unused-admission-control', '--worker'])
            finally:
                assert path.read_bytes() == original, 'render admission changed source'
                assert output.read_bytes() == b'previous render sentinel', 'render admission changed output'
                if rejected:
                    backend.assert_not_called()
                    assert not sidecar.exists(), 'rejected render published a resource sidecar'
            if not rejected:
                backend.assert_called_once()
        sidecar.unlink(missing_ok=True)

    prefix = '<!doctype html><html lang="fa" dir="rtl"><head><meta charset="utf-8"></head><body>'
    suffix = '</body></html>'
    accepted = prefix + '<span>' * 32 + 'متن علمی' + '</span>' * 32 + suffix
    good = work / 'good.html'
    good.write_text(accepted, encoding='utf-8')
    assert ParsedHTML(accepted).text_content()
    assert Source(good).html.text_content()
    assert ResourcePolicy(good).source_bytes == accepted.encode('utf-8')
    assert text_order.source_plain(good)
    def lint(path):
        child = subprocess.run([sys.executable, '-B', str(SCRIPTS / 'check-fa.py'), str(path)],
                               cwd=work, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                               stderr=subprocess.PIPE, timeout=8)
        assert len(child.stdout) + len(child.stderr) <= 65536, 'lint diagnostic bound exceeded'
        return child
    positive = lint(good)
    assert positive.returncode == 0, 'ordinary supported nesting must pass public lint'
    assert document_inputs(good) == [good.resolve()]
    assert build.source_assets(good) == []
    render_entry(good, rejected=False)
    seen, failed = ['ordinary-nesting', 'ordinary-lint', 'ordinary-guard', 'ordinary-assets',
                    'ordinary-render-entry-ordering'], []
    cases = {'depth': prefix + '<span>' * 513 + 'متن علمی' + '</span>' * 513 + suffix,
             'nodes': prefix + '<br>' * 100001 + 'متن علمی' + suffix}
    for label, text in cases.items():
        source = work / (label + '.html')
        source.write_text(text, encoding='utf-8')
        operations = {
            'parser': lambda: ParsedHTML(text),
            'source': lambda: Source(source),
            'guard': lambda: document_inputs(source),
            'assets': lambda: build.source_assets(source),
            'text-order': lambda: text_order.source_plain(source),
            'resource-policy': lambda: ResourcePolicy(source),
            'render-entry': lambda: render_entry(source, rejected=True),
        }
        for name, operation in operations.items():
            case = label + '/' + name
            try:
                expect_refusal(operation, case, diagnostic='HTML work budget')
            except (AssertionError, OSError, ValueError) as error:
                failed.append(case)
                print(json.dumps({'scenario': case, 'status': 'failed', 'reason': str(error)[:256]}), flush=True)
            else:
                seen.append(case)
                print(json.dumps({'scenario': case, 'status': 'passed'}), flush=True)
        child = lint(source)
        case = label + '/lint'
        if child.returncode != 2 or b'HTML work budget' not in child.stderr:
            failed.append(case)
            print(json.dumps({'scenario': case, 'status': 'failed', 'reason': 'missing work-budget refusal'}), flush=True)
        else:
            seen.append(case)
    if failed:
        raise AssertionError('HTML caller regressions failed: ' + ', '.join(failed))
    return seen


def publication_cases(work):
    import publication
    import stat
    destination = work / 'result.pdf'
    candidate = work / 'candidate.pdf'
    candidate.write_bytes(b'valid candidate')
    class Reparse:
        st_mode = stat.S_IFDIR | 0o755
        st_file_attributes = 0x400
    original_lstat = Path.lstat
    # Portable metadata contract is not a real Windows junction observation.
    def observation(path, *args, **kwargs):
        return Reparse() if path == destination.parent else original_lstat(path, *args, **kwargs)
    with unittest.mock.patch.object(Path, 'lstat', observation):
        expect_refusal(lambda: publication.validate_destination(destination), 'reparse metadata')
    publication.publish_files([(candidate, destination)])
    assert destination.read_bytes() == b'valid candidate'
    alias = work / 'alias.pdf'
    os.link(destination, alias)
    expect_refusal(lambda: publication.validate_destination(alias, [destination]), 'protected hardlink')
    return ['portable-reparse-metadata', 'ordinary-publication', 'protected-hardlink']


def main():
    sys.path.insert(0, str(SCRIPTS))
    root = Path(os.environ.get('TMPDIR', tempfile.gettempdir()))
    with tempfile.TemporaryDirectory(prefix='security admissions ', dir=root) as directory:
        work = Path(directory)
        results, failed = {}, []
        for name, scenario in (('docx', docx_cases), ('html', html_cases), ('publication', publication_cases)):
            try:
                results[name] = scenario(work)
            except (AssertionError, OSError, ValueError, RuntimeError) as error:
                failed.append(name)
                results[name] = {'status': 'failed', 'reason': str(error)[:512]}
        print(json.dumps({'phase': 'admissions', 'status': 'failed' if failed else 'passed',
                          'checks': results}, ensure_ascii=True))
        if failed:
            raise AssertionError('admission regressions failed: ' + ', '.join(failed))


if __name__ == '__main__':
    main()
