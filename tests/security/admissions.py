"""Finite authored admission cases; called only after effective isolation probes."""
import importlib.util
import json
import os
from pathlib import Path
import shutil
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


def expect_refusal(operation, label):
    try:
        operation()
    except ValueError:
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
    from document_context import DocumentContext
    text_order = module('check-pdf-text-order')
    build = module('build-support')
    accepted = '<!doctype html><html lang="fa"><body>' + '<span>' * 32 + 'متن علمی' + '</span>' * 32 + '</body></html>'
    good = work / 'good.html'
    good.write_text(accepted, encoding='utf-8')
    assert ParsedHTML(accepted).text_content()
    assert Source(good).html.text_content()
    assert ResourcePolicy(good).source_bytes == accepted.encode('utf-8')
    assert text_order.source_plain(good)
    seen = []
    cases = {'depth': '<span>' * 513 + 'x' + '</span>' * 513,
             'nodes': '<br>' * 100001}
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
        }
        for name, operation in operations.items():
            expect_refusal(operation, label + '/' + name)
            seen.append(label + '/' + name)
        child = subprocess.run([sys.executable, '-B', str(SCRIPTS / 'check-fa.py'), str(source)],
                               cwd=work, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                               stderr=subprocess.PIPE, timeout=8)
        assert child.returncode != 0 and len(child.stdout) + len(child.stderr) <= 65536
        seen.append(label + '/lint')
    return seen


def publication_cases(work):
    from publication import publish_files, validate_destination
    import publication
    import stat
    destination = work / 'result.pdf'
    candidate = work / 'candidate.pdf'
    candidate.write_bytes(b'valid candidate')
    real = candidate.lstat()
    class Reparse:
        st_mode = stat.S_IFDIR | 0o755
        st_file_attributes = 0x400
    original_lstat = Path.lstat
    # Portable metadata contract is not a real Windows junction observation.
    def observation(path, *args, **kwargs):
        return Reparse() if path == destination.parent else original_lstat(path, *args, **kwargs)
    with unittest.mock.patch.object(Path, 'lstat', observation):
        expect_refusal(lambda: publication.validate_destination(destination), 'reparse metadata')
    publish_files([(candidate, destination)])
    assert destination.read_bytes() == b'valid candidate'
    alias = work / 'alias.pdf'
    os.link(destination, alias)
    expect_refusal(lambda: validate_destination(alias, [destination]), 'protected hardlink')
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
