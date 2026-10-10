"""Native Windows 3.11 publication seams, after the trusted containment gate."""
import json
import os
from pathlib import Path
import stat
import subprocess
import sys


def require(condition, message):
    if not condition:
        raise AssertionError(message)


def run():
    require(os.name == 'nt' and sys.version_info[:2] == (3, 11),
            'required native Windows Python 3.11 tier is unavailable')
    root, scratch, powershell = map(Path, sys.argv[1:4])
    import zipfile
    package = scratch / 'case-variant.docx'
    with zipfile.ZipFile(package, 'w') as archive:
        archive.writestr('[Content_Types].xml', '<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"><Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/><Default Extension="xml" ContentType="application/xml"/><Default Extension="html" ContentType="text/html"/><Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/><Override PartName="/word/_rels/document.xml.RELS" ContentType="application/vnd.openxmlformats-package.relationships+xml"/></Types>')
        archive.writestr('_rels/.rels', '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="word/document.xml"/></Relationships>')
        archive.writestr('word/document.xml', '<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships"><w:body><w:p><w:r><w:t>original</w:t></w:r></w:p><w:altChunk r:id="rIdControlled"/></w:body></w:document>')
        archive.writestr('word/_rels/document.xml.RELS', '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rIdControlled" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/aFChunk" Target="chunk.html"/></Relationships>')
        archive.writestr('word/chunk.html', '<html><body>bounded independent OPC control</body></html>')
    consumer = subprocess.run([str(root / 'tests/security/windows/OpcConsumer.exe'), str(package)],
                              stdin=subprocess.DEVNULL, capture_output=True, text=True,
                              encoding='utf-8', timeout=10, creationflags=subprocess.CREATE_NO_WINDOW)
    require(consumer.returncode == 0 and consumer.stdout.strip() == 'OPC_CASE_RELATIONSHIP_RECOGNIZED',
            'existing WindowsBase OPC consumer did not establish case-variant relationship identity')
    print(json.dumps({'phase': 'consumer', 'id': 'WIN-OPC-CASE-IDENTITY', 'status': 'passed'}), flush=True)
    sys.path.insert(0, str(root / 'skills/revayat-scientific/scripts'))
    from publication import publish_files, validate_destination

    work = scratch / 'junction-fixture'
    work.mkdir()
    sentinel = work / 'separate-sentinel'
    sentinel.mkdir()
    original = sentinel / 'article.pdf'
    original.write_bytes(b'approved outside linked output')
    link = work / 'linked-output'
    # The trusted parent prepares a real junction before the reviewed worker starts.
    prepared = scratch / 'prepared-junction'
    require(prepared.is_dir(), 'trusted parent did not prepare the native junction')
    os.rename(prepared, link)
    require(os.lstat(link).st_reparse_tag == stat.IO_REPARSE_TAG_MOUNT_POINT,
            'fixture is not a native NTFS directory junction')
    target = Path(os.readlink(link))
    require(target.resolve() == (scratch / 'junction-target').resolve(),
            'junction fixture target identity changed')
    redirected = target / 'article.pdf'
    redirected.write_bytes(b'approved junction target')
    protected = redirected.read_bytes()
    stage = work / 'stage.pdf'
    stage.write_bytes(b'new staged output')
    destination = link / 'article.pdf'
    results, failures = [], []
    for name, operation in (
            ('WIN-JUNCTION-ADMISSION', lambda: validate_destination(destination)),
            ('WIN-JUNCTION-PUBLICATION', lambda: publish_files([(stage, destination)]))):
        refused = False
        try:
            operation()
        except ValueError as error:
            refused = 'link' in str(error).lower() or 'junction' in str(error).lower()
        except Exception as error:
            failures.append(name + ': unexpected ' + type(error).__name__)
        unchanged = redirected.read_bytes() == protected and stage.exists() and stage.read_bytes() == b'new staged output'
        if not refused or not unchanged:
            failures.append(name + ': linked output accepted or protected bytes changed')
        else:
            results.append(name)
        # Reset only authored scratch fixture state so one demonstrated failure does not mask sibling seams.
        redirected.write_bytes(protected)
        stage.write_bytes(b'new staged output')
    ordinary = work / 'ordinary.pdf'
    try:
        publish_files([(stage, ordinary)])
        require(ordinary.read_bytes() == b'new staged output', 'ordinary publication failed')
        results.append('WIN-ORDINARY-PUBLICATION')
    except Exception as error:
        failures.append('WIN-ORDINARY-PUBLICATION: ' + str(error))

    source = work / 'article.html'
    source.write_text('<!doctype html><html lang="fa" dir="rtl"><body><p>bounded</p></body></html>',
                      encoding='utf-8')
    terms, manifest = work / 'terms.tsv', work / 'manifest.txt'
    terms.write_text('en\tfa\tnote\n', encoding='utf-8')
    manifest.write_text('', encoding='utf-8')
    # A real prepared Chromium path plus real dependency imports enables engine selection;
    # expected linked-output admission stops before linting or any renderer launch.
    command = [str(powershell), '-NoLogo', '-NoProfile', '-NonInteractive', '-File',
               str(root / 'skills/revayat-scientific/scripts/build-pdf.ps1'), str(source),
               'article', '-Engine', 'chromium', '-Terms', str(terms), '-Manifest', str(manifest),
               '-OutputDirectory', str(link)]
    completed = subprocess.run(command, cwd=work, stdin=subprocess.DEVNULL,
                               capture_output=True, text=True, encoding='utf-8', timeout=35,
                               creationflags=subprocess.CREATE_NO_WINDOW)
    diagnostics = completed.stdout + completed.stderr
    require(len(diagnostics.encode('utf-8')) <= 65536, 'adapter diagnostics exceeded bound')
    if (completed.returncode != 0 and 'output path must not contain links or junctions' in diagnostics
            and redirected.read_bytes() == protected and original.read_bytes() == b'approved outside linked output'
            and not (work / 'article.pdf').exists()):
        results.append('WIN-POWERSHELL-LEXICAL')
    else:
        failures.append('WIN-POWERSHELL-LEXICAL: expected destination refusal not observed; exit=' + str(completed.returncode)
                        + ' diagnostic=' + diagnostics[:2000])
    print(json.dumps({'phase': 'native-regressions', 'passed': results, 'failures': failures,
                      'python': sys.version.split()[0]}, sort_keys=True), flush=True)
    require(not failures, '; '.join(failures))


if __name__ == '__main__':
    try:
        run()
    except Exception as error:
        print(json.dumps({'phase': 'native-regressions', 'status': 'failed',
                          'error': str(error)}, sort_keys=True), file=sys.stderr)
        raise SystemExit(1)
