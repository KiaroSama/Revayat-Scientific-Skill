"""Separate production output options from harmless outer-sandbox observations."""
import csv
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import tempfile
from types import MappingProxyType

SCRIPTS = Path('/target/skills/revayat-scientific/scripts')


def production_output_options(root):
    # Called only by the worker after the image-owned preflight. This imports
    # reviewed code, but never discovers a runtime or launches a nested container.
    original_path = sys.path[:]
    try:
        sys.path.insert(0, str(SCRIPTS))
        spec = importlib.util.spec_from_file_location('security_tex_container', SCRIPTS / 'tex-container.py')
        renderer = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(renderer)
        # Argument-only fixture identity, not an inspected/available toolchain.
        config = MappingProxyType({'base': ('/usr/bin/docker', '--host', 'unix:///var/run/docker.sock'),
                                   'kind': 'docker', 'image': 'sha256:' + '0' * 64})
        arguments = renderer.run_arguments(config, root, 'probe.tex', 'public-output-control')
    finally:
        sys.path[:] = original_path
    mounts = [dict(field.split('=', 1) if '=' in field else (field, '')
                   for field in next(csv.reader([arguments[index + 1]])))
              for index, value in enumerate(arguments) if value == '--mount']
    assert mounts == [
        {'type': 'bind', 'src': str((root / 'input').resolve()), 'dst': '/input', 'readonly': ''},
        {'type': 'bind', 'src': str((root / 'output').resolve()), 'dst': '/output'},
    ], 'production mount arrangement changed; re-evaluate output confinement'
    limits = [arguments[index + 1] for index, value in enumerate(arguments) if value == '--ulimit']
    assert 'fsize=268435456:268435456' in limits, 'production per-file limit changed'
    tmpfs = [arguments[index + 1] for index, value in enumerate(arguments) if value == '--tmpfs']
    assert tmpfs == ['/tmp:rw,noexec,nosuid,nodev,size=268435456'], 'production scratch arrangement changed'
    assert '--read-only' in arguments and '--network=none' in arguments
    assert '--storage-opt' not in arguments, 'production storage options changed; re-evaluate quota'
    assert arguments[arguments.index('--env') + 1] == 'HOME=/tmp/tex-home'
    assert 'TEXMFOUTPUT=/output' in arguments
    return {
        'status': 'unresolved',
        'evidence': 'actual tex-container.run_arguments with immutable argument-only configuration',
        'input': 'read-only bind', 'output': 'writable bind from staging/output',
        'per_file_bytes': 268435456, 'tmpfs_bytes': 268435456, 'tmpfs_destination': '/tmp',
        'output_aggregate_quota': 'not specified by selected output bind/options',
        'runtime_launched': False, 'effective_host_quota': 'not observed',
        'limitation': 'Production /output is not the capped /tmp tmpfs. A per-file fsize limit '
                      'does not bound the sum of output files; host filesystem quota and '
                      'effective production confinement remain unverified.',
    }


def main():
    with tempfile.TemporaryDirectory(prefix='tex output ', dir='/scratch/tmp') as directory:
        root = Path(directory)
        incoming, outgoing = root / 'input', root / 'output'
        incoming.mkdir()
        outgoing.mkdir()
        production = production_output_options(root)
        source = incoming / 'probe.tex'
        source.write_text(r'''\documentclass{article}
\newwrite\probe
\begin{document}
\immediate\openout\probe=public-one.txt
\immediate\write\probe{public harmless first}
\immediate\closeout\probe
\immediate\openout\probe=public-two.txt
\immediate\write\probe{public harmless second}
\immediate\closeout\probe
Ordinary scientific document.
\end{document}
''', encoding='utf-8')
        # Same source/output directory shape and XeLaTeX flags, NOT production
        # mounts or runtime: all writes here remain on the outer /scratch tmpfs.
        child = subprocess.run(['/usr/bin/xelatex', '-no-shell-escape', '-interaction=nonstopmode',
                                '-halt-on-error', '-file-line-error', '-jobname=document',
                                '-output-directory=' + str(outgoing), str(source)],
                               cwd=incoming, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                               stderr=subprocess.STDOUT, timeout=15)
        assert child.returncode == 0, 'harmless XeLaTeX producer failed'
        assert (outgoing / 'document.pdf').stat().st_size > 0
        for name, expected in (('public-one.txt', 'public harmless first'),
                               ('public-two.txt', 'public harmless second')):
            path = outgoing / name
            assert path.read_text(encoding='utf-8').strip() == expected
            assert 0 < path.stat().st_size < 1024, 'permitted output control is not small'
        assert sum(path.stat().st_size for path in outgoing.iterdir()) < 1024 * 1024, 'producer exceeded small control budget'
        # The trusted preflight already tests ENOSPC with reserved blocks. Do not
        # repeat it or attribute its 128 MiB outer quota to the production bind.
        print(json.dumps({'phase': 'tex-output', 'status': 'passed',
                          'checks': ['production-run-arguments-evaluated', 'production-rw-output-bind',
                                     'production-per-file-not-aggregate', 'real-xelatex-no-shell',
                                     'two-permitted-output-files', 'ordinary-pdf'],
                          'outer_scratch': {'quota_evidence': 'trusted preflight, not repeated here',
                                            'producer_storage': 'outer /scratch tmpfs, not production /output'},
                          'production_output': production,
                          'limitation': production['limitation']}))


if __name__ == '__main__':
    main()
