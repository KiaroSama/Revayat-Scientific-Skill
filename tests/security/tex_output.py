"""Harmless producer observations under an already-proven outer scratch budget."""
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile


def main():
    with tempfile.TemporaryDirectory(prefix='tex output ', dir='/scratch/tmp') as directory:
        root = Path(directory)
        source = root / 'probe.tex'
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
        child = subprocess.run(['/usr/bin/xelatex', '-no-shell-escape', '-interaction=nonstopmode',
                                '-halt-on-error', '-jobname=document', '-output-directory=' + str(root), str(source)],
                               cwd=root, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                               stderr=subprocess.STDOUT, timeout=15)
        assert child.returncode == 0, 'harmless XeLaTeX producer failed'
        assert (root / 'document.pdf').stat().st_size > 0
        assert (root / 'public-one.txt').read_text(encoding='utf-8').strip() == 'public harmless first'
        assert (root / 'public-two.txt').read_text(encoding='utf-8').strip() == 'public harmless second'
        # Probe quota with reserved blocks, not document-controlled amplification or
        # host-volume exhaustion. The complete namespace has a 128 MiB tmpfs cap.
        quota_files = []
        refused = False
        try:
            for index in range(9):
                path = root / ('quota-' + str(index))
                quota_files.append(path)
                with path.open('xb') as handle:
                    try:
                        os.posix_fallocate(handle.fileno(), 0, 16 * 1024 * 1024)
                    except OSError as error:
                        import errno
                        assert error.errno == errno.ENOSPC, 'unexpected aggregate quota error'
                        refused = True
                        break
            assert refused, 'scratch aggregate disk budget was not enforced'
        finally:
            for path in quota_files:
                path.unlink(missing_ok=True)
        print(json.dumps({'phase': 'tex-output', 'status': 'passed',
                          'checks': ['real-xelatex-no-shell', 'two-permitted-output-files',
                                     'ordinary-pdf', 'outer-aggregate-scratch-quota'],
                          'limitation': 'Outer scratch quota does not establish production output-bind quota.'}))


if __name__ == '__main__':
    main()
