"""Generate pure migration fixtures from the retained Python implementation, in CI only."""
import ast
import json
from pathlib import Path
import sys


def generate():
    source = Path(__file__).with_name('RegistryAuthorityProbe.py')
    tree = ast.parse(source.read_text(encoding='utf-8'), filename=str(source))
    selected = {'require_token_fields', 'require_denied', 'require_basic', 'read_identity'}
    functions = [node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name in selected]
    if {node.name for node in functions} != selected:
        raise RuntimeError('Authority oracle functions changed')

    def require(value):
        if not value:
            raise RuntimeError('fixed oracle refusal')

    namespace = {'require': require, 'DENIED': 0xC0000022}
    exec(compile(ast.Module(body=functions, type_ignores=[]), 'authority-oracle', 'exec'), namespace)
    rows = []
    for kind in (0, 1, 2):
        for elevated in (0, 1):
            for filtered in (0, 1):
                args = (kind, elevated, filtered)
                rows.append(('token', args, accepted(namespace['require_token_fields'], args)))
    for status in (0, 1, 0xC0000022, 0xFFFFFFFF):
        for handle in (0, 4):
            args = (status, handle)
            rows.append(('denied', args, accepted(namespace['require_denied'], args)))
    for args in ((0, 56, 0, 0x20019), (1, 56, 0, 0x20019), (0, 55, 0, 0x20019),
                 (0, 57, 0, 0x20019), (0, 56, 1, 0x20019), (0, 56, 0, 0x2001B)):
        rows.append(('basic', args, accepted(namespace['require_basic'], args)))
    for name in ('A', 'Registry', '\U0001F642', '\x00', '\ud800'):
        encoded = name.encode('utf-16-le', errors='surrogatepass')
        data = len(encoded).to_bytes(4, 'little') + encoded
        args = (0, len(data), data, len(encoded))
        rows.append(('identity', (0, len(data), data.hex(), len(encoded)), accepted(namespace['read_identity'], args)))
    for returned, data, expected in ((3, b'\x00' * 4, 0), (4097, b'\x00' * 4, 0),
                                     (6, b'\x04\x00\x00\x00A\x00', 4),
                                     (5, b'\x01\x00\x00\x00A', 1)):
        rows.append(('identity', (0, returned, data.hex(), expected),
                     accepted(namespace['read_identity'], (0, returned, data, expected))))
    for label, args, passed in rows:
        print(label, *(str(value) for value in args), int(passed), sep='\t')
    for role in ('primary', 'descendant'):
        for subkeys, accessible in ((0, 0), (2, 1), (256, 256)):
            controls = next(node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name == 'controls')
            returned = next(node.value for node in ast.walk(controls) if isinstance(node, ast.Return) and isinstance(node.value, ast.Dict))
            record = eval(compile(ast.Expression(returned), 'authority-source-record', 'eval'),
                          {'accessible': accessible, 'names': range(subkeys)})
            record['role'] = role
            wire = json.dumps(record, sort_keys=True, separators=(',', ':'), ensure_ascii=True) + '\n'
            print('wire', role, subkeys, accessible, wire.encode('ascii').hex(), sep='\t')


def accepted(function, args):
    try:
        function(*args)
        return True
    except (RuntimeError, UnicodeError):
        return False


if __name__ == '__main__':
    if sys.argv[1:]:
        raise SystemExit('Authority oracle accepts no arguments')
    generate()
