"""Inert bootstrap/loader contracts; never load a native image."""
import builtins
import io
from pathlib import Path
from types import SimpleNamespace
import unittest

ROOT = Path(__file__).resolve().parents[1]


class RegistryLoaderTest(unittest.TestCase):
    def test_reusable_kernel_helpers_do_not_initialize_network(self):
        import ast
        import ctypes
        import ctypes.wintypes
        source = (ROOT / 'tests/security/windows/KernelProbe.py').read_text(encoding='utf-8')
        tree = ast.parse(source)
        run = next(node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name == 'run')
        imports = [node for node in ast.walk(tree) if isinstance(node, ast.Import)
                   and any(alias.name == 'socket' for alias in node.names)]
        self.assertEqual(len(imports), 1)
        index = run.body.index(imports[0])
        network = run.body[index + 1]
        self.assertIsInstance(network, ast.For)
        self.assertIn('socket.AF_INET6', ast.get_source_segment(source, network))
        self.assertIn("error.winerror == 10013", ast.get_source_segment(source, network))
        self.assertIn('client.settimeout(1)', ast.get_source_segment(source, network))
        attempts = []

        class Declaration:
            def __call__(self, *args, **kwargs):
                raise AssertionError('Native declarations must not execute')

        class Library:
            def __init__(self):
                self.functions = {}
            def __getattr__(self, name):
                return self.functions.setdefault(name, Declaration())

        def ctypes_value(name):
            if name == 'WinDLL':
                return lambda *args, **kwargs: Library()
            return getattr(ctypes, name)

        fake = SimpleNamespace(**{name: ctypes_value(name) for name in
                                  ('Structure', 'c_void_p', 'c_size_t', 'c_longlong', 'c_ulonglong',
                                   'POINTER', 'WinDLL')}, wintypes=ctypes.wintypes)

        def importer(name, *args, **kwargs):
            if name == 'socket':
                attempts.append(name)
                raise ImportError('fixed network initialization refusal')
            if name == 'ctypes':
                return fake
            if name == 'ctypes.wintypes':
                return fake
            return builtins.__import__(name, *args, **kwargs)

        namespace = {'__name__': 'fixed-helper-import',
                     '__builtins__': dict(vars(builtins), __import__=importer)}
        exec(compile(source, 'fixed-kernel-helper', 'exec'), namespace)
        self.assertEqual(attempts, [])
        self.assertTrue(callable(namespace['require_detached_stdio']))
        self.assertTrue(callable(namespace['token_controls']))
        seam = ast.Module(body=[imports[0], network], type_ignores=[])
        with self.assertRaisesRegex(ImportError, 'fixed network initialization refusal'):
            exec(compile(seam, 'fixed-network-import', 'exec'), namespace)
        self.assertEqual(attempts, ['socket'])

    def test_original_receipt_precedes_fixed_loader_effects(self):
        source = (ROOT / 'tests/security/windows/RegistryAuthorityProbe.py').read_text(encoding='utf-8')
        code = compile(source, 'fixed-registry-authority', 'exec')
        for descendant in (False, True):
            for report_failure in ('none', 'short', 'write', 'flush'):
                order = []

                class Report(io.StringIO):
                    def write(self, text):
                        order.append('write')
                        if report_failure == 'write':
                            raise OSError('private-write')
                        if report_failure == 'short':
                            return len(text) - 1
                        return super().write(text)

                    def flush(self):
                        order.append('flush')
                        if report_failure == 'flush':
                            raise OSError('private-flush')

                output = Report()
                system = SimpleNamespace(argv=['fixed.py'] + (['--descendant'] if descendant else []), stderr=output)

                def importer(name, *args, **kwargs):
                    if name == 'sys':
                        return system
                    if name == 'ctypes':
                        raise ImportError('private-original', name='_ctypes', path='private-path')
                    order.append('followup')
                    raise ImportError('private-support')

                namespace = {'__name__': '__main__', '__builtins__': dict(vars(builtins), __import__=importer)}
                with self.subTest(role=descendant, failure=report_failure), self.assertRaises(SystemExit) as caught:
                    exec(code, namespace)
                self.assertEqual(caught.exception.code, 1)
                if report_failure == 'none':
                    self.assertEqual(order, ['write', 'flush', 'followup', 'write', 'flush'])
                    role = 'descendant' if descendant else 'primary'
                    self.assertEqual(output.getvalue(), 'REGISTRY_AUTHORITY_FAILURE role=' + role +
                                     ' child_exit=none errors=import-ctypes:import-ctypes-native\n' +
                                     'REGISTRY_LOADER_FOLLOWUP role=' + role + ' errors=loader:unqualified\n')
                else:
                    self.assertNotIn('followup', order)
                self.assertNotIn('private', output.getvalue())

    def test_fixed_file_binding_and_closed_results_without_native_loading(self):
        import ast
        import ntpath
        source = (ROOT / 'tests/security/windows/RegistryAuthorityProbe.py').read_text(encoding='utf-8')
        functions = ast.Module(body=[node for node in ast.parse(source).body if isinstance(node, ast.FunctionDef)], type_ignores=[])
        code = compile(functions, 'fixed-registry-functions', 'exec')
        path = r'C:\owned space\python\DLLs\_registry_loader.pyd'
        for mode in ('valid', 'load-failed', 'release-failed', 'bool', 'zero', 'range', 'cached', 'alias', 'origin', 'loader-path', 'package'):
            order = []
            system = SimpleNamespace(implementation=SimpleNamespace(name='cpython'), version_info=(3, 11),
                                     maxsize=0x7FFFFFFFFFFFFFFF, flags=SimpleNamespace(isolated=1),
                                     executable=r'C:\owned space\python\python.exe', modules={})
            if mode == 'cached':
                system.modules['_registry_loader'] = None
            if mode == 'alias':
                system.modules['alias'] = SimpleNamespace(__file__=path)

            class Loader:
                def __init__(self, name, selected):
                    self.asserted = (name, selected)
                    self.name, self.path = name, selected if mode != 'loader-path' else 'private-alternate'

                def exec_module(self, module):
                    order.append('exec')

            def specification(name, selected, *, loader):
                self.assertEqual((name, selected), ('_registry_loader', path))
                self.assertEqual(loader.asserted, ('_registry_loader', path))
                return SimpleNamespace(name=name, origin=selected if mode != 'origin' else 'private-alternate',
                                       loader=loader, has_location=True,
                                       submodule_search_locations=[] if mode == 'package' else None)

            def create(spec):
                order.append('create')
                values = (0, 5, 0, 1) if mode == 'load-failed' else (1, 0, 5, 1) if mode == 'release-failed' else (1, 0, 0, 1)
                if mode == 'bool':
                    values = (True, 0, 0, 1)
                if mode == 'zero':
                    values = (0, 0, 0, 1)
                if mode == 'range':
                    values = (0, 0x100000000, 0, 1)
                return SimpleNamespace(__name__='_registry_loader', __file__=path, __spec__=spec,
                                       __loader__=spec.loader, **dict(zip(('loaded', 'load_error', 'release_error', 'version'), values)))

            def importer(name, *args, **kwargs):
                if name == 'importlib.machinery':
                    return SimpleNamespace(ExtensionFileLoader=Loader)
                if name == 'importlib.util':
                    return SimpleNamespace(module_from_spec=create, spec_from_file_location=specification)
                self.assertEqual(name, 'os')
                return SimpleNamespace(path=ntpath)

            namespace = {'sys': system, '__builtins__': dict(vars(builtins), __import__=importer)}
            exec(code, namespace)
            with self.subTest(mode=mode):
                if mode in ('valid', 'load-failed', 'release-failed'):
                    expected = {'valid': 'loader:loaded,loader-release:released', 'load-failed': 'loader:win32-00000005',
                                'release-failed': 'loader:loaded,loader-release:win32-00000005'}[mode]
                    self.assertEqual(namespace['fixed_loader_followup'](), expected)
                else:
                    with self.assertRaises(RuntimeError):
                        namespace['fixed_loader_followup']()
                self.assertEqual(order, [] if mode in ('cached', 'alias', 'origin', 'loader-path', 'package') else ['create', 'exec'])

    def test_first_receipt_survives_unqualified_tail_and_child_timeout(self):
        import runpy
        import subprocess
        probe = runpy.run_path(str(ROOT / 'tests/security/windows/RegistryAuthorityProbe.py'))
        first = 'REGISTRY_AUTHORITY_FAILURE role=descendant child_exit=none errors=import-ctypes:import-ctypes-native\n'
        expected = (('import-ctypes', 'import-ctypes-native'),)
        self.assertEqual(probe['bootstrap_evidence'](first, 'descendant'), expected)
        for tail in ('private', 'x' * 513, '\ufffd', 'REGISTRY_LOADER_FOLLOWUP role=descendant errors=loader:win32-00000000\n',
                     'REGISTRY_LOADER_FOLLOWUP role=primary errors=loader:win32-00000005\n'):
            self.assertEqual(probe['bootstrap_evidence'](first + tail, 'descendant'), expected + (('loader', 'unqualified'),))
        self.assertEqual(probe['bootstrap_evidence'](first.encode('ascii') + b'\xff', 'descendant'), expected + (('loader', 'unqualified'),))
        self.assertIsNone(probe['bootstrap_evidence'](first.rstrip('\n'), 'descendant'))
        tail = 'REGISTRY_LOADER_FOLLOWUP role=descendant errors=loader:loaded,loader-release:win32-FFFFFFFF\n'
        child = subprocess.CompletedProcess([], 0xC0000022, '', first + tail)
        with self.assertRaises(probe['Failure']) as caught:
            probe['descendant_result'](child)
        self.assertEqual(caught.exception.child_exit, 0xC0000022)
        self.assertEqual(caught.exception.events, expected + (('loader', 'loaded'), ('loader-release', 'win32-FFFFFFFF'), ('descendant', 'transport')))
        self.assertIn('loader-release:win32-FFFFFFFF', probe['failure_wire'](caught.exception, 'primary'))
        for suffix, extra in (('', ()), (tail, (('loader', 'loaded'), ('loader-release', 'win32-FFFFFFFF'))),
                              ('private-malformed', (('loader', 'unqualified'),))):
            reports = []
            child = subprocess.CompletedProcess([], 0, 'private-output', first + suffix)
            operation = lambda: probe['complete_descendant'](child, {'role': 'primary'}, io.StringIO())
            self.assertEqual(probe['entry'](operation, reports.append, 'primary'), 1)
            expected_events = expected + extra + (('descendant', 'transport'),)
            expected_wire = ('REGISTRY_AUTHORITY_FAILURE role=primary child_exit=00000000 errors=' +
                             ','.join(phase + ':' + kind for phase, kind in expected_events) + '\n')
            self.assertEqual(reports, [expected_wire])
            self.assertNotIn('private', reports[0])
        error = subprocess.TimeoutExpired('private-command', 5, stderr=first.encode('ascii'))
        def timeout(*args, **kwargs):
            self.assertEqual(kwargs['timeout'], 5)
            self.assertTrue(kwargs['close_fds'])
            raise error
        operation = probe['main']
        environment = operation.__globals__
        replacements = {'controls': lambda: {}, 'sys': SimpleNamespace(argv=['fixed.py'], executable=str(ROOT / 'python.exe')),
                        'subprocess': SimpleNamespace(run=timeout, TimeoutExpired=subprocess.TimeoutExpired,
                                                      DEVNULL=subprocess.DEVNULL, DETACHED_PROCESS=8, CREATE_NO_WINDOW=0x08000000)}
        original = {key: environment[key] for key in replacements}
        try:
            environment.update(replacements)
            with self.assertRaises(probe['Failure']) as caught:
                operation()
        finally:
            environment.update(original)
        self.assertIs(caught.exception.original, error)
        self.assertIsNone(caught.exception.child_exit)
        wire = probe['failure_wire'](caught.exception, 'primary')
        self.assertEqual(wire, 'REGISTRY_AUTHORITY_FAILURE role=primary child_exit=none errors=import-ctypes:import-ctypes-native,descendant:timeout\n')
        for invalid in ('loader:win32-00000000', 'loader:win32-100000000', 'loader:win32-abcdefab',
                        'loader:loaded', 'loader-release:released', 'loader:loaded,loader-release:win32-00000000'):
            self.assertIsNone(probe['loader_events'](invalid))


if __name__ == '__main__':
    unittest.main()
