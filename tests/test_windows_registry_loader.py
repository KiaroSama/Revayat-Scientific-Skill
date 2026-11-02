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
                                  ('Structure', 'c_void_p', 'c_int', 'c_size_t', 'c_longlong', 'c_ulonglong',
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

    def test_scratch_entry_failure_preserves_original_and_bounds_diagnostics(self):
        import ast
        import ctypes
        import ctypes.wintypes
        import subprocess
        source = (ROOT / 'tests/security/windows/KernelProbe.py').read_text(encoding='utf-8')
        tree = ast.parse(source)
        helpers = [node for node in tree.body if isinstance(node, ast.FunctionDef)
                   and node.name in ('enter_scratch', 'failure_wire', 'require')]
        for mode in ('success', 'denied', 'open', 'close', 'query', 'probe', 'close-raise'):
            with self.subTest(mode=mode):
                calls = []
                original = PermissionError(13, 'private-message', 'private-path')

                class Call:
                    def __init__(self, name):
                        self.name = name
                    def __call__(self, *args):
                        calls.append((self.name, args))
                        if self.name == 'open':
                            if mode == 'probe':
                                raise ValueError('private-native-failure')
                            return None if mode in ('denied', 'query') else 17
                        if mode == 'close-raise':
                            raise ValueError('private-close-failure')
                        return mode != 'close'

                def chdir(path):
                    calls.append(('chdir', (path,)))
                    if mode != 'success':
                        raise original

                def cwd():
                    if mode == 'query':
                        raise OSError('private-cwd-failure')
                    return 'fixed-scratch' if mode in ('open', 'close') else 'other'

                namespace = {'__file__': 'fixed-kernel', 'P': ctypes.c_void_p,
                             'w': ctypes.wintypes, 'ctypes': SimpleNamespace(get_last_error=lambda: 5), 'subprocess': subprocess,
                             'K': SimpleNamespace(CreateFileW=Call('open'), CloseHandle=Call('close')),
                             'os': SimpleNamespace(chdir=chdir), 'Path': SimpleNamespace(cwd=cwd)}
                exec(compile(ast.Module(body=helpers, type_ignores=[]), 'fixed-kernel', 'exec'), namespace)
                caught = None
                try:
                    namespace['enter_scratch']('fixed-scratch')
                except OSError as error:
                    caught = error
                self.assertEqual(sum(name == 'chdir' for name, _ in calls), 1)
                if mode == 'success':
                    self.assertIsNone(caught)
                    self.assertEqual(len(calls), 1)
                    continue
                self.assertIs(caught, original)
                expected = {'denied': ('other', '00000005', 'none'), 'open': ('same', 'ok', 'ok'),
                            'close': ('same', 'ok', '00000005'), 'query': ('unknown', '00000005', 'none'),
                            'probe': ('other', 'unknown', 'none'), 'close-raise': ('other', 'ok', 'unknown')}
                self.assertEqual(caught.scratch_evidence, expected[mode])
                opens = [args for name, args in calls if name == 'open']
                self.assertEqual(opens, [('fixed-scratch', 0x100020, 7, None, 3, 0x02000000, None)])
                self.assertEqual(sum(name == 'close' for name, _ in calls), int(mode in ('open', 'close', 'close-raise')))
                wire = namespace['failure_wire'](caught)
                self.assertTrue(wire.endswith(' cwd=%s open=%s close=%s\n' % expected[mode]))
                self.assertLessEqual(len(wire), 128)
                self.assertNotIn('private', wire)
                for invalid in (None, 'private', ('private', 'ok', 'ok'), ('same', '100000000', 'ok'),
                                ('same', 'ok', 'private'), ('same', 'ok'), ['same', 'ok', 'ok']):
                    caught.scratch_evidence = invalid
                    self.assertNotIn(' cwd=', namespace['failure_wire'](caught))

    def test_positive_write_preserves_io_and_localizes_failure(self):
        import ast
        import subprocess
        path = ROOT / 'tests/security/windows/KernelProbe.py'
        source = path.read_text(encoding='utf-8')
        tree = ast.parse(source)
        helpers = [node for node in tree.body if isinstance(node, ast.FunctionDef)
                   and node.name in ('write_positive', 'failure_wire', 'require')]
        operation = next(node for node in helpers if node.name == 'write_positive')
        opened = next(node for node in operation.body if isinstance(node, ast.Assign)
                      and isinstance(node.value, ast.Call) and isinstance(node.value.func, ast.Attribute))
        context = next(node for node in operation.body if isinstance(node, ast.With))
        write = context.body[0]
        run = next(node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name == 'run')
        calls = [node for node in ast.walk(run) if isinstance(node, ast.Call)
                 and isinstance(node.func, ast.Name) and node.func.id == 'write_positive']
        self.assertEqual(len(calls), 1)
        self.assertEqual(ast.get_source_segment(source, calls[0]), 'write_positive(writable)')
        self.assertLess(calls[0].lineno, next(node.lineno for node in ast.walk(run)
                                            if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
                                            and node.func.attr == 'read_bytes'))
        for mode in ('success', 'short', 'open', 'enter', 'write', 'exit', 'write-exit'):
            with self.subTest(mode=mode):
                seen = []
                primary = PermissionError(13, 'private-write', 'private-path')
                cleanup = OSError(5, 'private-close')

                class Stream:
                    def __enter__(self):
                        seen.append('enter')
                        if mode == 'enter':
                            raise primary
                        return self

                    def write(self, data):
                        seen.append('write')
                        self_data = bytes(data)
                        if not isinstance(data, memoryview) or self_data != b'bounded control':
                            raise AssertionError('Unexpected positive data')
                        if mode in ('write', 'write-exit'):
                            raise primary
                        return 1 if mode == 'short' else len(self_data)

                    def __exit__(self, kind, error, trace):
                        seen.append(('exit', error))
                        if mode in ('exit', 'write-exit'):
                            raise cleanup
                        return False

                def open_file(*, mode):
                    self.assertEqual(mode, 'wb')
                    seen.append('open')
                    if current == 'open':
                        raise primary
                    return Stream()

                current = mode
                scope = {'__file__': str(path), 'subprocess': subprocess}
                exec(compile(ast.Module(body=helpers, type_ignores=[]), str(path), 'exec'), scope)
                if mode in ('success', 'short'):
                    result = scope['write_positive'](SimpleNamespace(open=open_file))
                    self.assertEqual(result, 1 if mode == 'short' else len(b'bounded control'))
                    self.assertEqual(seen, ['open', 'enter', 'write', ('exit', None)])
                else:
                    expected = cleanup if mode in ('exit', 'write-exit') else primary
                    try:
                        scope['write_positive'](SimpleNamespace(open=open_file))
                    except OSError as error:
                        self.assertIs(error, expected)
                        line = opened.lineno if mode == 'open' else write.lineno if mode == 'write' else context.lineno
                        frame = scope['failure_wire'](error)
                        self.assertIn('line=' + str(line) + ' kind=os ', frame)
                        self.assertLessEqual(len(frame), 128)
                        self.assertNotIn('private', frame)
                    else:
                        self.fail('Positive write failure was suppressed')
                    if mode == 'write-exit':
                        self.assertIs(cleanup.__context__, primary)
                    expected_seen = ['open'] if mode == 'open' else ['open', 'enter'] if mode == 'enter' else [
                        'open', 'enter', 'write', ('exit', primary if mode.startswith('write') else None)]
                    self.assertEqual(seen, expected_seen)

    def test_preflight_failure_frame_is_fixed_source_and_private(self):
        import ast
        import subprocess
        path = ROOT / 'tests/security/windows/KernelProbe.py'
        source = path.read_text(encoding='utf-8')
        tree = ast.parse(source)
        helpers = [node for node in tree.body if isinstance(node, ast.FunctionDef)
                   and node.name in ('require', 'failure_wire')]
        namespace = {'__file__': str(path), 'subprocess': subprocess}
        exec(compile(ast.Module(body=helpers, type_ignores=[]), str(path), 'exec'), namespace)
        wire = namespace['failure_wire']
        for error, category in ((AssertionError('private-message'), 'assertion'),
                                (PermissionError(13, 'private-message', 'private-path'), 'os'),
                                (subprocess.TimeoutExpired(['private-command'], 5), 'timeout'),
                                (ImportError('private-module'), 'import'),
                                (ValueError('private-value'), 'other')):
            with self.subTest(category=category):
                value = wire(error)
                self.assertRegex(value, r'\AWINDOWS_PREFLIGHT_FAILURE line=0 kind=' + category +
                                 r' errno=(none|[0-9A-F]{8}) winerror=none\n\Z')
                self.assertNotIn('private', value)
                self.assertLess(len(value), 128)
        operation = ast.parse('def fail():\n    require(False, "private-condition")\n')
        exec(compile(operation, str(path), 'exec'), namespace)
        try:
            namespace['fail']()
        except AssertionError as error:
            self.assertEqual(wire(error),
                             'WINDOWS_PREFLIGHT_FAILURE line=2 kind=assertion errno=none winerror=none\n')
        else:
            self.fail('Fixed-source refusal did not execute')
        recursion = ast.parse('def recurse(depth):\n    if depth:\n        return recurse(depth - 1)\n    require(False, "private-condition")\n')
        exec(compile(recursion, str(path), 'exec'), namespace)
        try:
            namespace['recurse'](65)
        except AssertionError as error:
            trace, depth = error.__traceback__, 0
            while trace is not None:
                depth += 1
                trace = trace.tb_next
            self.assertGreater(depth, 64)
            self.assertIn('line=0 kind=assertion', wire(error))
        else:
            self.fail('Deep fixed-source refusal did not execute')
        foreign = {}
        exec(compile('def fail():\n    raise ValueError("private-condition")\n',
                     'private-foreign-file', 'exec'), foreign)
        try:
            foreign['fail']()
        except ValueError as error:
            self.assertIn('line=0 kind=other', wire(error))
        else:
            self.fail('Foreign-source refusal did not execute')
        for code in (None, -1, True, 0, 5, 0xFFFFFFFF, 0x100000000):
            error = OSError('private-native')
            error.errno = error.winerror = code
            expected = format(code, '08X') if type(code) is int and 0 <= code <= 0xFFFFFFFF else 'none'
            self.assertEqual(wire(error), 'WINDOWS_PREFLIGHT_FAILURE line=0 kind=os errno=' + expected +
                             ' winerror=' + expected + '\n')
        main = next(node for node in tree.body if isinstance(node, ast.If) and
                    ast.get_source_segment(source, node.test) == "__name__ == '__main__'")
        output = io.StringIO()
        def fail():
            raise AssertionError('private-final-condition')
        with self.assertRaises(SystemExit) as caught:
            exec(compile(ast.Module(body=[main], type_ignores=[]), str(path), 'exec'),
                 dict(namespace, __name__='__main__', run=fail, sys=SimpleNamespace(stderr=output)))
        self.assertEqual(caught.exception.code, 1)
        self.assertEqual(output.getvalue(),
                         'WINDOWS_PREFLIGHT_FAILURE line=0 kind=assertion errno=none winerror=none\n')

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
        import runpy
        adapter = runpy.run_path(str(ROOT / 'tests/security/windows/RegistryDescendant.py'))
        error = TimeoutError('private-command')
        captured = adapter['CaptureFailure'](error, (), None, first.encode('ascii'))
        def timeout():
            raise captured
        operation = probe['main']
        environment = operation.__globals__
        def load(path):
            self.assertEqual(Path(path).name, 'RegistryDescendant.py')
            return dict(adapter, run=timeout)
        replacements = {'controls': lambda: {}, 'sys': SimpleNamespace(argv=['fixed.py'], executable=str(ROOT / 'python.exe')),
                        'runpy': SimpleNamespace(run_path=load)}
        original = {key: environment[key] for key in replacements}
        try:
            environment.update(replacements)
            with self.assertRaises(probe['Failure']) as caught:
                operation()
        finally:
            environment.update(original)
        self.assertIs(caught.exception.original, captured)
        self.assertIs(captured.original, error)
        self.assertEqual(captured.stderr, b'\0' * len(first.encode('ascii')))
        self.assertIsNone(caught.exception.child_exit)
        wire = probe['failure_wire'](caught.exception, 'primary')
        self.assertEqual(wire, 'REGISTRY_AUTHORITY_FAILURE role=primary child_exit=none errors=import-ctypes:import-ctypes-native,descendant:timeout\n')
        for invalid in ('loader:win32-00000000', 'loader:win32-100000000', 'loader:win32-abcdefab',
                        'loader:loaded', 'loader-release:released', 'loader:loaded,loader-release:win32-00000000'):
            self.assertIsNone(probe['loader_events'](invalid))


if __name__ == '__main__':
    unittest.main()
