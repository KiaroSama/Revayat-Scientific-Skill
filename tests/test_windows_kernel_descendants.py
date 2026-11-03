"""Inert checks of fixed ordinary launch roles; no Windows process execution."""
import ast
from pathlib import Path
import runpy
from types import SimpleNamespace
import unittest

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / 'tests/security/windows/KernelDescendants.py'


class KernelDescendantTest(unittest.TestCase):
    def setUp(self):
        self.module = runpy.run_path(str(SOURCE))
        self.scope = self.module['token_child'].__globals__
        self.seen, self.closed = [], []
        self.fail_duplicate = None
        self.fail_close = None
        outer = self

        class Api:
            def standard(self, identifier, kind, own, check):
                check()
                outer.seen.append((identifier, kind))
                handle = own(len(outer.seen) * 4)
                if outer.fail_duplicate == identifier:
                    raise OSError('private duplicate')
                return handle

            def standards(self, handles):
                outer.seen.append(tuple(handles))
                if handles != [4, 8, 12]:
                    raise AssertionError('wrong fixed handles')

            def close(self, handle):
                outer.closed.append(handle)
                if outer.fail_close == handle:
                    raise OSError('private close')

        self.api = Api()
        self.scope['transport']['Native'] = lambda: self.api
        self.scope['sys'] = SimpleNamespace(executable='fixed-python.exe',
            argv=['KernelProbe.py', 'root', 'scratch', 'pwsh', '1', '2', 'profile'])
        self.scope['os'] = SimpleNamespace(environ={'FIXED': 'value'}, getcwd=lambda: 'scratch')
        self.scope['subprocess'] = SimpleNamespace(STARTUPINFO=SimpleNamespace,
            STARTF_USESTDHANDLES=0x100, DETACHED_PROCESS=8)

    def assert_launch(self, arguments, options, handles):
        self.assertEqual(arguments[:5], ['fixed-python.exe', '-I', '-B', '-X', 'utf8'])
        self.assertEqual(options['env'], {'FIXED': 'value'})
        self.assertEqual(options['cwd'], 'scratch')
        self.assertEqual(options['creationflags'], 8)
        self.assertTrue(options['close_fds'])
        for name in ('stdin', 'stdout', 'stderr'):
            self.assertIsNone(options[name])
        startup = options['startupinfo']
        self.assertEqual(startup.dwFlags, 0x100)
        self.assertEqual([startup.hStdInput, startup.hStdOutput, startup.hStdError], handles)
        self.assertEqual(startup.lpAttributeList, {'handle_list': handles})
        self.assertNotIn('capture_output', options)
        self.assertNotIn('shell', options)

    def test_fixed_token_capture_keeps_arguments_current_directory_and_cap(self):
        sentinel = object()
        def capture(api, spawn, clock, limit):
            self.assertIs(api, self.api)
            self.assertEqual(limit, 65535)
            self.scope['subprocess'].Popen = lambda argv, **options: (argv, options)
            argv, options = spawn([4, 8, 12])
            self.assert_launch(argv, options, [4, 8, 12])
            self.assertEqual(argv[5:], [str(SOURCE.with_name('KernelProbe.py')), 'root', 'scratch', 'pwsh',
                                      '1', '2', 'profile', 'token-child'])
            return sentinel
        self.scope['transport']['_run'] = capture
        self.assertIs(self.module['token_child'](), sentinel)

    def test_capture_failure_keeps_original_and_cleanup_but_zeroes_private_stderr(self):
        failure = self.scope['transport']['CaptureFailure'](OSError('original'), [OSError('close')], 7, b'private')
        def capture(*_):
            raise failure
        self.scope['transport']['_run'] = capture
        with self.assertRaises(type(failure)) as caught:
            self.module['token_child']()
        self.assertIs(caught.exception, failure)
        self.assertEqual(failure.stderr, b'\0' * 7)
        self.assertEqual((str(failure.original), str(failure.cleanup[0]), failure.code), ('original', 'close', 7))

    def test_closed_sleep_and_pid_roles_retain_exact_standard_allowlist(self):
        with self.module['Standards']() as standards:
            for role, code in (('wall', 'import time; time.sleep(30)'),
                               ('pid-hold', 'import time; time.sleep(10)'),
                               ('pid-extra', 'raise SystemExit(0)')):
                arguments, options = standards.prepare(role)
                self.assertEqual(arguments, (['fixed-python.exe', '-I', '-B', '-c', code],))
                self.assertEqual(options['startupinfo'].lpAttributeList, {'handle_list': [4, 8, 12]})
                self.assertEqual(options['cwd'], 'scratch')
                self.assertEqual(options['env'], {'FIXED': 'value'})
                self.assertTrue(options['close_fds'])
                self.assertEqual(options['creationflags'], 8)
                self.assertTrue(all(options[name] is None for name in ('stdin', 'stdout', 'stderr')))
            with self.assertRaises(RuntimeError):
                standards.prepare('arbitrary')
        self.assertEqual(self.closed, [4, 8, 12])
        self.assertEqual(self.seen[:3], [(0xFFFFFFF6, 2), (0xFFFFFFF5, 3), (0xFFFFFFF4, 3)])

    def test_partial_duplicates_and_all_close_failures_remain_fatal(self):
        for index, identifier in enumerate((0xFFFFFFF6, 0xFFFFFFF5, 0xFFFFFFF4)):
            self.setUp()
            self.fail_duplicate = identifier
            with self.subTest(identifier=identifier), self.assertRaises(OSError):
                with self.module['Standards']():
                    self.fail('failed preparation cannot launch')
            self.assertEqual(self.closed, [4, 8, 12][:index + 1])
        self.setUp()
        self.fail_close = 4
        original = OSError('original')
        with self.assertRaises(self.scope['transport']['CaptureFailure']) as caught:
            with self.module['Standards']():
                raise original
        self.assertIs(caught.exception.original, original)
        self.assertEqual(len(caught.exception.cleanup), 1)
        self.assertEqual(self.closed, [4, 8, 12])

    def test_extra_pid_denial_catch_contains_only_real_popen(self):
        tree = ast.parse(SOURCE.with_name('KernelProbe.py').read_text(encoding='utf-8'))
        run = next(node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name == 'run')
        expected = next(node for node in ast.walk(run) if isinstance(node, ast.Try) and any(
            isinstance(child, ast.Assign) and any(isinstance(target, ast.Name) and target.id == 'extra'
                                                for target in child.targets) for child in node.body))
        self.assertEqual(len(expected.body), 1)
        self.assertEqual(ast.unparse(expected.body[0].value), 'subprocess.Popen(*extra_launch[0], **extra_launch[1])')
        source = ast.unparse(run)
        self.assertNotIn('subprocess.DEVNULL', source)
        self.assertIn("standards.prepare('pid-extra')", source)
        self.assertIn('children.append(extra)', source)
        self.assertIn('extra.wait(timeout=3)', source)


if __name__ == '__main__':
    unittest.main()
