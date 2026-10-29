"""Inert checks of the fixed Python descendant transport; no native execution."""
from pathlib import Path
import runpy
from types import SimpleNamespace
import unittest

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / 'tests/security/windows/RegistryDescendant.py'


class DescendantTransportTest(unittest.TestCase):
    def setUp(self):
        self.module = runpy.run_path(str(SOURCE))
        self.scope = self.module['_run'].__globals__

    def fixture(self, fault=None, output=b'child\n', errors=b'', code=0, cleanup_faults=()):
        seen, closed = [], []
        clock = [0.0]
        payload = {1: bytearray(output), 3: bytearray(errors)}
        state = {'waits': 0, 'signaled': False}

        class ProcessHandle(int):
            def Close(self):
                seen.append('process-close')
                if 'process-close' in cleanup_faults:
                    raise OSError('private-process-close')

        child = SimpleNamespace(_handle=ProcessHandle(6), _child_created=True, returncode=None)

        def fail(label):
            seen.append(label)
            if fault == label:
                raise OSError('private-' + label)

        class Api:
            def pair(self, role, own, check):
                check()
                base = 1 if role == 'output' else 3
                own(base)
                fail(role + '-pair')
                own(base + 1)
                return base, base + 1

            def input(self, own, check):
                check()
                own(5)
                fail('input')
                return 5

            def standards(self, handles):
                fail('standards')
                if handles != [5, 2, 4]:
                    raise AssertionError('wrong standard handles')

            def close(self, handle):
                closed.append(handle)
                seen.append('close-' + str(handle))
                if 'close-' + str(handle) in cleanup_faults:
                    raise OSError('private-close')

            def peek(self, handle):
                fail('peek-' + str(handle))
                if payload[handle]:
                    return len(payload[handle])
                return None if state['signaled'] else 0

            def read(self, handle, capacity):
                fail('read-' + str(handle))
                data = bytes(payload[handle][:capacity])
                del payload[handle][:capacity]
                return data

            def wait(self, handle, milliseconds):
                seen.append('wait')
                state['waits'] += 1
                if 'wait' in cleanup_faults:
                    raise OSError('private-wait')
                if fault == 'timeout':
                    clock[0] += 1
                    return False
                state['signaled'] = True
                return True

            def exit(self, handle):
                fail('exit')
                return code

            def kill(self, handle):
                seen.append('kill')
                if 'kill' in cleanup_faults:
                    raise OSError('private-kill')
                state['signaled'] = True

        def spawn(handles):
            fail('spawn')
            self.assertEqual(handles, [5, 2, 4])
            return child

        return Api(), spawn, lambda: clock[0], seen, closed, child, state

    def test_exact_standard_handles_and_observed_exit_including_259(self):
        for code in (0, 7, 259, 0xFFFFFFFF):
            api, spawn, clock, seen, closed, child, _ = self.fixture(code=code)
            result = self.module['_run'](api, spawn, clock)
            self.assertEqual((result.returncode, result.stdout, result.stderr), (code, 'child\n', ''))
            self.assertEqual(sorted(closed), [1, 2, 3, 4, 5])
            self.assertEqual(len(closed), len(set(closed)))
            self.assertLess(seen.index('spawn'), seen.index('close-2'))
            self.assertEqual(seen.count('process-close'), 1)
            self.assertFalse(child._child_created)
            self.assertEqual(child.returncode, code)

    def test_each_acquisition_failure_closes_only_obtained_owners(self):
        for fault, expected in (('output-pair', [1]), ('error-pair', [1, 2, 3]),
                                ('input', [1, 2, 3, 4, 5]), ('standards', [1, 2, 3, 4, 5]),
                                ('spawn', [1, 2, 3, 4, 5])):
            api, spawn, clock, seen, closed, _, _ = self.fixture(fault=fault)
            with self.subTest(fault=fault), self.assertRaises(self.module['CaptureFailure']) as caught:
                self.module['_run'](api, spawn, clock)
            self.assertEqual(sorted(closed), expected)
            self.assertIsNone(caught.exception.code)
            self.assertNotIn('process-close', seen)
            self.assertIn('private-' + fault, str(caught.exception.original))
            self.assertNotIn('private', str(caught.exception))

    def test_exact_caps_allow_live_empty_peek_but_refuse_overflow_and_missing_eof(self):
        api, spawn, clock, seen, _, _, _ = self.fixture(output=b'x' * 1024, errors=b'y' * 512)
        wait = api.wait
        first = [True]

        def delayed(handle, milliseconds):
            if first[0]:
                first[0] = False
                seen.append('live-empty')
                return False
            return wait(handle, milliseconds)

        api.wait = delayed
        result = self.module['_run'](api, spawn, clock)
        self.assertEqual((len(result.stdout), len(result.stderr)), (1024, 512))
        self.assertIn('live-empty', seen)
        for stream in ('output', 'errors'):
            args = {stream: b'x' * (1025 if stream == 'output' else 513)}
            api, spawn, clock, _, closed, _, _ = self.fixture(**args)
            with self.subTest(stream=stream), self.assertRaises(self.module['CaptureFailure']):
                self.module['_run'](api, spawn, clock)
            self.assertEqual(sorted(closed), [1, 2, 3, 4, 5])
        api, spawn, clock, _, _, _, _ = self.fixture()
        peek = api.peek
        api.peek = lambda handle: 0 if not peek(handle) else peek(handle)
        with self.assertRaises(self.module['CaptureFailure']) as caught:
            self.module['_run'](api, spawn, clock)
        self.assertEqual(caught.exception.code, 0)

    def test_invalid_read_and_cleanup_faults_are_fatal_and_exhaustive(self):
        for invalid in (b'', b'x' * 1025):
            api, spawn, clock, _, closed, child, _ = self.fixture()
            api.read = lambda *_: invalid
            with self.subTest(length=len(invalid)), self.assertRaises(self.module['CaptureFailure']):
                self.module['_run'](api, spawn, clock)
            self.assertEqual(sorted(closed), [1, 2, 3, 4, 5])
            self.assertFalse(child._child_created)
        faults = ('close-2', 'close-3', 'kill', 'wait', 'process-close')
        api, spawn, clock, seen, closed, child, _ = self.fixture(cleanup_faults=faults)
        with self.assertRaises(self.module['CaptureFailure']) as caught:
            self.module['_run'](api, spawn, clock)
        self.assertEqual(str(caught.exception.original), 'private-close')
        self.assertEqual(len(caught.exception.cleanup), 4)
        self.assertEqual(sorted(closed), [1, 2, 3, 4, 5])
        self.assertIn('kill', seen)
        self.assertIn('wait', seen)
        self.assertFalse(child._child_created)
        self.assertEqual(seen.count('process-close'), 1)
        for stage in ('peek-1', 'peek-3', 'read-1', 'read-3', 'exit'):
            api, spawn, clock, seen, closed, child, _ = self.fixture(fault=stage, errors=b'error')
            with self.subTest(stage=stage), self.assertRaises(self.module['CaptureFailure']):
                self.module['_run'](api, spawn, clock)
            self.assertEqual(sorted(closed), [1, 2, 3, 4, 5])
            self.assertFalse(child._child_created)

    def test_cleanup_overrun_is_fatal_after_every_owner_is_attempted(self):
        for selected in ('reader', 'process'):
            api, spawn, _, seen, closed, child, _ = self.fixture(code=259)
            now = [0.0]
            close = api.close
            process_close = child._handle.Close

            def slow_close(handle):
                close(handle)
                if selected == 'reader' and handle == 1:
                    now[0] += 3

            class SlowHandle(int):
                def Close(self):
                    process_close()
                    if selected == 'process':
                        now[0] += 3

            api.close = slow_close
            child._handle = SlowHandle(6)
            with self.subTest(selected=selected), self.assertRaises(self.module['CaptureFailure']) as caught:
                self.module['_run'](api, spawn, lambda: now[0])
            self.assertEqual(caught.exception.code, 259)
            self.assertTrue(any(isinstance(error, TimeoutError) for error in caught.exception.cleanup))
            self.assertEqual(sorted(closed), [1, 2, 3, 4, 5])
            self.assertEqual(seen.count('process-close'), 1)
            self.assertFalse(child._child_created)

    def test_regular_child_failure_survives_later_transport_and_cleanup_faults(self):
        probe = runpy.run_path(str(SOURCE.with_name('RegistryAuthorityProbe.py')))
        scope = probe['main'].__globals__
        for phase in ('ti-admin', 'tf-priv-value'):
            receipt = ('REGISTRY_AUTHORITY_FAILURE role=descendant child_exit=none errors=' + phase + ':control\n').encode('ascii')
            for operation in (None, OSError('private-transport')):
                captured = self.module['CaptureFailure'](operation, [OSError('private-close')], 7, receipt)
                def refused():
                    raise captured
                scope['controls'] = lambda: {}
                scope['sys'] = SimpleNamespace(argv=['fixed.py'])
                scope['runpy'] = SimpleNamespace(run_path=lambda _: dict(self.module, run=refused))
                with self.subTest(phase=phase, operation=operation), self.assertRaises(probe['Failure']) as caught:
                    probe['main']()
                self.assertEqual(caught.exception.child_exit, 7)
                events = caught.exception.events
                self.assertEqual(events[:2], (('descendant', 'transport'), (phase, 'control')))
                self.assertEqual(events[-1], ('close', 'cleanup'))
                if operation is not None:
                    self.assertEqual(events[2], ('descendant', 'native'))
                self.assertNotIn('private', probe['failure_wire'](caught.exception, 'primary'))
                self.assertEqual(captured.stderr, b'\0' * len(receipt))

    def test_natural_exit_survives_decode_eof_and_close_failures(self):
        for fault in ('decode', 'eof', 'close'):
            api, spawn, clock, _, _, child, state = self.fixture(
                output=b'\xff' if fault == 'decode' else b'child\n', code=259,
                cleanup_faults=('process-close',) if fault == 'close' else ())
            peek = api.peek
            if fault == 'eof':
                api.peek = lambda h: 0 if state['signaled'] else peek(h)
            with self.subTest(fault=fault), self.assertRaises(self.module['CaptureFailure']) as caught:
                self.module['_run'](api, spawn, clock)
            self.assertEqual(caught.exception.code, 259)
            self.assertFalse(child._child_created)

    def test_timeout_retains_bounded_bootstrap_before_exhaustive_cleanup(self):
        receipt = b'REGISTRY_AUTHORITY_FAILURE role=descendant child_exit=none errors=import-ctypes:import-ctypes-native\n'
        api, spawn, clock, seen, closed, child, _ = self.fixture(fault='timeout', errors=receipt)
        with self.assertRaises(self.module['CaptureFailure']) as caught:
            self.module['_run'](api, spawn, clock)
        self.assertIsInstance(caught.exception.original, TimeoutError)
        self.assertEqual(caught.exception.stderr, receipt)
        self.assertIsNone(caught.exception.code)
        self.assertEqual(sorted(closed), [1, 2, 3, 4, 5])
        self.assertIn('kill', seen)
        self.assertFalse(child._child_created)

    def test_actual_native_adapter_owns_outputs_before_failures(self):
        import ctypes
        for selected in ('none', 'server', 'client', 'connect', 'endpoint-query', 'endpoint', 'noninherit', 'duplicate'):
            seen, owners, private_buffers = [], [], []
            error = [535]

            def server(path, access, mode, instances, outgoing, incoming, timeout, security):
                seen.append('server')
                self.assertTrue(path.value.startswith('\\\\.\\pipe\\LOCAL\\RegistryAuthority-'))
                self.assertEqual((access, mode, instances, outgoing, incoming, timeout), (0x80001, 9, 1, 4096, 4096, 0))
                self.assertEqual(security._obj.inherit, 0)
                private_buffers.append(path)
                return ctypes.c_void_p(-1).value if selected == 'server' else 8

            def client(path, access, share, security, disposition, flags, template):
                seen.append('client')
                self.assertEqual((access, share, disposition, flags, template), (0x40000000, 0, 3, 0x100000, None))
                self.assertEqual(security._obj.inherit, 1)
                return ctypes.c_void_p(-1).value if selected == 'client' else 12

            def connect(handle, overlapped):
                seen.append('connect')
                error[0] = 5 if selected == 'connect' else 535
                return 0

            def endpoint(handle, pid):
                seen.append('endpoint-query')
                pid._obj.value = 8 if selected == 'endpoint' else 7
                return selected != 'endpoint-query'

            def noninherit(handle, mask, flags):
                seen.append('noninherit')
                self.assertEqual((handle, mask, flags), (8, 1, 0))
                return selected != 'noninherit'

            def duplicate(source_process, source, target_process, target, access, inherit, options):
                seen.append('duplicate')
                self.assertEqual((source_process, source, target_process, access, inherit, options), (99, 4, 99, 0, True, 2))
                target._obj.value = 16
                return selected != 'duplicate'

            def random(provider, buffer, length, flags):
                self.assertEqual((provider, length, flags), (None, 16, 2))
                for index in range(16):
                    buffer[index] = 0xAB
                private_buffers.append(buffer)
                return 0

            self.scope['ctypes'] = SimpleNamespace(**dict(vars(ctypes), get_last_error=lambda: error[0],
                                                         WinError=lambda code: OSError('private-native-' + str(code))))
            native = object.__new__(self.module['Native'])
            native.b = SimpleNamespace(BCryptGenRandom=random)
            native.k = SimpleNamespace(CreateNamedPipeW=server, CreateFileW=client, ConnectNamedPipe=connect,
                                       GetNamedPipeClientProcessId=endpoint, GetCurrentProcessId=lambda: 7,
                                       SetHandleInformation=noninherit, GetStdHandle=lambda _: 4,
                                       GetFileType=lambda _: 2, GetCurrentProcess=lambda: 99, DuplicateHandle=duplicate)
            def own(handle):
                if native.valid(handle):
                    owners.append(handle)
                return handle
            with self.subTest(selected=selected):
                if selected == 'duplicate':
                    with self.assertRaises(OSError):
                        native.input(own, lambda: None)
                    self.assertEqual(owners, [16])
                elif selected == 'none':
                    self.assertEqual(native.pair('output', own, lambda: None), (8, 12))
                    self.assertEqual(native.input(own, lambda: None), 16)
                    self.assertEqual(owners, [8, 12, 16])
                else:
                    with self.assertRaises((OSError, RuntimeError)):
                        native.pair('error', own, lambda: None)
                    self.assertEqual(owners, [] if selected == 'server' else [8] if selected == 'client' else [8, 12])
                for buffer in private_buffers:
                    self.assertEqual(ctypes.string_at(ctypes.addressof(buffer), ctypes.sizeof(buffer)), b'\0' * ctypes.sizeof(buffer))
                self.assertNotIn(4, owners)
                self.assertNotIn(99, owners)
        self.scope['ctypes'] = ctypes

    def test_actual_spawn_has_no_implicit_pipe_or_nul_route(self):
        seen = []
        sentinel = object()

        def popen(argv, **kwargs):
            seen.append((argv, kwargs))
            return sentinel

        self.scope['subprocess'] = SimpleNamespace(
            STARTUPINFO=lambda **kwargs: SimpleNamespace(**kwargs), Popen=popen,
            STARTF_USESTDHANDLES=0x100, DETACHED_PROCESS=8, CREATE_NO_WINDOW=0x08000000)
        self.scope['sys'] = SimpleNamespace(executable=str(ROOT / 'python.exe'))
        self.scope['os'] = SimpleNamespace(environ={'FIXED': 'value'})
        self.assertIs(self.module['_spawn']([5, 2, 4]), sentinel)
        argv, kwargs = seen[0]
        self.assertEqual(argv[1:5], ['-I', '-B', '-X', 'utf8'])
        self.assertEqual(argv[-1], '--descendant')
        self.assertEqual(Path(argv[-2]).name, 'RegistryAuthorityProbe.py')
        self.assertTrue(kwargs['close_fds'])
        for name in ('stdin', 'stdout', 'stderr'):
            self.assertIsNone(kwargs[name])
        startup = kwargs['startupinfo']
        self.assertEqual(startup.dwFlags, 0x100)
        self.assertEqual([startup.hStdInput, startup.hStdOutput, startup.hStdError], [5, 2, 4])
        self.assertEqual(startup.lpAttributeList, {'handle_list': [5, 2, 4]})
        self.assertEqual(kwargs['env'], {'FIXED': 'value'})
        self.assertEqual(kwargs['creationflags'], 0x08000008)
        self.assertNotIn('capture_output', kwargs)
        self.assertNotIn('shell', kwargs)


if __name__ == '__main__':
    unittest.main()
