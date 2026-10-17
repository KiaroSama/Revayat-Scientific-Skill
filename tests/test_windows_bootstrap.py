"""Portable checks of the trusted owner; no Windows calls or child processes."""
import contextlib
import ctypes
import importlib.util
import io
from pathlib import Path
import threading
import unittest
from unittest.mock import patch

PATH = Path(__file__).parent / 'security/windows/bootstrap.py'
spec = importlib.util.spec_from_file_location('security_bootstrap_fixture', PATH)
bootstrap = importlib.util.module_from_spec(spec)
spec.loader.exec_module(bootstrap)


class KernelFixture:
    def __init__(self, timeout=False, bad_utf8=False, cleanup_failure=False):
        self.timeout = timeout
        self.cleanup_failure = cleanup_failure
        self.now = 0
        self.readers = {}
        self.done = []
        self.closed = []
        self.payload = b'\xff' if bad_utf8 else b'WINDOWS_FIXED_PHASE before-stall\n'

    def CreateJobObjectW(self, *_):
        return 10

    def SetInformationJobObject(self, *_):
        return True

    def CreatePipe(self, reader, writer, *_):
        handle = 20 + len(self.readers) * 2
        reader._obj.value, writer._obj.value = handle, handle + 1
        self.readers[handle] = False
        self.done.append(threading.Event())
        return True

    def ReadFile(self, handle, buffer, capacity, count, _):
        if not self.readers[handle]:
            self.readers[handle] = True
            data = self.payload if handle == 20 else b'fixed stderr\n'
            ctypes.memmove(buffer, data, len(data))
            count._obj.value = len(data)
        else:
            count._obj.value = 0
            self.done[(handle - 20) // 2].set()
        return True

    def SetHandleInformation(self, *_):
        return True

    def CreateFileW(self, *_):
        return 30

    def InitializeProcThreadAttributeList(self, _, count, flags, size):
        size._obj.value = 32
        return True

    def UpdateProcThreadAttribute(self, *_):
        return True

    def DeleteProcThreadAttributeList(self, *_):
        if self.cleanup_failure:
            raise RuntimeError('fixed attribute cleanup failure')

    def CreateProcessW(self, *args):
        child = args[-1]._obj
        child.process, child.thread, child.pid, child.tid = 40, 41, 42, 43
        return True

    def AssignProcessToJobObject(self, *_):
        return True

    def ResumeThread(self, *_):
        return 1

    def WaitForSingleObject(self, *_):
        for done in self.done:
            if not done.wait(2):
                raise AssertionError('fixture pipe reader did not finish')
        self.now = 1000 if self.timeout else 0
        return 258 if self.timeout else 0

    def GetExitCodeProcess(self, _, code):
        code._obj.value = 0
        return True

    def TerminateJobObject(self, *_):
        return True

    def QueryInformationJobObject(self, _, kind, accounting, *__):
        accounting._obj.active = 0
        return True

    def CloseHandle(self, handle):
        self.closed.append(handle)
        return True

    def CancelIoEx(self, *_):
        return True


class BootstrapCaptureTest(unittest.TestCase):
    def invoke(self, kernel):
        output, error = io.StringIO(), io.StringIO()
        threads = []
        original = threading.Thread

        def thread(*args, **kwargs):
            instance = original(*args, **kwargs)
            threads.append(instance)
            return instance

        with contextlib.redirect_stdout(output), contextlib.redirect_stderr(error), \
                patch.object(bootstrap.time, 'monotonic', side_effect=lambda: kernel.now), \
                patch.object(bootstrap.threading, 'Thread', side_effect=thread):
            failure = None
            try:
                result = bootstrap.run_owned(kernel, 'fixed-pwsh', Path('fixed-entry'),
                                             Path('fixed-python'), Path('.'), 'a' * 32)
            except BaseException as caught:
                failure, result = caught, None
        self.assertEqual(len(threads), 2)
        self.assertTrue(all(not worker.is_alive() for worker in threads))
        self.assertTrue({10, 20, 22, 40, 41}.issubset(kernel.closed))
        return result, failure, output.getvalue(), error.getvalue()

    def test_timeout_keeps_capture_once_after_reader_cleanup(self):
        result, failure, output, error = self.invoke(KernelFixture(timeout=True))
        self.assertIsNone(result)
        self.assertIsInstance(failure, TimeoutError)
        self.assertEqual(output, 'WINDOWS_FIXED_PHASE before-stall\n')
        self.assertEqual(error, 'fixed stderr\n')

    def test_primary_and_recovery_failures_remain_ordered_in_sanitized_report(self):
        primary = TimeoutError('private primary')
        recovery = OSError('private recovery')
        recovery.winerror = 5
        for outcome in (recovery, 7):
            with self.subTest(outcome=type(outcome).__name__):
                with patch.object(bootstrap, 'run_owned', side_effect=[primary, outcome]) as run:
                    with self.assertRaises(BaseExceptionGroup) as caught:
                        bootstrap.run_with_recovery(lambda: bootstrap.run_owned(),
                                                    lambda _: bootstrap.run_owned(), {'reaped': False})
                self.assertEqual(run.call_count, 2)
                self.assertIs(caught.exception.exceptions[0], primary)
                self.assertEqual(len(caught.exception.exceptions), 2)
                categories = bootstrap.failure_categories(caught.exception)['causes']
                self.assertEqual(categories[0], {'category': 'timeout'})
                self.assertEqual(categories[1], {'category': 'os_error', 'winerror': 5} if outcome is recovery
                                 else {'category': 'unknown_failure'})
                self.assertNotIn('private', str(bootstrap.failure_categories(caught.exception)))

    def test_outer_recovery_requires_reaping_and_handle_cleanup(self):
        for cleanup_failure in (False, True):
            kernel = KernelFixture(cleanup_failure=cleanup_failure)
            qualification = {'reaped': False}
            with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
                try:
                    bootstrap.run_owned(kernel, 'fixed-pwsh', Path('fixed-entry'), Path('fixed-python'),
                                        Path('.'), 'a' * 32, qualification=qualification)
                except BaseExceptionGroup:
                    self.assertTrue(cleanup_failure)
            self.assertEqual(qualification, {'reaped': not cleanup_failure})
        kernel = KernelFixture()
        arguments = []
        original = kernel.CreateProcessW

        def capture(*args):
            arguments.append(args[1].value)
            return original(*args)

        kernel.CreateProcessW = capture
        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            bootstrap.run_owned(kernel, 'fixed-pwsh', Path('fixed-entry'), Path('fixed-python'),
                                Path('.'), 'a' * 32, cleanup=True, outer_reaped=True)
        self.assertIn('-CleanupOnly', arguments[0])
        self.assertIn('-OuterOwnerReaped', arguments[0])

    def test_success_keeps_capture_once(self):
        result, failure, output, error = self.invoke(KernelFixture())
        self.assertEqual(result, 0)
        self.assertIsNone(failure)
        self.assertEqual(output, 'WINDOWS_FIXED_PHASE before-stall\n')
        self.assertEqual(error, 'fixed stderr\n')

    def test_timeout_and_cleanup_failure_preserve_both_and_capture(self):
        _, failure, output, error = self.invoke(KernelFixture(timeout=True, cleanup_failure=True))
        self.assertIsInstance(failure, BaseExceptionGroup)
        self.assertTrue(any(isinstance(item, TimeoutError) for item in failure.exceptions))
        self.assertTrue(any(str(item) == 'fixed attribute cleanup failure' for item in failure.exceptions))
        self.assertEqual(output, 'WINDOWS_FIXED_PHASE before-stall\n')
        self.assertEqual(error, 'fixed stderr\n')

    def test_timeout_and_invalid_utf8_preserve_both_failures(self):
        _, failure, output, _ = self.invoke(KernelFixture(timeout=True, bad_utf8=True))
        self.assertIsInstance(failure, BaseExceptionGroup)
        self.assertTrue(any(isinstance(item, TimeoutError) for item in failure.exceptions))
        self.assertTrue(any(isinstance(item, UnicodeDecodeError) for item in failure.exceptions))
        self.assertEqual(output, '')

    def test_failure_categories_are_bounded_redacted_and_nonzero(self):
        native = OSError('private path and canary')
        native.winerror = 5
        failure = ExceptionGroup('private group', [TimeoutError('secret'), native, ValueError('hidden')])
        evidence = bootstrap.failure_categories(failure)
        self.assertEqual(evidence, {'causes': [{'category': 'timeout'}, {'category': 'os_error', 'winerror': 5},
                                             {'category': 'unknown_failure'}], 'truncated': False})
        output = io.StringIO()
        with patch.object(bootstrap, 'main', side_effect=failure), contextlib.redirect_stderr(output):
            self.assertEqual(bootstrap.entrypoint(), 1)
        self.assertNotIn('private', output.getvalue())
        self.assertNotIn('canary', output.getvalue())
        nested = RuntimeError('hidden')
        for _ in range(8):
            nested = ExceptionGroup('hidden', [nested])
        self.assertTrue(bootstrap.failure_categories(nested)['truncated'])
        wide = ExceptionGroup('hidden', [ValueError('hidden') for _ in range(40)])
        self.assertLessEqual(len(bootstrap.failure_categories(wide)['causes']), 16)
        self.assertTrue(bootstrap.failure_categories(wide)['truncated'])


if __name__ == '__main__':
    unittest.main()
