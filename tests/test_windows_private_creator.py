"""Inert checks of the fixed private-file acquisition and bound cleanup."""
import ast
import ctypes
from pathlib import Path
import runpy
from types import SimpleNamespace
import unittest
from unittest.mock import Mock

WINDOWS = Path(__file__).resolve().parent / 'security/windows'


class NativeCall:
    def __init__(self, call):
        self.call = call

    def __call__(self, *arguments):
        return self.call(*arguments)


class PrivateCreatorTest(unittest.TestCase):
    def fixture(self, fault=None, close_faults=(), root_name='\\Device\\HarddiskVolume12\\'):
        events, closed, creates = [], [], []
        scope = runpy.run_path(str(WINDOWS / 'PrivateCreator.py'))
        invalid = ctypes.c_void_p(-1).value
        current_error = [5]
        identity = (11, bytes(range(16)))
        security = object()
        scratch = Path('E:/')
        names = {8: root_name, 9: root_name + 'private-creator'}
        for handle in (12, 16, 20, 24):
            names[handle] = root_name + 'private-creator\\authority-protected'

        def create(path, access, share, descriptor, disposition, flags, template):
            creates.append((path, access, share, descriptor, disposition, flags, template))
            role = ({str(scratch): 'root', str(scratch / 'private-creator'): 'parent'}.get(path, 'pin')
                    if access == 0x80 else {0xC0000000: 'create', 0x10080: 'delete'}[access])
            events.append(role)
            if fault == role:
                current_error[0] = 5
                return invalid
            return {'root': 8, 'parent': 9, 'create': 12, 'pin': 20, 'delete': 24}[role]

        def reopen(*arguments):
            events.append('reopen')
            self.assertEqual(arguments, (12, 0xC00C0000, 3, 0))
            return invalid if fault == 'reopen' else 16

        def info(handle, kind, output, size):
            events.append(('info', handle, kind))
            if fault == 'query' and handle == 16:
                return 0
            if kind == 18:
                self.assertEqual(size, 24)
                output._obj.volume = identity[0] + (1 if (fault == 'volume' and handle == 16 or
                                                        fault == 'parent-volume' and handle == 9) else 0)
                output._obj.identifier[:] = identity[1]
                if fault in ('identity', 'cleanup-identity') and handle == (16 if fault == 'identity' else 24):
                    output._obj.identifier[0] ^= 1
            else:
                self.assertEqual((kind, size), (9, 8))
                output._obj.attributes = 0x10 if handle in (8, 9) else 0x80
                output._obj.tag = 0
                if fault == 'reparse' and handle == 16 or fault == 'parent-reparse' and handle == 9:
                    output._obj.attributes |= 0x400
                    output._obj.tag = 0xA000000C
            return 1

        def name(handle, output, capacity, flags):
            if (capacity, flags) != (512, 2):
                raise RuntimeError('unexpected fixed name-query contract')
            events.append(('name', handle, flags))
            value = names[handle] + ('-foreign' if (fault == 'name' and handle == 16 or
                                                   fault == 'parent-name' and handle == 9) else '')
            if fault == 'different-device' and handle == 16:
                value = '\\Device\\HarddiskVolume13\\authority-protected'
            output.value = value
            if fault in ('long-name', 'zero-name') and handle == 16 or fault in ('root-long', 'root-zero') and handle == 8:
                return 0 if fault in ('zero-name', 'root-zero') else 512
            return len(value)

        def query(handle, kind, output, capacity, returned):
            self.assertEqual((kind, capacity), (0, 56))
            returned._obj.value = 56
            output[0] = 2 if fault == 'inherit' and handle == 16 else 0
            output[1] = (0x12019F if handle == 12 else 0x1E019F)
            if fault == 'grant' and handle == 16:
                output[1] |= 0x10000
            if fault == 'basic-length' and handle == 16:
                returned._obj.value = 55
            return -1073741820 if fault == 'basic-status' and handle == 16 else 0

        def close(handle):
            events.append(('close', handle))
            closed.append(handle)
            return handle not in close_faults

        def attributes(_path):
            events.append('absent')
            current_error[0] = 3 if fault == 'absence' else 2
            return 0x80 if fault == 'collision' else 0xFFFFFFFF

        def dispose(handle, kind, output, size):
            events.append('dispose')
            self.assertEqual((handle, kind, output._obj.value, size), (24, 4, 1, 1))
            return fault != 'dispose'

        kernel = SimpleNamespace(**{key: NativeCall(value) for key, value in {
            'CreateFileW': create, 'ReOpenFile': reopen, 'GetFileInformationByHandleEx': info,
            'GetFinalPathNameByHandleW': name, 'GetFileType': lambda _handle: 1,
            'CloseHandle': close, 'GetFileAttributesW': attributes,
            'SetFileInformationByHandle': dispose}.items()})
        def require(condition, message):
            if not condition:
                raise AssertionError(message)
        scope.update(K=kernel, require=require, prepare=lambda: SimpleNamespace(NtQueryObject=query))
        scope['ctypes'] = SimpleNamespace(**dict(vars(ctypes), get_last_error=lambda: current_error[0]))
        # runpy returns a copy; functions retain their own shared global dictionary.
        actual = scope['PrivateFile'].__init__.__globals__
        actual.update(scope)
        return scope, scratch, security, events, closed, creates

    def test_exact_control_request_and_bound_cleanup(self):
        scope, scratch, security, events, closed, creates = self.fixture()
        with scope['PrivateFile'](scratch, security) as fixture:
            fixture.create()
            self.assertEqual(fixture.original, 12)
            self.assertNotIn(('info', 12, 9), events)
            fixture.bind_original()
            fixture.reopen()
            self.assertEqual(fixture.qualify(), 16)
            events.append('controls')
        self.assertEqual(closed, [12, 16, 24, 20, 9, 8])
        self.assertEqual([call[1:] for call in creates], [
            (0x80, 7, None, 3, 0x02200000, None),
            (0x80, 3, None, 3, 0x02200000, None),
            (0xC0000000, 3, security, 1, 0x80, None),
            (0x80, 7, None, 3, 0x00200000, None),
            (0x10080, 3, None, 3, 0x00200000, None)])
        self.assertLess(events.index(('close', 16)), events.index('delete'))
        self.assertLess(events.index('controls'), events.index('dispose'))
        self.assertEqual(events[-1], 'absent')

    def test_acquisition_and_qualification_failures_never_reach_controls(self):
        for fault in ('root', 'parent', 'parent-volume', 'parent-name', 'parent-reparse', 'create', 'pin', 'reopen', 'query', 'volume', 'identity',
                      'reparse', 'name', 'long-name', 'inherit', 'grant', 'basic-length',
                      'basic-status', 'collision', 'absence', 'different-device', 'zero-name', 'root-long', 'root-zero'):
            with self.subTest(fault=fault):
                scope, scratch, security, events, closed, _ = self.fixture(fault)
                reached = Mock()
                with self.assertRaises((OSError, AssertionError, ExceptionGroup)):
                    with scope['PrivateFile'](scratch, security) as fixture:
                        fixture.create()
                        fixture.bind_original()
                        fixture.reopen()
                        fixture.qualify()
                        reached()
                reached.assert_not_called()
                self.assertEqual(len(closed), len(set(closed)))
                if fault in ('collision', 'absence', 'create', 'pin'):
                    self.assertNotIn('dispose', events)
                if fault == 'reopen':
                    self.assertIn('dispose', events)
                    self.assertNotIn(16, closed)

    def test_creation_and_binding_fail_at_distinct_boundaries(self):
        for fault, expected_stage in (('create', 'create'), ('pin', 'bind')):
            scope, scratch, security, events, closed, _ = self.fixture(fault)
            stage = 'setup'
            with self.subTest(fault=fault):
                with self.assertRaises(OSError) as caught:
                    with scope['PrivateFile'](scratch, security) as fixture:
                        stage = 'create'
                        fixture.create()
                        self.assertEqual(fixture.original, 12)
                        stage = 'bind'
                        fixture.bind_original()
                        stage = 'reopen'
                        fixture.reopen()
                self.assertEqual(stage, expected_stage)
                self.assertEqual(caught.exception.winerror, 5)
                self.assertNotIn('reopen', events)
                self.assertNotIn('dispose', events)
                self.assertEqual(closed, [9, 8] if fault == 'create' else [12, 9, 8])

    def test_original_and_independent_cleanup_failures_are_retained(self):
        for close_faults in ((12,), (16,), (12, 16), (24, 20, 9, 8)):
            with self.subTest(close_faults=close_faults):
                scope, scratch, security, events, closed, _ = self.fixture(close_faults=close_faults)
                original = ValueError('private original')
                action = Mock(side_effect=original)
                with self.assertRaises(ExceptionGroup) as caught:
                    with scope['PrivateFile'](scratch, security) as fixture:
                        fixture.create()
                        fixture.bind_original()
                        fixture.reopen()
                        fixture.qualify()
                        action()
                self.assertIs(caught.exception.exceptions[0], original)
                self.assertEqual(len(caught.exception.exceptions), 1 + len(close_faults))
                self.assertIn(12, closed)
                self.assertIn(16, closed)
                self.assertIn(20, closed)
                self.assertIn(8, closed)
                if 12 in close_faults or 16 in close_faults:
                    self.assertNotIn('delete', events)

    def test_cleanup_refuses_foreign_identity_and_keeps_all_close_attempts(self):
        for fault in ('delete', 'cleanup-identity', 'dispose'):
            with self.subTest(fault=fault):
                scope, scratch, security, events, closed, _ = self.fixture(fault)
                with self.assertRaises(ExceptionGroup):
                    with scope['PrivateFile'](scratch, security) as fixture:
                        fixture.create()
                        fixture.bind_original()
                        fixture.reopen()
                        fixture.qualify()
                self.assertTrue({12, 16, 20, 8}.issubset(closed))
                if fault != 'dispose':
                    self.assertNotIn('dispose', events)

    def test_native_root_shape_is_exact_and_does_not_use_dos_translation(self):
        prefix = '\\Device\\HarddiskVolume'
        for digits in ('0', '1', '9' * 20):
            scope, scratch, security, events, _, _ = self.fixture(root_name=prefix + digits + '\\')
            with scope['PrivateFile'](scratch, security) as fixture:
                fixture.create()
                fixture.bind_original()
                fixture.reopen()
                self.assertEqual(fixture.qualify(), 16)
            self.assertTrue(all(event[2] == 2 for event in events
                                if type(event) is tuple and event[0] == 'name'))
        invalid = ('\\\\?\\E:\\', '\\\\server\\share\\', '\\Device\\Other1\\', prefix + '\\',
                   prefix + '1', prefix + '1\\\\', prefix + '1\\temp\\', prefix + 'x\\',
                   prefix + '١\\', prefix + '9' * 21 + '\\', '\\\\?\\Volume{123}\\',
                   prefix.lower() + '1\\')
        for name in invalid:
            with self.subTest(name=name):
                scope, scratch, security, events, closed, _ = self.fixture(root_name=name)
                reached = Mock()
                with self.assertRaisesRegex(AssertionError, '^private creator scratch name differs$'):
                    with scope['PrivateFile'](scratch, security):
                        reached()
                reached.assert_not_called()
                self.assertEqual(closed, [8])
                self.assertNotIn('create', events)

    def test_native_error_is_immediate_and_success_never_reads_stale_error(self):
        scope = runpy.run_path(str(WINDOWS / 'PrivateCreator.py'))
        actual = scope['private_creator'].__globals__
        for code in (None, 0, 5, 8, 0xFFFFFFFF):
            seen = []
            def create(*arguments):
                seen.append('create')
                self.assertEqual(arguments, ('fixed-leaf', 0xC0000000, 3, 7, 1, 0x80, None))
                return 12 if code is None else ctypes.c_void_p(-1).value
            def error():
                seen.append('error')
                return code
            actual.update(K=SimpleNamespace(CreateFileW=create),
                          ctypes=SimpleNamespace(c_void_p=ctypes.c_void_p, get_last_error=error))
            with self.subTest(code=code):
                if code is None:
                    self.assertEqual(scope['private_creator']('fixed-leaf', 7), 12)
                    self.assertEqual(seen, ['create'])
                else:
                    with self.assertRaises(OSError) as caught:
                        scope['private_creator']('fixed-leaf', 7)
                    self.assertEqual(caught.exception.winerror, code)
                    self.assertEqual(seen, ['create', 'error'])

    def test_private_parent_is_bound_and_removed_before_reviewed_admission(self):
        controller = (WINDOWS / 'Run-WindowsSecurity.ps1').read_text(encoding='utf-8')
        anchors = ('[ScientificSecurity.PrivateCreatorFixture]::Prepare($runId, $mountPath, $package.Value)',
                   '    Set-OwnedAccess $mountPath $true $true',
                   '[ScientificSecurity.PrivateCreatorFixture]::RequireAfterSeal($runId, $mountPath, $package.Value)',
                   '$negativeBaselineExit = [ScientificSecurity.RegistryCausalComparison]::Run(',
                   '$preflightText = [ScientificSecurity.Sandbox]::Run(',
                   '$wall = [ScientificSecurity.Sandbox]::Run(',
                   '[ScientificSecurity.PrivateCreatorFixture]::RemoveBeforeAdmission($runId, $mountPath, $package.Value)',
                   "Write-RunLog INFO 'all required native controls observed including wall-tree cleanup; reviewed regressions admitted'",
                   '$regressionText = [ScientificSecurity.Sandbox]::Run(')
        for anchor in anchors:
            self.assertEqual(controller.count(anchor), 1)
        positions = [controller.index(anchor) for anchor in anchors]
        self.assertEqual(positions, sorted(positions))
        for name in ('PrivateCreatorFixture.cs', 'PrivateCreatorValidation.cs'):
            self.assertIn("(Join-Path $PSScriptRoot '" + name + "')", controller)
        self.assertIn("Invoke-BootstrapStage 'managed' 53 { [ScientificSecurity.PrivateCreatorFixture]::CheckValidation() }", controller)
        release = controller.index('[ScientificSecurity.PrivateCreatorFixture]::ReleasePins()')
        self.assertLess(release, controller.index('if ($mounted -and $traceStopped -and $attachmentClosed)'))
        preparation = (WINDOWS / 'SandboxPreparation.cs').read_text(encoding='utf-8')
        self.assertIn('if (phase == "preflight") PrivateCreatorFixture.RequireUse(process, scratch, package);', preparation)
        completion = (WINDOWS / 'SandboxCompletion.cs').read_text(encoding='utf-8')
        self.assertIn('ScratchVolumePolicy.EndRun, PrivateCreatorFixture.EndRun,', completion)
        scope, scratch, security, _, _, creates = self.fixture()
        with scope['PrivateFile'](scratch, security) as fixture:
            fixture.create()
            fixture.bind_original()
            fixture.reopen()
            fixture.qualify()
        self.assertEqual(creates[1][0], str(scratch / 'private-creator'))
        self.assertEqual(creates[2][0], str(scratch / 'private-creator' / 'authority-protected'))
        for call in creates[2:]:
            self.assertEqual(call[0], creates[2][0])

    def test_authority_consumer_retains_original_actual_controls(self):
        tree = ast.parse((WINDOWS / 'KernelProbe.py').read_text(encoding='utf-8'))
        authority = next(node for node in tree.body if isinstance(node, ast.FunctionDef)
                         and node.name == 'authority_controls')
        source = ast.unparse(authority)
        for text in ("'D:P(A;;GA;;;' + sid + ')'", 'fixture.create()', 'fixture.bind_original()', 'fixture.reopen()',
                     'handle = fixture.qualify()', 'native_eof_quota(handle, sparse=False)',
                     'native_eof_quota(handle, sparse=True)', 'for owner_name in owners:',
                     "'S-1-5-32-544'", "'S-1-5-21-101-202-303-404'", 'for access in (3221225472, 1073741824, 2):'):
            self.assertIn(text, source)
        self.assertNotIn('protected.unlink', source)


if __name__ == '__main__':
    unittest.main()
