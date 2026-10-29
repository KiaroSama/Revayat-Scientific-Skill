"""Inert checks of the actual Python token diagnostic and its closed wire."""
import ast
import ctypes
import io
from pathlib import Path
import runpy
from types import SimpleNamespace
import unittest

ROOT = Path(__file__).resolve().parents[1]
WINDOWS = ROOT / 'tests/security/windows'
STAGES = (
    'platform', 'x64', 'version', 'abi', 'import', 'detached', 'open',
    'type-query', 'type-length', 'elevation-query', 'elevation-length',
    'restrictions-query', 'restrictions-length', 'restrictions-len1', 'primary-fields',
    'lpac-query', 'lpac-value', 'app-read', 'app-value', 'caps-read', 'caps-value',
    'traversal', 'priv-read', 'priv-count', 'priv-value', 'groups-read', 'groups-count',
    'sid-read', 'admin', 'libraries', 'prototypes', 'job-query', 'job-value', 'deadline',
)


class PythonTokenTest(unittest.TestCase):
    def setUp(self):
        self.probe = runpy.run_path(str(WINDOWS / 'RegistryAuthorityProbe.py'))
        self.scope = self.probe['token_controls'].__globals__

    def token_fixture(self, selected, final=False, close_fault=False, restriction=None, privileges=None, privilege_length=None):
        seen = []
        prefix = 'tf-' if final else 'ti-'

        class Luid(ctypes.Structure):
            _fields_ = [('low', ctypes.c_uint32), ('high', ctypes.c_int32)]

        class Privilege(ctypes.Structure):
            _fields_ = [('luid', Luid), ('attributes', ctypes.c_uint32)]

        self.assertEqual(ctypes.sizeof(Luid), 8)
        self.assertEqual(ctypes.sizeof(Privilege), 12)

        class SidAttributes(ctypes.Structure):
            _fields_ = [('sid', ctypes.c_void_p), ('attributes', ctypes.c_uint32)]

        class Groups(ctypes.Structure):
            _fields_ = [('count', ctypes.c_uint32), ('first', SidAttributes)]

        class Authority:
            def __getattr__(self, _name):
                raise AssertionError('Traversal resolver must not be accessed')

        def query(_token, kind, value, _capacity, returned):
            stage = {8: 'type', 20: 'elevation', 21: 'restrictions'}[kind]
            seen.append(stage)
            returned._obj.value = 4
            value._obj.value = 0 if kind == 20 else 1
            if selected == stage + '-query':
                return 0
            if selected == stage + '-length':
                returned._obj.value = 2
            if restriction is not None and kind == 21:
                returned._obj.value, value._obj.value, success = restriction
                return success
            if selected == 'primary-fields' and kind == 20:
                value._obj.value = 1
            return 1

        def data(_token, kind):
            stage = {29: 'app', 30: 'caps', 3: 'priv', 2: 'groups'}[kind]
            seen.append(stage)
            if selected == stage + '-read':
                raise AssertionError('private-helper-sentinel')
            if kind in (29, 30):
                value = (0 if selected == 'app-value' else 1) if kind == 29 else (1 if selected == 'caps-value' else 0)
                return bytearray(value.to_bytes(4, 'little'))
            if kind == 3:
                entries = [(24 if selected == 'priv-value' else 23, 0, 0)] if privileges is None else privileges
                count = 129 if selected == 'priv-count' else len(entries)
                result = bytearray(4 + len(entries) * ctypes.sizeof(Privilege))
                result[:4] = count.to_bytes(4, 'little')
                for index, (low, high, attributes) in enumerate(entries):
                    item = Privilege.from_buffer(result, 4 + index * ctypes.sizeof(Privilege))
                    item.luid.low, item.luid.high, item.attributes = low, high, attributes
                return result if privilege_length is None else result[:privilege_length]
            count = 257 if selected == 'groups-count' else 1
            result = bytearray(Groups.first.offset + ctypes.sizeof(SidAttributes))
            result[:4] = count.to_bytes(4, 'little')
            item = SidAttributes.from_buffer(result, Groups.first.offset)
            item.sid, item.attributes = 1, 4 if selected == 'admin' else 16
            return result

        def opened(_process, _access, token):
            seen.append('open')
            token._obj.value = 1
            return selected != 'open'

        def lpac(_token):
            seen.append('lpac')
            if selected == 'lpac-query':
                raise AssertionError('private-lpac-sentinel')
            return selected != 'lpac-value'

        def sid(_value):
            seen.append('sid')
            if selected == 'sid-read':
                raise AssertionError('private-sid-sentinel')
            return 'S-1-5-32-544'

        def close(_token):
            seen.append('close')
            if close_fault:
                raise OSError('private-close-sentinel')
            return 1

        self.scope['w'] = SimpleNamespace(DWORD=ctypes.c_uint32, LPCWSTR=object())
        authority = Authority()
        authority.OpenProcessToken, authority.GetTokenInformation = opened, query
        trusted = {'A': authority,
                   'K': SimpleNamespace(GetCurrentProcess=lambda: 1, CloseHandle=close),
                   'lpac_enabled': lpac, 'token_data': data, 'sid_text': sid,
                   'Luid': Luid, 'Privilege': Privilege, 'Groups': Groups, 'SidAttributes': SidAttributes}
        return lambda: self.probe['token_controls'](trusted, final=final), seen, prefix

    def test_existing_token_predicates_keep_first_failure_and_occurrence(self):
        tested = tuple(stage for stage in STAGES[6:29] if stage not in ('restrictions-len1', 'traversal'))
        for final in (False, True):
            for selected in tested:
                operation, seen, prefix = self.token_fixture(selected, final)
                output = io.StringIO()
                with self.subTest(final=final, stage=selected):
                    self.assertEqual(self.probe['entry'](operation, output.write, 'primary'), 1)
                    category = 'other' if selected in ('lpac-query', 'app-read', 'caps-read', 'priv-read', 'groups-read', 'sid-read') else 'control'
                    self.assertEqual(output.getvalue(), 'REGISTRY_AUTHORITY_FAILURE role=primary child_exit=none errors=' + prefix + selected + ':' + category + '\n')
                    self.assertNotIn('private', output.getvalue())
                    self.assertEqual(seen.count('close'), 0 if selected == 'open' else 1)
            operation, seen, _ = self.token_fixture(None, final)
            operation()
            self.assertEqual(seen, ['open', 'type', 'elevation', 'restrictions', 'lpac', 'app', 'caps',
                                    'priv', 'groups', 'sid', 'close'])

    def test_privileges_require_full_canonical_identity_without_a_resolver(self):
        cases = [([], None, None)] + [([(23, 0, flags)], None, None) for flags in (0, 2, 0xFFFFFFFF)]
        cases += [([(low, high, 0)], None, 'priv-value')
                  for low, high in ((0, 0), (22, 0), (24, 0), (0xFFFFFFFF, 0), (23, 1), (23, -1))]
        cases += [(entries, None, 'priv-value') for entries in
                  ([(23, 0, 0), (24, 0, 0)], [(24, 0, 0), (23, 0, 0)])]
        cases += [([(23, 0, 0)], length, 'priv-count') for length in (4, 15)]
        for final in (False, True):
            for entries, length, refused in cases:
                operation, seen, prefix = self.token_fixture(None, final, privileges=entries, privilege_length=length)
                with self.subTest(final=final, entries=entries, length=length):
                    if refused is None:
                        operation()
                    else:
                        with self.assertRaises(self.probe['Failure']) as caught:
                            operation()
                        self.assertEqual(caught.exception.events, ((prefix + refused, 'control'),))
                    self.assertEqual(seen[-1], 'close')
                    self.assertNotIn('traversal', seen)

    def test_restrictions_decode_only_the_successful_returned_span(self):
        cases = [
            (1, 1, 1, None), (1, 0xAABBCC01, 1, None), (4, 1, 1, None),
            (1, 0, 1, 'primary-fields'), (1, 2, 1, 'primary-fields'),
            (1, 255, 1, 'primary-fields'), (4, 0x10001, 1, 'primary-fields'),
            (4, 0xAABBCC01, 1, 'primary-fields'), (4, 0, 1, 'primary-fields'),
        ]
        cases += [(length, 1, 1, 'restrictions-length') for length in (0, 2, 3, 5, 0xFFFFFFFF)]
        cases += [(length, 1, 0, 'restrictions-query') for length in (1, 4)]
        real = ctypes.string_at
        for final in (False, True):
            for length, value, success, refused in cases:
                operation, seen, prefix = self.token_fixture(None, final, restriction=(length, value, success))
                reads = []

                def read(pointer, count):
                    reads.append(count)
                    self.assertIn(count, (1, 4))
                    return real(pointer, count)

                self.scope['ctypes'] = SimpleNamespace(**dict(vars(ctypes), string_at=read))
                with self.subTest(final=final, length=length, value=value, success=success):
                    if refused is None:
                        operation()
                        self.assertEqual(seen[-1], 'close')
                    else:
                        with self.assertRaises(self.probe['Failure']) as caught:
                            operation()
                        self.assertEqual(caught.exception.events, ((prefix + refused, 'control'),))
                        self.assertEqual(seen[-1], 'close')
                    self.assertEqual(reads, [length] if success and length in (1, 4) else [])
                self.scope['ctypes'] = ctypes

    def test_actual_preamble_stops_at_each_existing_boundary(self):
        real_ctypes = ctypes
        for selected in STAGES[:6] + ('libraries', 'prototypes', 'job-query', 'job-value'):
            self.setUp()
            scope = self.scope

            class Function:
                def __call__(self, *args):
                    if len(args) == 3:
                        args[2]._obj.value = 0 if selected == 'job-value' else 1
                        return selected != 'job-query'
                    return 1
                def __setattr__(self, name, value):
                    if selected == 'prototypes':
                        raise RuntimeError('private-prototype-sentinel')
                    object.__setattr__(self, name, value)

            class Library:
                def __getattr__(self, _name):
                    return Function()

            def library(*_args, **_kwargs):
                if selected == 'libraries':
                    raise OSError('private-library-sentinel')
                return Library()

            def size(kind):
                if kind is scope['P']:
                    return 4 if selected == 'x64' else 8
                if kind is scope['Unicode']:
                    return 0 if selected == 'abi' else 16
                if kind is scope['Attributes']:
                    return 48
                return real_ctypes.sizeof(kind)

            def loaded(_path):
                if selected == 'import':
                    raise ImportError('private-import-sentinel')
                def detached():
                    if selected == 'detached':
                        raise AssertionError('private-detached-sentinel')
                return {'require_detached_stdio': detached}

            scope['os'] = SimpleNamespace(name='posix' if selected == 'platform' else 'nt')
            scope['sys'] = SimpleNamespace(version_info=(3, 12) if selected == 'version' else (3, 11))
            names = ('POINTER', 'byref', 'c_int', 'c_longlong')
            scope['ctypes'] = SimpleNamespace(**{name: getattr(real_ctypes, name) for name in names},
                                              sizeof=size, WinDLL=library)
            scope['w'] = SimpleNamespace(DWORD=ctypes.c_uint32, ULONG=ctypes.c_uint32, LONG=ctypes.c_int32,
                                         BOOL=ctypes.c_int32, LPWSTR=ctypes.c_void_p, LPCWSTR=ctypes.c_void_p)
            scope['runpy'] = SimpleNamespace(run_path=loaded)
            scope['token_controls'] = lambda _trusted: None
            output = io.StringIO()
            with self.subTest(stage=selected):
                self.assertEqual(self.probe['entry'](self.probe['controls'], output.write, 'primary'), 1)
                kind = 'other' if selected in ('import', 'detached') else 'native' if selected == 'libraries' else 'control'
                self.assertEqual(output.getvalue(), 'REGISTRY_AUTHORITY_FAILURE role=primary child_exit=none errors=ti-' + selected + ':' + kind + '\n')
                self.assertNotIn('private', output.getvalue())

    def test_operation_close_and_report_failures_remain_fatal(self):
        for final in (False, True):
            operation, seen, prefix = self.token_fixture('restrictions-length', final, close_fault=True)
            with self.assertRaises(self.probe['Failure']) as caught:
                operation()
            self.assertEqual(caught.exception.events, ((prefix + 'restrictions-length', 'control'), ('close', 'cleanup')))
            self.assertIsNone(caught.exception.child_exit)
            self.assertEqual(seen[-1], 'close')
            self.assertNotIn('private', self.probe['failure_wire'](caught.exception, 'primary'))
            operation, _, prefix = self.token_fixture('restrictions-length', final)

            def refused(_text):
                raise OSError('private-report-sentinel')

            with self.assertRaises(self.probe['Failure']) as caught:
                self.probe['entry'](operation, refused, 'primary')
            self.assertEqual(caught.exception.events, ((prefix + 'restrictions-length', 'control'), ('report', 'other')))
            self.assertIsNone(caught.exception.child_exit)

    def test_closed_phases_descendant_retention_and_transport_limits(self):
        self.assertEqual(self.probe['PYTHON_TOKEN_STAGES'], STAGES)
        self.assertEqual(len(STAGES), len(set(STAGES)))
        for prefix in ('ti-', 'tf-'):
            for stage in STAGES:
                for kind in ('control', 'other', 'native'):
                    event = (prefix + stage, kind)
                    failure = self.probe['Failure']((event,))
                    frame = self.probe['failure_wire'](failure, 'descendant')
                    child = SimpleNamespace(returncode=7, stdout='', stderr=frame)
                    with self.assertRaises(self.probe['Failure']) as caught:
                        self.probe['descendant_result'](child)
                    self.assertEqual(caught.exception.events, (('descendant', 'transport'), event))
                    self.assertEqual(caught.exception.child_exit, 7)
        invalid = ('ti-private', 'tf-private', 'ti-openx', 'token-initial', 'token-final')
        for phase in invalid:
            with self.assertRaises(self.probe['Failure']):
                self.probe['failure_wire'](self.probe['Failure'](((phase, 'control'),)), 'primary')
            child = SimpleNamespace(returncode=9, stdout='', stderr='REGISTRY_AUTHORITY_FAILURE role=descendant child_exit=none errors=' + phase + ':control\n')
            with self.assertRaises(self.probe['Failure']) as caught:
                self.probe['descendant_result'](child)
            self.assertEqual(caught.exception.events, (('descendant', 'transport'),))
            self.assertEqual(caught.exception.child_exit, 9)
        for prefix in ('ti-', 'tf-'):
            invalid = self.probe['Failure'](((prefix + 'open', 'import'),))
            with self.assertRaises(self.probe['Failure']):
                self.probe['failure_wire'](invalid, 'primary')
            child = SimpleNamespace(returncode=5, stdout='', stderr='REGISTRY_AUTHORITY_FAILURE role=descendant child_exit=none errors=' + prefix + 'open:import\n')
            with self.assertRaises(self.probe['Failure']) as caught:
                self.probe['descendant_result'](child)
            self.assertEqual(caught.exception.events, (('descendant', 'transport'),))
            self.assertEqual(caught.exception.child_exit, 5)
        with self.assertRaises(self.probe['Failure']):
            self.probe['failure_wire'](self.probe['Failure']((('ti-open', 'control'),) * 9), 'primary')
        for final in ('ti-', 'tf-'):
            longest = max(STAGES, key=len)
            frame = self.probe['failure_wire'](self.probe['Failure'](((final + longest, 'control'),) * 8, 0xFFFFFFFF), 'primary')
            self.assertTrue(frame.isascii())
            self.assertLessEqual(len(frame.encode('ascii')), 512)

    def test_controller_and_actual_call_sites_share_closed_phase_inventory(self):
        comparison = (WINDOWS / 'RegistryAuthorityComparison.cs').read_text(encoding='utf-8')
        import re
        stages = re.search(r'const string PythonTokenStages = "([^"]+)";', comparison)
        self.assertIsNotNone(stages)
        self.assertEqual(tuple(stages[1].split('|')), STAGES)
        self.assertIn('(?:ti|tf)-(?:', comparison)
        self.assertIn('token:control-restrictions-query', comparison)
        self.assertIn('ti-restrictions-len1:control restrictions=', comparison)
        tree = ast.parse((WINDOWS / 'RegistryAuthorityProbe.py').read_text(encoding='utf-8'))
        controls = next(node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name == 'controls')
        calls = [node for node in ast.walk(controls) if isinstance(node, ast.Call)
                 and isinstance(node.func, ast.Name) and node.func.id == 'token_controls']
        calls.sort(key=lambda node: node.lineno)
        self.assertEqual(len(calls), 2)
        self.assertEqual(calls[0].keywords, [])
        self.assertEqual(len(calls[1].keywords), 1)
        self.assertEqual(calls[1].keywords[0].arg, 'final')
        self.assertIs(calls[1].keywords[0].value.value, True)
        assigned = [node.value.value for node in ast.walk(controls) if isinstance(node, ast.Assign)
                    and any(isinstance(target, ast.Name) and target.id == 'PHASE' for target in node.targets)
                    and isinstance(node.value, ast.Constant) and isinstance(node.value.value, str)]
        for phase in ('ti-platform', 'ti-x64', 'ti-version', 'ti-abi', 'ti-import', 'ti-detached',
                      'ti-libraries', 'ti-prototypes', 'ti-job-query', 'ti-job-value', 'tf-deadline'):
            self.assertIn(phase, assigned)


if __name__ == '__main__':
    unittest.main()
