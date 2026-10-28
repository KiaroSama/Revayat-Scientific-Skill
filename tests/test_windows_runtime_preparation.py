"""Exercise trusted preparation functions, not the native security entry point."""
from pathlib import Path
import runpy
import shutil
import sys
import tempfile
import unittest

from processes import run as owned_run

ROOT = Path(__file__).resolve().parents[1]


class DiagnosticOrderTest(unittest.TestCase):
    def test_python_diagnostics_precede_independent_debugger_controls(self):
        controller = (ROOT / 'tests/security/windows/Run-WindowsSecurity.ps1').read_text(encoding='utf-8')
        python_block = """    Write-RunLog INFO 'separate bounded trusted pass-code loader trace starts; never an admission control'
    $loaderDiagnostic = [ScientificSecurity.Sandbox]::Run($childPython, $target, $mountPath, $childPowerShell, $chromium, $moniker, $profileFolder, $true, $tcpPort, $udpPort, $false, $true)
    Write-RunLog INFO $loaderDiagnostic
    Write-RunLog INFO 'fixed three-condition Python clone loader comparison starts; diagnostic only and never admission'
    [ScientificSecurity.PythonLoaderComparison]::Run($runId, $state, $childPython, $target, $mountPath, $childPowerShell, $chromium, $moniker, $profileFolder, $tcpPort, $udpPort)
    [ScientificSecurity.PythonCsrDispatch]::RunHost($childPython)
"""
        anchors = (
            '[ScientificSecurity.PythonStartupFixture]::Prepare($runId, $state)',
            '[ScientificSecurity.PythonCsrDispatch]::Prepare($runId, $state)',
            '    Protect-Tree $runtime\n',
            '[ScientificSecurity.StaticKernelInspection]::RunFixed($state)',
            '[ScientificSecurity.StaticKernelInspection]::RunActivationWorker($state)',
            python_block,
            '[ScientificSecurity.PythonCsrDispatch]::RunHost($childPython)',
            '[ScientificSecurity.RegistryStartupComparison]::Run($runId, $state, $childPython, $target, $mountPath, $childPowerShell, $chromium, $moniker, $profileFolder, $tcpPort, $udpPort)',
            '[ScientificSecurity.RegistryAuthorityComparison]::Run($runId, $state, $childPython, $target, $mountPath, $childPowerShell, $chromium, $moniker, $profileFolder, $tcpPort, $udpPort)',
            '[ScientificSecurity.RegistryAuthorityComparison]::RunPython($runId, $state, $childPython, $target, $mountPath, $childPowerShell, $chromium, $moniker, $profileFolder, $tcpPort, $udpPort)',
            '[ScientificSecurity.PythonActivationPreparation]::Run($runId, $state, $childPython, $target, $mountPath, $childPowerShell, $chromium, $moniker, $profileFolder, $tcpPort, $udpPort)',
            '[ScientificSecurity.PythonActivationPreparation]::RunHost($runId, $state, $childPython, $target, $mountPath, $childPowerShell, $chromium, $moniker, $profileFolder, $tcpPort, $udpPort)',
            '[ScientificSecurity.PythonActivationPreparation]::RunImages($runId, $state, $childPython, $target, $mountPath, $childPowerShell, $chromium, $moniker, $profileFolder, $tcpPort, $udpPort)',
            '[ScientificSecurity.PythonActivationPreparation]::RunActivationBundle($runId, $state, $childPython, $target, $mountPath, $childPowerShell, $chromium, $moniker, $profileFolder, $tcpPort, $udpPort)',
            '[ScientificSecurity.DefaultDaclComparison]::Run($runId, $state, $childPython, $target, $mountPath, $childPowerShell, $chromium, $moniker, $profileFolder, $tcpPort, $udpPort)',
            '[ScientificSecurity.DebugControl]::RunFixed($runId, $state)',
            '[ScientificSecurity.ChildActivationFixture]::RunDllHost($childPython)',
            '[ScientificSecurity.SelfActivationFixture]::RunHost($childPython)',
            '[ScientificSecurity.SelfActivationFixture]::RunDispatchHost($childPython)',
            '[ScientificSecurity.ModuleActivationFixture]::RunDispatchHost($childPython)',
            '[ScientificSecurity.SelfActivationFixture]::RunEntryHost($childPython)',
            '[ScientificSecurity.SelfActivationFixture]::RunResourceHost($childPython)',
            "[ScientificSecurity.LoaderSnaps]::Enable($runId, $state, (Join-Path (Split-Path $childPython) 'startup-native.exe'))",
            '$nativeDiagnostic = [ScientificSecurity.Sandbox]::Run($childPython, $target, $mountPath, $childPowerShell, $chromium, $moniker, $profileFolder, $true, $tcpPort, $udpPort, $false, $true, $true)',
            'finally { [ScientificSecurity.LoaderSnaps]::Cleanup($runId, $state, $diagnosticFailure) }\n'
            '    [ScientificSecurity.LoaderSnaps]::RequireClean($runId, $state)',
            "[Console]::Out.WriteLine('WINDOWS_INTERNAL_OBSERVATION site=",
            '[ScientificSecurity.ManualActivationComparison]::Run(',
            '[ScientificSecurity.ManualActivationComparison]::RunDllRequest(',
            '[ScientificSecurity.CsrDispatchComparison]::Run(',
            '[ScientificSecurity.CsrDispatchComparison]::RunModule(',
            '[ScientificSecurity.CsrDispatchComparison]::RunPython(',
            '[ScientificSecurity.AutomaticResourceComparison]::Run(',
            '$negativeBaselineExit = [ScientificSecurity.RegistryCausalComparison]::Run(',
            '$preflightText = [ScientificSecurity.Sandbox]::Run(',
            '[ScientificSecurity.PythonActivationPreparation]::RequireClean()',
            '[ScientificSecurity.CsrDispatchComparison]::RequireClean()',
            '[ScientificSecurity.RegistryCausalComparison]::RequireNegativeBaseline($negativeBaselineExit)',
            "if ($preflight.status -ne 'passed' -or $preflight.phase -ne 'preflight')",
            '$wall = [ScientificSecurity.Sandbox]::Run(',
            '$regressionText = [ScientificSecurity.Sandbox]::Run(',
        )
        for anchor in anchors:
            self.assertEqual(controller.count(anchor), 1, 'Missing, duplicated or altered diagnostic/admission step')
        positions = [controller.index(anchor) for anchor in anchors]
        self.assertEqual(positions, sorted(positions), 'Python diagnostic cleanup must precede debugger controls without bypassing later gates')

    def test_standard_trace_has_one_owned_lifecycle_and_outer_recovery(self):
        windows = ROOT / 'tests/security/windows'
        controller = (windows / 'Run-WindowsSecurity.ps1').read_text(encoding='utf-8')
        self.assertEqual(controller.count('[ScientificSecurity.SxsTraceCapture]::Run('), 1)
        anchors = (
            "@('quota','query', $volume)",
            '[ScientificSecurity.SxsTraceCapture]::PrepareStorage(',
            '    Set-OwnedAccess $mountPath $true $true\n',
            '[ScientificSecurity.SxsTraceCapture]::RequireStorageAfterSeal(',
            '[ScientificSecurity.SxsTraceCapture]::Run(',
        )
        self.assertTrue(all(controller.count(anchor) == 1 for anchor in anchors), 'Missing or repeated sealed-storage phase')
        self.assertEqual([controller.index(anchor) for anchor in anchors], sorted(controller.index(anchor) for anchor in anchors))
        self.assertIn('[ScientificSecurity.SxsTraceSession]::Recover($runId, $state, $OuterOwnerReaped.IsPresent)', controller)
        self.assertIn('[ScientificSecurity.SxsTraceSession]::Recover($runId, $state, $true)', controller)
        self.assertLess(controller.index('[ScientificSecurity.SxsTraceSession]::Recover($runId, $state, $OuterOwnerReaped.IsPresent)'), controller.index('$disk = Get-VHD'))
        self.assertIn('$mounted -and $traceStopped', controller)
        preparation = (windows / 'RegistryStartupComparison.cs').read_text(encoding='utf-8')
        self.assertIn('if (observation is RegistryAuthorityComparison.PythonObservation) SxsTraceCapture.StartAuthority(child, package, clock);', preparation)
        runner = (windows / 'TrustedSetup.cs').read_text(encoding='utf-8')
        self.assertIn('internal static void RunSxsTrace(', runner)
        self.assertNotIn('"-filter:python.exe"', runner)
        self.assertNotIn('"pwsh.exe", "sxstrace.exe" }.Contains(name)', runner)
        capture = (windows / 'SxsTraceCapture.cs').read_text(encoding='utf-8')
        self.assertNotIn('Directory.CreateDirectory(folder)', capture)
        self.assertIn('SxsTraceStorage.Create(folder, policy)', capture)
        self.assertNotIn('CreateDirectoryW', capture)
        self.assertIn('CreateSealed(security, host.User.Value, package', capture)
        self.assertIn('Acquired(SxsTraceSession.Exclusive', capture)
        self.assertIn('SxsCanaryOwner.Run(host.User, () => {', capture)
        self.assertIn('SxsTraceSeed.Create(() => new FileStream(seed, FileMode.CreateNew, FileAccess.ReadWrite, FileShare.None)', capture)
        self.assertIn('SxsTraceSeed.PrepareText(', capture)
        self.assertIn("(Join-Path $PSScriptRoot 'SxsTraceSeed.cs')", controller)
        self.assertIn('RequireSeed(); Need(clock.Elapsed.TotalSeconds < 10);', capture)
        self.assertIn('Path.Combine(folder, "canary"), Path.Combine(folder, "capture.etl")', capture)
        self.assertIn('new FileStream(canary, FileMode.CreateNew, FileAccess.ReadWrite, FileShare.None)', capture)
        self.assertNotIn('CanaryPolicy(', capture)
        self.assertIn("(Join-Path $PSScriptRoot 'SxsCanaryOwner.cs')", controller)

    def test_rust_authority_keeps_python_diagnostic_separate(self):
        windows = ROOT / 'tests/security/windows'
        controller = (windows / 'Run-WindowsSecurity.ps1').read_text(encoding='utf-8')
        authority = controller.index('[ScientificSecurity.RegistryAuthorityComparison]::Run(')
        trace = controller.index('[ScientificSecurity.SxsTraceCapture]::Run(')
        python = controller.index('[ScientificSecurity.RegistryAuthorityComparison]::RunPython(')
        admission = controller.index('$preflightText = [ScientificSecurity.Sandbox]::Run(')
        self.assertLess(authority, trace)
        self.assertLess(trace, python)
        self.assertLess(python, admission)
        preparation = (windows / 'SandboxPreparation.cs').read_text(encoding='utf-8')
        self.assertIn('new List<string> { RegistryAuthorityFixture.Image(python) }', preparation)
        self.assertIn('RegistryAuthorityProbe.py', preparation)
        self.assertIn("[ScientificSecurity.RegistryAuthorityFixture]::Prepare($PSScriptRoot, $childPython)", controller)
        self.assertLess(controller.index('[ScientificSecurity.RegistryAuthorityFixture]::Prepare('), controller.index('    Protect-Tree $runtime\n'))

    def test_rust_token_stage_allowlists_match_controller(self):
        import re
        windows = ROOT / 'tests/security/windows'
        protocol = (windows / 'registry-authority/src/protocol.rs').read_text(encoding='utf-8')
        token = protocol.split('pub const TOKEN_CHECKS: &[&str] = &[', 1)[1].split('];', 1)[0]
        rust = re.findall(r'"(control-[a-z-]+)"', token)
        comparison = (windows / 'RegistryAuthorityComparison.cs').read_text(encoding='utf-8')
        managed = re.search(r'const string TokenStages = "([^"]+)";', comparison)[1].split('|')
        self.assertEqual(rust, ['control-' + stage for stage in managed])
        self.assertEqual(len(rust), len(set(rust)))
        self.assertEqual(len(rust), 41)
        self.assertIn('|token:control-(?:', comparison)

    def test_descendant_stages_preserve_ownership_and_native_error_boundaries(self):
        import re
        windows = ROOT / 'tests/security/windows'
        protocol = (windows / 'registry-authority/src/protocol.rs').read_text(encoding='utf-8')
        comparison = (windows / 'RegistryAuthorityComparison.cs').read_text(encoding='utf-8')
        for rust_name, managed_name, count in (('DESCENDANT_CHECKS', 'DescendantStages', 25),
                                                ('NATIVE_CHECKS', 'NativeStages', 14)):
            block = protocol.split('pub const ' + rust_name + ': &[&str] = &[', 1)[1].split('];', 1)[0]
            rust = re.findall(r'"(control-[a-z-]+)"', block)
            managed = re.search(r'const string ' + managed_name + r' = "([^"]+)";', comparison)[1].split('|')
            self.assertEqual(rust, ['control-' + stage for stage in managed])
            self.assertEqual(len(rust), count)
            self.assertEqual(len(rust), len(set(rust)))
        source = (windows / 'registry-authority/src/process.rs').read_text(encoding='utf-8')
        for start, end, anchors in (
            ('fn pipe(', 'fn collect(', ('let success = unsafe { CreatePipe(', 'let error =',
             'let read = Handle::new(', 'let write = Handle::new(', 'descendant_result(')),
            ('let created = unsafe {', 'let mut in_job =', ('CreateProcessW(', 'let create_error =',
             'let process = Handle::new(', 'let thread = Handle::new(', 'descendant_result(', 'let mut child = Child {')),
        ):
            block = source.split(start, 1)[1].split(end, 1)[0]
            self.assertEqual([block.index(anchor) for anchor in anchors],
                             sorted(block.index(anchor) for anchor in anchors))
        self.assertIn('if error == 109', source)
        self.assertIn('wait != u32::MAX', source)
        self.assertIn('raw_input as isize == -1', source)
        child_parser = source.split('fn child_failure(', 1)[1].split('pub fn descendant(', 1)[0]
        self.assertNotIn('descendant_need', child_parser)
        self.assertNotIn('native_error', child_parser)
        self.assertIn('role == "primary"', protocol)
        self.assertIn('self.restrictions.is_none()', protocol)
        self.assertIn('NativeStages.Split', comparison)

    def test_restrictions_query_uses_existing_call_and_failure_only_error(self):
        windows = ROOT / 'tests/security/windows'
        source = (windows / 'registry-authority/src/token.rs').read_text(encoding='utf-8')
        scalar = source.split('for (index, class) in [8, 20, 21].iter().enumerate() {', 1)[1].split('    lpac(token.raw)?;', 1)[0]
        self.assertEqual(scalar.count('GetTokenInformation('), 1)
        self.assertEqual(scalar.count('GetLastError()'), 1)
        self.assertIn('if *class == 21 {', scalar)
        self.assertIn('restriction_need(success, returned, || unsafe { GetLastError() })?;', scalar)
        protocol = (windows / 'registry-authority/src/protocol.rs').read_text(encoding='utf-8')
        guard = protocol.split('pub fn restriction_need(', 1)[1].split('#[derive(Debug)]', 1)[0]
        self.assertLess(guard.index('Some(error())'), guard.index('Failure::new('))
        self.assertIn('if success == 0', guard)
        self.assertIn('success != 0 && matches!(returned, 1 | 4)', guard)
        self.assertIn('restriction_value(&fields[index].to_le_bytes()[..returned as usize])?', scalar)
        self.assertIn('success != 0 && returned == 4', scalar)
        comparison = (windows / 'RegistryAuthorityComparison.cs').read_text(encoding='utf-8')
        self.assertIn('(?!0000000[14]:)', comparison)
        self.assertIn('.Contains("token:control-restrictions-query")', comparison)

    def test_rust_privileges_use_full_luid_without_worker_name_resolution(self):
        windows = ROOT / 'tests/security/windows'
        source = (windows / 'registry-authority/src/token.rs').read_text(encoding='utf-8')
        native = (windows / 'registry-authority/src/native.rs').read_text(encoding='utf-8')
        self.assertNotIn('LookupPrivilegeValueW', source + native)
        self.assertIn('const SE_CHANGE_NOTIFY_PRIVILEGE: u64 = 23;', source)
        inventory = source.split('fn privileges(', 1)[1].split('fn u32_at(', 1)[0]
        self.assertIn('length >= 4 && length <= std::mem::size_of_val(data)', inventory)
        self.assertIn('count <= 128 && 4 + count * 12 <= length', inventory)
        self.assertIn('u64::from(u32_at(data, offset + 4)) << 32', inventory)
        self.assertIn('luid == SE_CHANGE_NOTIFY_PRIVILEGE', inventory)
        controls = source.split('pub fn controls()', 1)[1].split('#[cfg(test)]', 1)[0]
        anchors = ('let (privilege_data, length) = data(token.raw, 3)?;',
                   'privileges(&privilege_data, length)?;', 'let (groups, length) = data(token.raw, 2)?;')
        for anchor in anchors:
            self.assertEqual(controls.count(anchor), 1)
        self.assertEqual([controls.index(anchor) for anchor in anchors],
                         sorted(controls.index(anchor) for anchor in anchors))
        host = (windows / 'TokenPolicy.cs').read_text(encoding='utf-8')
        self.assertIn('LookupPrivilegeValueW(null, "SeChangeNotifyPrivilege", out traverse)', host)
        for name in ('KernelProbe.py', 'RegistryAuthorityProbe.py'):
            self.assertIn('LookupPrivilegeValueW', (windows / name).read_text(encoding='utf-8'))

    def test_ordinary_admission_uses_fresh_strict_output_after_negative_baseline(self):
        controller = (ROOT / 'tests/security/windows/Run-WindowsSecurity.ps1').read_text(encoding='utf-8')
        block = '''    Write-RunLog INFO 'trusted undebugged kernel preflight starts before reviewed-code import'
    $preflightText = [ScientificSecurity.Sandbox]::Run($childPython, $target, $mountPath, $childPowerShell, $chromium, $moniker, $profileFolder, $true, $tcpPort, $udpPort)
    [ScientificSecurity.PythonActivationPreparation]::RequireClean()
    [ScientificSecurity.CsrDispatchComparison]::RequireClean()
    [ScientificSecurity.RegistryCausalComparison]::RequireNegativeBaseline($negativeBaselineExit)
    $preflight = $preflightText | ConvertFrom-Json
    if ($preflight.status -ne 'passed' -or $preflight.phase -ne 'preflight') { throw 'Trusted preflight did not return its required success observation' }
    $wall = [ScientificSecurity.Sandbox]::Run($childPython, $target, $mountPath, $childPowerShell, $chromium, $moniker, $profileFolder, $true, $tcpPort, $udpPort, $true)
    if ($wall -ne 'WALL_TREE_TERMINATED') { throw 'Native wall/process-tree negative control was not proved' }
    Write-RunLog INFO 'all required native controls observed including wall-tree cleanup; reviewed regressions admitted'
    $regressionText = [ScientificSecurity.Sandbox]::Run($childPython, $target, $mountPath, $childPowerShell, $chromium, $moniker, $profileFolder, $false, 0, 0)
'''
        self.assertEqual(controller.count(block), 1, 'Actual ordinary output and every fatal gate must precede reviewed code')
        self.assertEqual(controller.count('$preflightText = '), 1, 'Diagnostic output cannot substitute for fresh admission')
        self.assertEqual(controller.count('$preflight = '), 1, 'Admission must validate that same ordinary output')
        self.assertNotIn('RequireAdmission', controller)
        self.assertNotIn('$originalAdmissionExit', controller)

    def test_csr_host_launch_preserves_aggregate_containment_prerequisites(self):
        windows = ROOT / 'tests/security/windows'
        source = (windows / 'CsrDispatchObservation.cs').read_text(encoding='utf-8')
        aggregate = '''        internal static void RequireDispatchHostPositive(string python)
        { RequireResourceHostPositive(python); Need(dispatchHostPositive); }'''
        launch = '''        public static void RunDispatchHost(string python)
        {
            RequireHostPositive(python, SelfActivationRole.ExplicitId2); Need(!dispatchHostPositive);'''
        self.assertEqual(source.count(aggregate), 1, 'Contained CSR must retain entry/resource and its own host positives')
        self.assertEqual(source.count(launch), 1, 'CSR host launch must retain the strict undebugged ExplicitId2 positive')
        controller = (windows / 'Run-WindowsSecurity.ps1').read_text(encoding='utf-8')
        start = controller.index('    [ScientificSecurity.ChildActivationFixture]::RunDllHost($childPython)')
        end = controller.index("    Write-RunLog INFO 'fixed no-CRT native startup differential starts; never an admission control'", start)
        self.assertEqual(controller[start:end], '''    [ScientificSecurity.ChildActivationFixture]::RunDllHost($childPython)
    [ScientificSecurity.SelfActivationFixture]::RunHost($childPython)
    [ScientificSecurity.SelfActivationFixture]::RunDispatchHost($childPython)
    [ScientificSecurity.ModuleActivationFixture]::RunDispatchHost($childPython)
    [ScientificSecurity.SelfActivationFixture]::RunEntryHost($childPython)
    [ScientificSecurity.SelfActivationFixture]::RunResourceHost($childPython)
''', 'All host gates must remain unconditional and fatal before contained work')

    def test_preparation_failures_use_one_ordered_controller_boundary(self):
        windows = ROOT / 'tests/security/windows'
        controller = (windows / 'Run-WindowsSecurity.ps1').read_text(encoding='utf-8')
        source = (windows / 'PythonActivationPreparation.cs').read_text(encoding='utf-8')
        self.assertEqual(source.count('return RegistryStartupComparison.PreserveFailure(PreserveFailure(CsrDispatchComparison.PreserveFailure(RegistryCausalComparison.PreserveCallbackFailure(later))));'), 1)
        self.assertEqual(source.count('Exception failure = PreserveAllFailures(null); if (failure != null) throw failure;'), 1)
        start = controller.index('    $cause = $_.Exception\n')
        end = controller.index('    $staticReport = ', start)
        self.assertEqual(controller[start:end], '''    $cause = $_.Exception
    if ('ScientificSecurity.PythonActivationPreparation' -as [type]) {
        $cause = [ScientificSecurity.PythonActivationPreparation]::PreserveAllFailures($cause)
        $failure = [Management.Automation.ErrorRecord]::new($cause, 'WindowsSecurityFailure', [Management.Automation.ErrorCategory]::NotSpecified, $null)
    }
''', 'Later preservers must not prepend already-consumed failures out of chronological order')


class RegistryAuthorityValidationTest(unittest.TestCase):
    def test_bootstrap_import_failures_are_private_and_nonzero(self):
        import builtins
        import io
        from types import SimpleNamespace
        source = (ROOT / 'tests/security/windows/RegistryAuthorityProbe.py').read_text(encoding='utf-8')
        code = compile(source, 'fixed-registry-authority', 'exec')
        imports = ('ctypes', 'ctypes.wintypes', 'json', 'os', 'pathlib', 'runpy', 'subprocess', 'time')
        for selected in imports:
            for descendant in (False, True):
                for error, category in ((ImportError('private-import-sentinel'), 'import-absent'),
                                        (OSError('private-native-sentinel'), 'native'),
                                        (ValueError('private-other-sentinel'), 'other')):
                    output = io.StringIO()
                    system = SimpleNamespace(argv=['fixed.py'] + (['--descendant'] if descendant else []), stderr=output)
                    seen = []

                    def importer(name, *args, **kwargs):
                        if name == 'sys':
                            return system
                        self.assertIn(name, imports)
                        seen.append(name)
                        if name == selected:
                            raise error
                        return SimpleNamespace(Path=object(), wintypes=SimpleNamespace())

                    namespace = {'__name__': '__main__', '__builtins__': dict(vars(builtins), __import__=importer)}
                    with self.subTest(module=selected, descendant=descendant, category=category), self.assertRaises(SystemExit) as caught:
                        exec(code, namespace)
                    self.assertEqual(caught.exception.code, 1)
                    role = 'descendant' if descendant else 'primary'
                    expected = 'REGISTRY_AUTHORITY_FAILURE role=' + role + ' child_exit=none errors=import-' + selected.replace('.', '-') + ':' + category + '\n'
                    self.assertEqual(output.getvalue(), expected)
                    self.assertEqual(seen, list(imports[:imports.index(selected) + 1]))
                    self.assertNotIn('private', output.getvalue())
        class BrokenReport:
            def write(self, _):
                raise OSError('private-report-sentinel')
            def flush(self):
                raise AssertionError('unreachable flush')
        system.stderr = BrokenReport()
        with self.assertRaises(SystemExit) as caught:
            exec(code, namespace)
        self.assertEqual(caught.exception.code, 1)

    def test_bootstrap_reported_import_name_is_closed_metadata(self):
        import builtins
        import io
        from types import SimpleNamespace
        source = (ROOT / 'tests/security/windows/RegistryAuthorityProbe.py').read_text(encoding='utf-8')
        code = compile(source, 'fixed-registry-authority', 'exec')

        class HostileName(str):
            def __hash__(self):
                raise AssertionError('Private name must not be hashed')
            def __eq__(self, _):
                raise AssertionError('Private name must not be compared')

        class CustomImport(ImportError):
            @property
            def name(self):
                raise AssertionError('Custom exception metadata must not be read')

        names = [('_ctypes', 'ctypes-native'), ('ctypes', 'ctypes'), ('struct', 'struct'),
                 ('_struct', 'struct-native'), ('ctypes._endian', 'endian'), ('os', 'os'), ('types', 'types'),
                 (None, 'absent'), ('private-name-sentinel', 'unrecognized'), (b'_ctypes', 'unrecognized'),
                 (1, 'unrecognized'), (True, 'unrecognized'), (HostileName('_ctypes'), 'unrecognized')]
        cases = [(kind('private-message-sentinel', name=name, path='private-path-sentinel'), prefix + label)
                 for kind, prefix in ((ImportError, 'import-'), (ModuleNotFoundError, 'missing-')) for name, label in names]
        cases.append((CustomImport('private-subclass-sentinel'), 'import-unrecognized'))
        messages = [('Access is denied.', 'denied'), ('The specified module could not be found.', 'module'),
                    ('The specified procedure could not be found.', 'procedure'),
                    ('A dynamic link library (DLL) initialization routine failed.', 'init'),
                    ('Not enough memory resources are available to process this command.', 'memory'),
                    ('%1 is not a valid Win32 application.', 'format')]
        prefix = 'DLL load failed while importing _ctypes: '
        for body, label in messages:
            text = prefix + body
            cases.append((ImportError(text, name='_ctypes', path='private-path-sentinel'), 'import-ctypes-' + label))
            for altered in (text + ' ', 'private-prefix' + text, text + '\r\n', body, text[:-1],
                            HostileName(text), text.encode('ascii'), None, 1, True):
                cases.append((ImportError(altered, name='_ctypes'), 'import-ctypes-native'))
            cases.append((ModuleNotFoundError(text, name='_ctypes'), 'missing-ctypes-native'))
            cases.append((ImportError(text, name='ctypes'), 'import-ctypes'))
        cases.append((ImportError('بارگذاری ناموفق', name='_ctypes'), 'import-ctypes-native'))
        for error, expected in cases:
            for descendant in (False, True):
                output = io.StringIO()
                system = SimpleNamespace(argv=['fixed.py'] + (['--descendant'] if descendant else []), stderr=output)

                def importer(name, *args, **kwargs):
                    if name == 'sys':
                        return system
                    if name == 'ctypes':
                        raise error
                    self.assertEqual(name, 'importlib.machinery')
                    raise ImportError('private-support-sentinel')

                namespace = {'__name__': '__main__', '__builtins__': dict(vars(builtins), __import__=importer)}
                with self.subTest(category=expected, descendant=descendant), self.assertRaises(SystemExit) as caught:
                    exec(code, namespace)
                self.assertEqual(caught.exception.code, 1)
                role = 'descendant' if descendant else 'primary'
                tail = ('REGISTRY_LOADER_FOLLOWUP role=' + role + ' errors=loader:unqualified\n'
                        if type(error) is ImportError and type(error.name) is str and error.name == '_ctypes' else '')
                self.assertEqual(output.getvalue(), 'REGISTRY_AUTHORITY_FAILURE role=' + role +
                                 ' child_exit=none errors=import-ctypes:' + expected + '\n' + tail)
                self.assertLessEqual(len(output.getvalue().encode('ascii')), 512)
                self.assertNotIn('private', output.getvalue())
        for fail_flush in (False, True):
            class BrokenReport(io.StringIO):
                def write(self, text):
                    if not fail_flush:
                        raise OSError('private-report-sentinel')
                    return super().write(text)
                def flush(self):
                    raise OSError('private-flush-sentinel')
            system.stderr = BrokenReport()
            with self.assertRaises(SystemExit) as caught:
                exec(code, namespace)
            self.assertEqual(caught.exception.code, 1)

    def test_fixed_controls_without_native_execution(self):
        probe = runpy.run_path(str(ROOT / 'tests/security/windows/RegistryAuthorityProbe.py'))
        denied, basic = probe['require_denied'], probe['require_basic']
        token, identity = probe['require_token_fields'], probe['read_identity']
        key = r'\Registry\MACHINE\Software\Microsoft\Windows\CurrentVersion\SideBySide'
        encoded = key.encode('utf-16-le', errors='strict')
        data = b'\x8c\0\0\0' + encoded
        self.assertEqual(len(encoded), 140)
        self.assertEqual(identity(0, 144, data, 140), key)
        token(1, 0, 1)
        basic(0, 56, 0, 0x20019)
        denied(0xC0000022, None)
        cases = [
            lambda: token(2, 0, 1), lambda: token(1, 1, 1), lambda: token(1, 0, 0),
            lambda: basic(1, 56, 0, 0x20019), lambda: basic(0, 55, 0, 0x20019),
            lambda: basic(0, 56, 2, 0x20019), lambda: basic(0, 56, 0, 0xF003F),
            lambda: denied(0, None), lambda: denied(0xC0000022, 4), lambda: denied(0xC0000034, None),
            lambda: identity(1, 144, data, 140), lambda: identity(0, 143, data, 140),
            lambda: identity(0, 4097, data, 140), lambda: identity(0, 144, data, 138),
            lambda: identity(0, 144, b'\x8b\0\0\0' + encoded, 140),
            lambda: identity(0, 144, b'\x8c\0\0\0' + encoded[:-2] + b'\0\0', 140),
            lambda: identity(0, 144, b'\x8c\0\0\0' + encoded[:-2] + b'\0\xd8', 140),
        ]
        for index, case in enumerate(cases):
            with self.subTest(case=index), self.assertRaises((probe['Failure'], UnicodeError)):
                case()
        operation, cleanup = RuntimeError('operation'), RuntimeError('cleanup')
        attempted = []

        def fail():
            attempted.append('close')
            raise cleanup

        with self.assertRaises(probe['Failure']) as caught:
            probe['finish'](operation, [fail, lambda: attempted.append('second')])
        self.assertEqual(attempted, ['close', 'second'])
        self.assertEqual(caught.exception.events, (('start', 'control'), ('close', 'cleanup')))
        self.assertIs(caught.exception.original.exceptions[0].original, operation)
        self.assertIs(caught.exception.original.exceptions[1].original, cleanup)

    def test_failure_projection_preserves_exits_order_and_privacy(self):
        import subprocess
        probe = runpy.run_path(str(ROOT / 'tests/security/windows/RegistryAuthorityProbe.py'))
        reports = []
        wire = 'REGISTRY_AUTHORITY_FAILURE role=descendant child_exit=none errors=root:control,close:cleanup\n'

        def child_failure():
            probe['descendant_result'](subprocess.CompletedProcess([], 7, '', wire))

        self.assertEqual(probe['entry'](child_failure, reports.append, 'primary'), 1)
        self.assertEqual(reports.pop(), 'REGISTRY_AUTHORITY_FAILURE role=primary child_exit=00000007 errors=descendant:transport,root:control,close:cleanup\n')
        for category in ('import-ctypes-native', 'missing-struct-native', 'import-absent', 'missing-unrecognized',
                         'import-ctypes-denied', 'import-ctypes-module', 'import-ctypes-procedure',
                         'import-ctypes-init', 'import-ctypes-memory', 'import-ctypes-format'):
            frame = 'REGISTRY_AUTHORITY_FAILURE role=descendant child_exit=none errors=import-ctypes:' + category + '\n'
            with self.assertRaises(probe['Failure']) as caught:
                probe['descendant_result'](subprocess.CompletedProcess([], 1, '', frame))
            expected = ((('import-ctypes', category), ('descendant', 'transport'))
                        if category in ('import-ctypes-native', 'import-ctypes-denied', 'import-ctypes-module',
                                        'import-ctypes-procedure', 'import-ctypes-init', 'import-ctypes-memory', 'import-ctypes-format')
                        else (('descendant', 'transport'), ('import-ctypes', category)))
            self.assertEqual(caught.exception.events, expected)
            self.assertEqual(caught.exception.child_exit, 1)
        for events in (','.join(['import-ctypes:import-absent'] * 7), ','.join(['import-ctypes:import-absent'] * 8),
                       'import-ctypes:import-private', 'import-ctypes:missing-private'):
            frame = 'REGISTRY_AUTHORITY_FAILURE role=descendant child_exit=none errors=' + events + '\n'
            with self.assertRaises(probe['Failure']) as caught:
                probe['descendant_result'](subprocess.CompletedProcess([], 7, '', frame))
            self.assertEqual(len(caught.exception.events), 8 if events.count(',') == 6 else 1)
            self.assertEqual(caught.exception.child_exit, 7)
        with self.assertRaises(probe['Failure']) as caught:
            probe['descendant_result'](subprocess.CompletedProcess([], 7, '', 'x' * 513))
        self.assertEqual(caught.exception.events, (('descendant', 'transport'),))
        for error, kind in [(subprocess.TimeoutExpired('private-command-sentinel', 5, output=b'private-output-sentinel'), 'timeout'),
                            (UnicodeDecodeError('utf-16-le', b'\x37\xd8', 0, 2, 'private-decode-sentinel'), 'decode')]:
            def operation():
                raise error
            self.assertEqual(probe['entry'](operation, reports.append, 'primary'), 1)
            report = reports.pop()
            self.assertEqual(report, 'REGISTRY_AUTHORITY_FAILURE role=primary child_exit=none errors=start:' + kind + '\n')
            self.assertNotIn('private', report)
        def malformed_child():
            probe['descendant_result'](subprocess.CompletedProcess([], 0xC0000022, '', 'private-stderr-sentinel'))
        self.assertEqual(probe['entry'](malformed_child, reports.append, 'primary'), 1)
        self.assertEqual(reports.pop(), 'REGISTRY_AUTHORITY_FAILURE role=primary child_exit=C0000022 errors=descendant:transport\n')
        def operation_cleanup_failure():
            probe['finish'](probe['Failure']((('root', 'control'),)), [lambda: (_ for _ in ()).throw(OSError('private-close-sentinel'))])
        self.assertEqual(probe['entry'](operation_cleanup_failure, reports.append, 'primary'), 1)
        self.assertEqual(reports.pop(), 'REGISTRY_AUTHORITY_FAILURE role=primary child_exit=none errors=root:control,close:cleanup\n')
        import io
        record = {'role': 'primary'}
        child = subprocess.CompletedProcess([], 0, '{"role":"descendant"}\n', '')
        for flush_failure in (False, True):
            class BrokenOutput(io.StringIO):
                def write(self, text):
                    if not flush_failure:
                        raise OSError('private-output-sentinel')
                    return super().write(text)

                def flush(self):
                    raise OSError('private-flush-sentinel')

            def completed_child_reporting():
                probe['complete_descendant'](child, record, BrokenOutput())

            self.assertEqual(probe['entry'](completed_child_reporting, reports.append, 'primary'), 1)
            self.assertEqual(reports.pop(), 'REGISTRY_AUTHORITY_FAILURE role=primary child_exit=00000000 errors=report:native\n')
        def broken_report(_):
            raise OSError('private-report-sentinel')
        with self.assertRaises(probe['Failure']) as caught:
            probe['entry'](child_failure, broken_report, 'primary')
        self.assertEqual(caught.exception.child_exit, 7)
        self.assertEqual(caught.exception.events[-1], ('report', 'other'))
        self.assertNotIn('private', str(caught.exception))


@unittest.skipUnless(sys.platform == 'win32', 'Windows PowerShell preparation functions')
class RuntimePreparationTest(unittest.TestCase):
    def test_streaming_validation_copy_progress_and_refusal(self):
        shell = shutil.which('pwsh')
        self.assertIsNotNone(shell, 'PowerShell 7 is required on Windows')
        (ROOT / '.scratch').mkdir(exist_ok=True)
        with tempfile.TemporaryDirectory(prefix='runtime preparation ', dir=ROOT / '.scratch') as directory:
            result = owned_run([
                shell, '-NoLogo', '-NoProfile', '-NonInteractive', '-File',
                str(ROOT / 'tests/security/windows/Check-RuntimePreparation.ps1'),
                '-Root', str(ROOT), '-Work', directory,
            ], timeout=15, cwd=ROOT)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('RUNTIME_PREPARATION_FUNCTIONS_OK native_methods_invoked=false', result.stdout)


if __name__ == '__main__':
    unittest.main()
