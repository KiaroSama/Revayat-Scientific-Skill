"""Exercise trusted preparation functions, not the native security entry point."""
from pathlib import Path
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
"""
        anchors = (
            '[ScientificSecurity.PythonStartupFixture]::Prepare($runId, $state)',
            '[ScientificSecurity.PythonCsrDispatch]::Prepare($runId, $state)',
            '    Protect-Tree $runtime\n',
            '[ScientificSecurity.StaticKernelInspection]::RunFixed($state)',
            '[ScientificSecurity.StaticKernelInspection]::RunActivationWorker($state)',
            python_block,
            '[ScientificSecurity.PythonActivationPreparation]::Run($runId, $state, $childPython, $target, $mountPath, $childPowerShell, $chromium, $moniker, $profileFolder, $tcpPort, $udpPort)',
            '[ScientificSecurity.DefaultDaclComparison]::Run($runId, $state, $childPython, $target, $mountPath, $childPowerShell, $chromium, $moniker, $profileFolder, $tcpPort, $udpPort)',
            '[ScientificSecurity.DebugControl]::RunFixed($runId, $state)',
            '[ScientificSecurity.ChildActivationFixture]::RunDllHost($childPython)',
            '[ScientificSecurity.SelfActivationFixture]::RunHost($childPython)',
            '[ScientificSecurity.SelfActivationFixture]::RunDispatchHost($childPython)',
            '[ScientificSecurity.ModuleActivationFixture]::RunDispatchHost($childPython)',
            '[ScientificSecurity.PythonCsrDispatch]::RunHost($childPython)',
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
            '$originalAdmissionExit = [ScientificSecurity.RegistryCausalComparison]::Run(',
            '$preflightText = [ScientificSecurity.Sandbox]::Run(',
            '[ScientificSecurity.PythonActivationPreparation]::RequireClean()',
            '[ScientificSecurity.CsrDispatchComparison]::RequireClean()',
            '[ScientificSecurity.RegistryCausalComparison]::RequireAdmission($originalAdmissionExit)',
            "if ($preflight.status -ne 'passed' -or $preflight.phase -ne 'preflight')",
            '$wall = [ScientificSecurity.Sandbox]::Run(',
            '$regressionText = [ScientificSecurity.Sandbox]::Run(',
        )
        for anchor in anchors:
            self.assertEqual(controller.count(anchor), 1, 'Missing, duplicated or altered diagnostic/admission step')
        positions = [controller.index(anchor) for anchor in anchors]
        self.assertEqual(positions, sorted(positions), 'Python diagnostic cleanup must precede debugger controls without bypassing later gates')

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
    [ScientificSecurity.PythonCsrDispatch]::RunHost($childPython)
    [ScientificSecurity.SelfActivationFixture]::RunEntryHost($childPython)
    [ScientificSecurity.SelfActivationFixture]::RunResourceHost($childPython)
''', 'All host gates must remain unconditional and fatal before contained work')

    def test_preparation_failures_use_one_ordered_controller_boundary(self):
        windows = ROOT / 'tests/security/windows'
        controller = (windows / 'Run-WindowsSecurity.ps1').read_text(encoding='utf-8')
        source = (windows / 'PythonActivationPreparation.cs').read_text(encoding='utf-8')
        self.assertEqual(source.count('return PreserveFailure(CsrDispatchComparison.PreserveFailure(RegistryCausalComparison.PreserveCallbackFailure(later)));'), 1)
        self.assertEqual(source.count('Exception failure = PreserveAllFailures(null); if (failure != null) throw failure;'), 1)
        start = controller.index('    $cause = $_.Exception\n')
        end = controller.index('    $staticReport = ', start)
        self.assertEqual(controller[start:end], '''    $cause = $_.Exception
    if ('ScientificSecurity.PythonActivationPreparation' -as [type]) {
        $cause = [ScientificSecurity.PythonActivationPreparation]::PreserveAllFailures($cause)
        $failure = [Management.Automation.ErrorRecord]::new($cause, 'WindowsSecurityFailure', [Management.Automation.ErrorCategory]::NotSpecified, $null)
    }
''', 'Later preservers must not prepend already-consumed failures out of chronological order')


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
