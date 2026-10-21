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
    Write-RunLog INFO 'fixed byte-identical Python clone loader snaps starts; rename and debug perturbation remain noncausal'
    $diagnosticFailure = $null
    $cloneLease = [ScientificSecurity.PythonStartupFixture]::Hold($runId, $state)
    try {
        [ScientificSecurity.LoaderSnaps]::EnablePython($runId, $state)
        $cloneDiagnostic = [ScientificSecurity.Sandbox]::Run($childPython, $target, $mountPath, $childPowerShell, $chromium, $moniker, $profileFolder, $true, $tcpPort, $udpPort, $false, $true, $false, $true)
        Write-RunLog INFO $cloneDiagnostic
    }
    catch { $diagnosticFailure = $_.Exception; throw }
    finally { [ScientificSecurity.LoaderSnaps]::Cleanup($runId, $state, $diagnosticFailure, $cloneLease) }
    [ScientificSecurity.LoaderSnaps]::RequireClean($runId, $state)
"""
        anchors = (
            '[ScientificSecurity.PythonStartupFixture]::Prepare($runId, $state)',
            '    Protect-Tree $runtime\n',
            '[ScientificSecurity.StaticKernelInspection]::RunFixed($state)',
            '[ScientificSecurity.StaticKernelInspection]::RunActivationWorker($state)',
            python_block,
            '[ScientificSecurity.DebugControl]::RunFixed($runId, $state)',
            '[ScientificSecurity.ChildActivationFixture]::RunDllHost($childPython)',
            '[ScientificSecurity.SelfActivationFixture]::RunHost($childPython)',
            '[ScientificSecurity.SelfActivationFixture]::RunEntryHost($childPython)',
            '[ScientificSecurity.SelfActivationFixture]::RunResourceHost($childPython)',
            "[ScientificSecurity.LoaderSnaps]::Enable($runId, $state, (Join-Path (Split-Path $childPython) 'startup-native.exe'))",
            '$nativeDiagnostic = [ScientificSecurity.Sandbox]::Run($childPython, $target, $mountPath, $childPowerShell, $chromium, $moniker, $profileFolder, $true, $tcpPort, $udpPort, $false, $true, $true)',
            'finally { [ScientificSecurity.LoaderSnaps]::Cleanup($runId, $state, $diagnosticFailure) }\n'
            '    [ScientificSecurity.LoaderSnaps]::RequireClean($runId, $state)',
            "[Console]::Out.WriteLine('WINDOWS_INTERNAL_OBSERVATION site=",
            '[ScientificSecurity.ManualActivationComparison]::Run(',
            '[ScientificSecurity.ManualActivationComparison]::RunDllRequest(',
            '[ScientificSecurity.AutomaticResourceComparison]::Run(',
            '$originalAdmissionExit = [ScientificSecurity.RegistryCausalComparison]::Run(',
            '$preflightText = [ScientificSecurity.Sandbox]::Run(',
            '[ScientificSecurity.RegistryCausalComparison]::RequireAdmission($originalAdmissionExit)',
            "if ($preflight.status -ne 'passed' -or $preflight.phase -ne 'preflight')",
            '$wall = [ScientificSecurity.Sandbox]::Run(',
            '$regressionText = [ScientificSecurity.Sandbox]::Run(',
        )
        for anchor in anchors:
            self.assertEqual(controller.count(anchor), 1, 'Missing, duplicated or altered diagnostic/admission step')
        positions = [controller.index(anchor) for anchor in anchors]
        self.assertEqual(positions, sorted(positions), 'Python diagnostic cleanup must precede debugger controls without bypassing later gates')


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
