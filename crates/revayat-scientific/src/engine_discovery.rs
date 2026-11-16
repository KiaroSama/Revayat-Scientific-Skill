//! Ordered, request-scoped PDF backend discovery shared by production and pure checks.
//!
//! An available engine retains its own capability. In particular, WeasyPrint is
//! an optional external renderer and is never an alias for Chromium.
use anyhow::{Result, ensure};
use std::{ffi::OsString, path::Path, time::Duration};

/// Production adapters retain the resolved renderer/container capability; pure
/// checks use per-call doubles at exactly these four external boundaries.
pub trait Probes {
    type Tex;
    type Browser;
    type Weasyprint;

    fn tex(&mut self) -> Result<Option<Self::Tex>>;
    fn browser(&mut self) -> Result<Option<Self::Browser>>;
    fn chromium(&mut self, browser: &Self::Browser) -> Result<bool>;
    fn weasyprint(&mut self) -> Result<Option<Self::Weasyprint>>;
}

#[derive(Debug)]
pub struct Available<Tex, Browser, Weasyprint> {
    /// Discovery preference order, which is significant for automatic selection.
    pub engines: Vec<&'static str>,
    pub tex: Option<Tex>,
    pub browser: Option<Browser>,
    pub weasyprint: Option<Weasyprint>,
}

/// Preserve Get-AvailableEngines' exact short-circuit order. An unavailable
/// explicit engine produces an empty inventory and never probes a fallback.
/// Operational errors propagate so failed cleanup cannot masquerade as absence.
pub fn available_engines<P: Probes>(
    requested: Option<&str>,
    probes: &mut P,
) -> Result<Available<P::Tex, P::Browser, P::Weasyprint>> {
    let requested = requested.unwrap_or("auto");
    ensure!(
        ["auto", "tex", "chromium", "weasyprint"].contains(&requested),
        "PDF engine must be auto, tex, chromium or weasyprint"
    );
    let mut available = Available {
        engines: Vec::new(),
        tex: None,
        browser: None,
        weasyprint: None,
    };
    if (requested == "auto" || requested == "tex")
        && let Some(tex) = probes.tex()?
    {
        available.engines.push("tex");
        available.tex = Some(tex);
    }
    if (requested == "auto" || requested == "chromium")
        && let Some(browser) = probes.browser()?
        && probes.chromium(&browser)?
    {
        available.engines.push("chromium");
        available.browser = Some(browser);
    }
    if (requested == "auto" || requested == "weasyprint")
        && let Some(weasyprint) = probes.weasyprint()?
    {
        available.engines.push("weasyprint");
        available.weasyprint = Some(weasyprint);
    }
    Ok(available)
}

pub const PROBE_TIMEOUT: Duration = Duration::from_secs(15);
pub const PROBE_MAX_OUTPUT: usize = 64 * 1024;

/// Execute a resolved tool's readiness command without a shell, with bounded
/// diagnostics and owned process cleanup. Missing executables/nonzero exits are
/// unavailable; timeout, output-budget and cleanup failures remain errors.
///
/// The caller supplies the real adapter's arguments (for example `--version`
/// for an external WeasyPrint executable, or a container's capability command).
pub fn probe_executable(
    program: &Path,
    args: impl IntoIterator<Item = impl Into<OsString>>,
) -> Result<bool> {
    ensure!(
        program.is_absolute(),
        "engine probe executable must be resolved"
    );
    let mut spec = crate::runtime::CommandSpec::new(program.as_os_str()).args(args);
    spec.timeout = PROBE_TIMEOUT;
    spec.max_output = PROBE_MAX_OUTPUT;
    match crate::runtime::run(&spec) {
        Ok(output) => Ok(output.success()),
        Err(error) if crate::runtime::is_missing_executable(&error) => Ok(false),
        Err(error) => Err(error),
    }
}
