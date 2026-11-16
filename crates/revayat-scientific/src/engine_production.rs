//! Real bounded adapters for the ordered backend discovery controller.
use crate::{
    engine_discovery::{Available, Probes, available_engines},
    tex_container::RuntimeConfig,
};
use anyhow::Result;
use std::path::PathBuf;

struct Production<'a> {
    browser: Option<&'a str>,
    requested: Option<&'a str>,
    readiness: bool,
    container_checked: bool,
    container: Option<RuntimeConfig>,
}
impl Production<'_> {
    fn container(&mut self) -> Result<Option<RuntimeConfig>> {
        if !self.container_checked {
            self.container_checked = true;
            self.container = match crate::tex_container::runtime_config() {
                Ok(config) => Some(config),
                Err(error)
                    if self
                        .requested
                        .is_some_and(|engine| engine == "tex" || engine == "weasyprint") =>
                {
                    return Err(error);
                }
                Err(error)
                    if error
                        .downcast_ref::<crate::runtime::CleanupFailure>()
                        .is_some()
                        || error
                            .downcast_ref::<crate::runtime::DeadlineExceeded>()
                            .is_some() =>
                {
                    return Err(error);
                }
                Err(_) => None,
            };
        }
        Ok(self.container.clone())
    }
}
impl Probes for Production<'_> {
    type Tex = RuntimeConfig;
    type Browser = PathBuf;
    type Weasyprint = RuntimeConfig;
    fn tex(&mut self) -> Result<Option<Self::Tex>> {
        self.container()
    }
    fn browser(&mut self) -> Result<Option<Self::Browser>> {
        match crate::render::discover_browser(self.browser) {
            Ok(browser) => Ok(Some(browser)),
            Err(error) if self.browser.is_some() => Err(error),
            Err(_) => Ok(None),
        }
    }
    fn chromium(&mut self, browser: &Self::Browser) -> Result<bool> {
        if !self.readiness {
            return Ok(true);
        }
        #[cfg(windows)]
        {
            // Windows GUI Chrome may keep running for --version. Qualify the
            // same owned headless endpoint used to render, rather than waiting
            // for that unrelated GUI invocation to exit.
            let scratch = tempfile::Builder::new()
                .prefix("revayat-engine-browser-")
                .tempdir()?;
            let ready = scratch
                .path()
                .canonicalize()
                .map_err(Into::into)
                .and_then(|parent| {
                    crate::render::preflight_browser(browser, &parent).map(|()| true)
                });
            crate::runtime::with_cleanup(ready, scratch.close().map_err(Into::into))
        }
        #[cfg(not(windows))]
        {
            crate::engine_discovery::probe_executable(browser, ["--version"])
        }
    }
    fn weasyprint(&mut self) -> Result<Option<Self::Weasyprint>> {
        let config = self.container()?;
        if !self.readiness {
            return Ok(config);
        }
        match config {
            Some(config) => crate::weasyprint_container::available(config),
            None => Ok(None),
        }
    }
}
pub(super) fn discover(
    requested: Option<&str>,
    browser: Option<&str>,
) -> Result<Available<RuntimeConfig, PathBuf, RuntimeConfig>> {
    inventory(requested, browser, true)
}

/// Resolve executable and immutable container configuration only. A build must
/// admit destinations and lint source before launching a renderer; the selected
/// renderer then performs its real readiness operation under that build guard.
pub(super) fn resolve(
    requested: Option<&str>,
    browser: Option<&str>,
) -> Result<Available<RuntimeConfig, PathBuf, RuntimeConfig>> {
    inventory(requested, browser, false)
}

fn inventory(
    requested: Option<&str>,
    browser: Option<&str>,
    readiness: bool,
) -> Result<Available<RuntimeConfig, PathBuf, RuntimeConfig>> {
    available_engines(
        requested,
        &mut Production {
            browser,
            requested,
            readiness,
            container_checked: false,
            container: None,
        },
    )
}
