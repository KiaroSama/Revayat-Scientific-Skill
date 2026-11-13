//! Real bounded adapters for the ordered backend discovery controller.
use crate::{
    engine_discovery::{Available, Probes, available_engines, probe_executable},
    tex_container::RuntimeConfig,
};
use anyhow::Result;
use std::path::PathBuf;

struct Production<'a> {
    browser: Option<&'a str>,
    requested: Option<&'a str>,
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
        probe_executable(browser, ["--version"])
    }
    fn weasyprint(&mut self) -> Result<Option<Self::Weasyprint>> {
        match self.container()? {
            Some(config) => crate::weasyprint_container::available(config),
            None => Ok(None),
        }
    }
}
pub(super) fn discover(
    requested: Option<&str>,
    browser: Option<&str>,
) -> Result<Available<RuntimeConfig, PathBuf, RuntimeConfig>> {
    available_engines(
        requested,
        &mut Production {
            browser,
            requested,
            container_checked: false,
            container: None,
        },
    )
}
