//! Retain owned recovery before any fallible report and preserve the primary cause.
use crate::runtime;
use anyhow::{Context, Result};
use std::path::Path;
fn combined<T>(operation: Result<T>, secondary: anyhow::Error) -> anyhow::Error {
    match operation {
        Err(primary) => runtime::with_cleanup::<()>(Err(primary), Err(secondary)).unwrap_err(),
        Ok(_) => secondary,
    }
}
pub(crate) fn finish_stage<T>(
    stage: tempfile::TempDir,
    run_id: &str,
    operation: Result<T>,
    cleanup: Result<()>,
    acknowledge: impl FnOnce() -> Result<()>,
    report: impl FnOnce(&Path, &str) -> Result<()>,
) -> Result<(tempfile::TempDir, T)> {
    if let Err(error) = cleanup {
        let retained = stage.keep();
        let report_result = report(&retained, run_id);
        let secondary = runtime::with_cleanup::<()>(Err(error), report_result)
            .unwrap_err()
            .context(format!(
                "container cleanup failed; retained evidence: {}",
                retained.display()
            ));
        return Err(combined(operation, secondary));
    }
    if let Err(error) = acknowledge() {
        let retained = stage.keep();
        return Err(combined(
            operation,
            error.context(format!(
                "container receipt acknowledgement failed; retained evidence: {}",
                retained.display()
            )),
        ));
    }
    operation.map(|value| (stage, value))
}
pub(crate) fn recovery(directory: &Path, run_id: &str) -> Result<()> {
    std::fs::write(directory.join("recovery.json"),serde_json::to_vec_pretty(&serde_json::json!({
        "run_id":run_id,"container_name":format!("revayat-tex-{run_id}"),"status":"cleanup_not_verified"
    }))?).context("container recovery report could not be written")?;
    Ok(())
}
