//! Narrow observer for the existing suspended, qualified authority. No arbitrary process hook.
use super::*;
pub(crate) trait AuthorityObserver {
    fn default_policy(&mut self, _primary: &[u8], _duplicate: &[u8]) -> Result<()> {
        Ok(())
    }
    fn registry_status(&mut self, _status: i32) -> Result<()> {
        Ok(())
    }
    fn prepare(&mut self, package: &str) -> Result<()>;
    fn before_create(&mut self) -> Result<()>;
    fn token_metadata(&mut self, record: &str) -> Result<()> {
        // This is host diagnostic output, not either of the two child authority records.
        // println preserves libtest capture; direct handle writes corrupt its case protocol.
        // Broken output must return through the authority's explicit reap/cleanup path.
        std::panic::catch_unwind(|| match record {
            "" => println!(),
            _ => println!("{record}"),
        })
        .map_err(|_| anyhow::anyhow!("default-DACL diagnostic output failed"))?;
        std::io::stdout().flush()?;
        Ok(())
    }
    fn startup_token(&mut self, lines: &[String]) -> Result<()> {
        ensure!(lines.len() <= 2, "token-query observation count exceeded");
        for record in lines {
            self.token_metadata(record)?;
        }
        Ok(())
    }
    fn startup_registry(&mut self, lines: &[String]) -> Result<()> {
        ensure!(lines.len() <= 2, "registry observation count exceeded");
        for record in lines {
            self.token_metadata(record)?;
        }
        Ok(())
    }
    fn before_resume(&mut self, process: Handle, package: &str, image: &Path) -> Result<()>;
    fn after_reap(&mut self, reaped: bool) -> Result<()>;
}
pub(super) struct NoObserver;
impl AuthorityObserver for NoObserver {
    fn prepare(&mut self, _: &str) -> Result<()> {
        Ok(())
    }
    fn before_create(&mut self) -> Result<()> {
        Ok(())
    }
    fn before_resume(&mut self, _: Handle, _: &str, _: &Path) -> Result<()> {
        Ok(())
    }
    fn after_reap(&mut self, _: bool) -> Result<()> {
        Ok(())
    }
}
