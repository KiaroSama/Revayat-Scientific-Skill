//! One protected canary owner shared by the kernel primary and wall plans.
use super::*;
const BYTES: &[u8] = b"fixed protected quota canary\n";
pub(in crate::windows_security::native) struct QuotaCanary {
    pin: Pin,
    run: String,
    state: ObjectId,
    host: String,
}
impl NativeRunView {
    pub(in crate::windows_security::native) fn bound_quota_canary(&self) -> Result<QuotaCanary> {
        let path = self.quota_canary()?; // CREATE_NEW remains mandatory and happens once.
        let pin = Pin::open(&path, false)?;
        let mut canary = QuotaCanary {
            pin,
            run: self.run_id().into(),
            state: self.state_identity(),
            host: self.manifest.host.clone(),
        };
        match canary.require(self) {
            Ok(()) => Ok(canary),
            Err(primary) => finish(Err(primary), canary.close()),
        }
    }
}
impl QuotaCanary {
    pub(in crate::windows_security::native) fn require(&self, view: &NativeRunView) -> Result<()> {
        view.require()?;
        ensure!(
            self.run == view.run_id()
                && self.state == view.state_identity()
                && self.host == view.manifest.host
                && self.pin.path == view.state.join("quota-host-canary"),
            "kernel canary belongs to another native run"
        );
        self.pin.require()?;
        private(
            self.pin.file.as_ref().context("kernel canary pin closed")?,
            &self.host,
            false,
        )?;
        ensure!(
            self.pin.read_bytes()? == BYTES,
            "kernel canary bytes changed"
        );
        Ok(())
    }
    pub(in crate::windows_security::native) fn path(&self) -> &Path {
        &self.pin.path
    }
    pub(in crate::windows_security::native) fn close(&mut self) -> Result<()> {
        self.pin.close()
    }
}
