//! Closed arguments/environment for native kernel worker roles; records alone prove no host gate.
use super::quota_controls::{self as quota, OwnerInventory, WorkerPlan};
use anyhow::{Result, ensure};
use std::{collections::BTreeMap, path::PathBuf};
#[path = "kernel_validation.rs"]
mod validation;
pub use validation::check_validation;
pub const WALL_MARKER: &[u8] = b"trusted wall-tree negative control started\n";
pub const PROCESS_MEMORY: u64 = 384 * 1024 * 1024;
pub const JOB_MEMORY: u64 = 512 * 1024 * 1024;
pub const JOB_CPU_TICKS: i64 = 30 * 10_000_000;
pub const JOB_FLAGS: u32 = 0x230c;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Role {
    KernelPrimary,
    KernelWall,
    TokenChild,
    PidHold,
    PidExtra,
    WallHold,
}
impl Role {
    pub fn argument(self) -> &'static str {
        match self {
            Self::KernelPrimary => "--kernel-primary",
            Self::KernelWall => "--kernel-wall",
            Self::TokenChild => "--kernel-token-child",
            Self::PidHold => "--kernel-pid-hold",
            Self::PidExtra => "--kernel-pid-extra",
            Self::WallHold => "--kernel-wall-hold",
        }
    }
    pub fn parse(value: &str) -> Result<Self> {
        Ok(match value {
            "--kernel-primary" => Self::KernelPrimary,
            "--kernel-wall" => Self::KernelWall,
            "--kernel-token-child" => Self::TokenChild,
            "--kernel-pid-hold" => Self::PidHold,
            "--kernel-pid-extra" => Self::PidExtra,
            "--kernel-wall-hold" => Self::WallHold,
            _ => anyhow::bail!("unsupported fixed kernel role"),
        })
    }
}
#[derive(Clone)]
pub struct KernelPlan {
    pub role: Role,
    pub quota: WorkerPlan,
    pub system_root: PathBuf,
    pub chromium: PathBuf,
    pub tcp_port: u16,
    pub udp_port: u16,
}
fn text(path: &std::path::Path) -> Result<&str> {
    let text = path
        .to_str()
        .ok_or_else(|| anyhow::anyhow!("kernel path is not Unicode"))?;
    let bytes = text.as_bytes();
    ensure!(
        bytes.len() >= 3
            && bytes[0].is_ascii_alphabetic()
            && &bytes[1..3] == b":\\"
            && !text.contains(['\0', '"', '/', ';'])
            && text.encode_utf16().count() < 512
            && text[3..]
                .split('\\')
                .all(|part| part != "." && part != ".."),
        "kernel fixed path differs"
    );
    Ok(text)
}
impl KernelPlan {
    pub fn validate(&self) -> Result<()> {
        self.quota.validate()?;
        ensure!(
            self.quota.role == quota::Role::Primary && self.tcp_port > 0 && self.udp_port > 0,
            "kernel plan role/ports differ"
        );
        text(&self.system_root)?;
        text(&self.chromium)?;
        text(&self.quota.readonly_root)?;
        text(&self.quota.auxiliary_image)?;
        Ok(())
    }
    pub fn arguments(&self, role: Role) -> Result<Vec<String>> {
        self.validate()?;
        let mut args = self.quota.arguments(quota::Role::Primary)?;
        args[0] = role.argument().into();
        args.extend([
            text(&self.system_root)?.into(),
            text(&self.chromium)?.into(),
            self.tcp_port.to_string(),
            self.udp_port.to_string(),
        ]);
        Ok(args)
    }
    pub fn parse(args: &[String]) -> Result<Self> {
        ensure!(args.len() == 12, "kernel worker argument count differs");
        let role = Role::parse(&args[0])?;
        let mut quota_args = args[..8].to_vec();
        quota_args[0] = quota::Role::Primary.argument().into();
        let port = |value: &str| -> Result<u16> {
            let port = value
                .parse::<u16>()
                .map_err(|_| anyhow::anyhow!("kernel port is outside bound"))?;
            ensure!(
                port > 0 && value == port.to_string(),
                "kernel port is noncanonical"
            );
            Ok(port)
        };
        let value = Self {
            role,
            quota: WorkerPlan::parse(&quota_args)?,
            system_root: args[8].clone().into(),
            chromium: args[9].clone().into(),
            tcp_port: port(&args[10])?,
            udp_port: port(&args[11])?,
        };
        value.validate()?;
        Ok(value)
    }
    pub fn environment(&self) -> Result<BTreeMap<String, String>> {
        self.validate()?;
        let home = format!("{}home", self.quota.scratch);
        let temp = format!("{}temp", self.quota.scratch);
        let auxiliary = text(&self.quota.auxiliary_image)?
            .rsplit_once('\\')
            .ok_or_else(|| anyhow::anyhow!("kernel auxiliary parent is absent"))?
            .0;
        Ok([
            ("SYSTEMROOT", text(&self.system_root)?.into()),
            ("WINDIR", text(&self.system_root)?.into()),
            (
                "PATH",
                format!("{};{auxiliary}", text(&self.quota.readonly_root)?),
            ),
            ("HOME", home.clone()),
            ("USERPROFILE", home.clone()),
            ("LOCALAPPDATA", home.clone()),
            ("APPDATA", home.clone()),
            ("TEMP", temp.clone()),
            ("TMP", temp),
            ("PYTHONIOENCODING", "utf-8".into()),
            ("REVAYAT_CHROMIUM", text(&self.chromium)?.into()),
            ("DOTNET_CLI_HOME", home.clone()),
            ("XDG_CACHE_HOME", format!("{home}\\cache")),
        ]
        .into_iter()
        .map(|(name, value)| (name.into(), value))
        .collect())
    }
    pub fn arguments_digest(&self, role: Role) -> Result<String> {
        Ok(crate::windows_security::image::sha256(
            self.arguments(role)?.join("\0").as_bytes(),
        ))
    }
    pub fn environment_digest(&self) -> Result<String> {
        Ok(crate::windows_security::image::sha256(
            self.environment()?
                .into_iter()
                .map(|(name, value)| format!("{name}={value}"))
                .collect::<Vec<_>>()
                .join("\0")
                .as_bytes(),
        ))
    }
    /// Exact double-NUL terminated Unicode block, never a host-environment copy.
    pub fn environment_block(&self) -> Result<Vec<u16>> {
        let mut out = Vec::new();
        for (name, value) in self.environment()? {
            ensure!(!value.contains('\0'), "kernel environment contains NUL");
            out.extend(name.encode_utf16());
            out.push(61);
            out.extend(value.encode_utf16());
            out.push(0);
        }
        ensure!(out.len() < 32766, "kernel environment exceeds native bound");
        out.push(0);
        Ok(out)
    }
}
pub(crate) fn primary_record(plan: &KernelPlan, inventory: &OwnerInventory) -> Result<String> {
    Ok(format!(
        "WINDOWS_KERNEL_CONTROL role=primary run={} status=passed arguments_sha256={} environment_sha256={} owner_count={} owner_digest={} environment=True readonly_files=True profile_registry=True network=True job_limits=True memory_denied=True pids_denied=True quota=True runtime=rust quota_bytes=16777216 process_memory_mib=384 job_memory_mib=512 cpu_rate=1000 pids=8\n",
        plan.quota.run,
        plan.arguments_digest(Role::KernelPrimary)?,
        plan.environment_digest()?,
        inventory.owner_count(),
        inventory.digest()
    ))
}
pub fn require_primary_record(
    bytes: &[u8],
    plan: &KernelPlan,
    inventory: &OwnerInventory,
) -> Result<()> {
    plan.validate()?;
    ensure!(
        plan.role == Role::KernelPrimary
            && bytes.len() <= 2048
            && bytes.is_ascii()
            && bytes == primary_record(plan, inventory)?.as_bytes(),
        "kernel primary record differs from exact prepared plan/inventory"
    );
    Ok(())
}
