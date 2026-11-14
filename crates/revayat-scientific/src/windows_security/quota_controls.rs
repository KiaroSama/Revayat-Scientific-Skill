//! Closed contracts for actual native token-owner and NTFS quota observations.
//! Parsing these records does not establish that a native operation occurred.
use anyhow::{Result, ensure};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{fmt, path::PathBuf};
#[path = "quota_validation.rs"]
mod validation;
pub use validation::check_validation;

pub const QUOTA_BYTES: u64 = 16 * 1024 * 1024;
pub const VOLUME_BYTES: u64 = 128 * 1024 * 1024;
pub const OWNER_LIMIT: usize = 16;
pub const DESCENDANT_BYTES: usize = 65_535;

#[derive(Clone, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct Sid(Vec<u8>);
impl Sid {
    pub(crate) fn binary(bytes: &[u8]) -> Result<Self> {
        ensure!(
            bytes.len() >= 8
                && bytes[0] == 1
                && bytes[1] <= 15
                && bytes.len() == 8 + usize::from(bytes[1]) * 4,
            "invalid bounded quota SID"
        );
        Ok(Self(bytes.to_vec()))
    }
    pub(crate) fn text(value: &str) -> Result<Self> {
        ensure!(
            value.len() <= 184 && value.is_ascii(),
            "invalid quota SID text"
        );
        let parts = value.split('-').collect::<Vec<_>>();
        ensure!(
            parts.len() >= 3 && parts.len() <= 18 && parts[..2] == ["S", "1"],
            "invalid quota SID text"
        );
        let number = |part: &str| -> Result<u64> {
            ensure!(
                !part.is_empty()
                    && part.bytes().all(|v| v.is_ascii_digit())
                    && (part == "0" || !part.starts_with('0')),
                "noncanonical quota SID text"
            );
            part.parse()
                .map_err(|_| anyhow::anyhow!("quota SID number exceeds bound"))
        };
        let authority = number(parts[2])?;
        ensure!(
            authority <= 0xffffffffffff,
            "quota SID authority exceeds bound"
        );
        let mut bytes = vec![1, (parts.len() - 3) as u8];
        bytes.extend(&authority.to_be_bytes()[2..]);
        for part in &parts[3..] {
            let value = number(part)?;
            ensure!(
                value <= u32::MAX.into(),
                "quota SID subauthority exceeds bound"
            );
            bytes.extend((value as u32).to_le_bytes());
        }
        Self::binary(&bytes)
    }
    pub(crate) fn bytes(&self) -> &[u8] {
        &self.0
    }
    pub(crate) fn canonical(&self) -> String {
        let authority = self.0[2..8]
            .iter()
            .fold(0u64, |n, b| n * 256 + u64::from(*b));
        let mut value = format!("S-1-{authority}");
        for part in self.0[8..].as_chunks::<4>().0 {
            use fmt::Write;
            write!(&mut value, "-{}", u32::from_le_bytes(*part)).expect("String formatting");
        }
        value
    }
}
impl Drop for Sid {
    fn drop(&mut self) {
        self.0.fill(0);
    }
}

/// Constructed only from complete, bounded native token queries, never caller-supplied counts.
pub struct OwnerInventory {
    pub(crate) user: Sid,
    pub(crate) package: Sid,
    pub(crate) owner: Sid,
    pub(crate) owners: Vec<Sid>,
}
impl fmt::Debug for OwnerInventory {
    fn fmt(&self, out: &mut fmt::Formatter<'_>) -> fmt::Result {
        out.debug_struct("OwnerInventory")
            .field("owner_count", &self.owners.len())
            .finish()
    }
}
impl OwnerInventory {
    pub(crate) fn new(user: Sid, package: Sid, owner: Sid, groups: &[(Sid, u32)]) -> Result<Self> {
        ensure!(
            groups.len() <= 256 && owner == user,
            "quota token owner does not equal token user"
        );
        let admin = Sid::text("S-1-5-32-544")?;
        let mut owners = vec![user.clone(), package.clone()];
        for (sid, attributes) in groups {
            if *sid == admin {
                ensure!(
                    attributes & (8 | 4 | 2) == 0 && attributes & 16 != 0,
                    "Administrators retains quota owner or enabled authority"
                );
            }
            if attributes & 8 != 0 {
                owners.push(sid.clone());
            }
        }
        owners.sort_by_key(Sid::canonical);
        owners.dedup();
        ensure!(
            owners.len() <= OWNER_LIMIT,
            "assignable quota owner set exceeds fixed bound"
        );
        Ok(Self {
            user,
            package,
            owner,
            owners,
        })
    }
    pub fn owner_count(&self) -> usize {
        self.owners.len()
    }
    pub fn digest(&self) -> String {
        let mut hash = Sha256::new();
        for sid in [&self.user, &self.package, &self.owner]
            .into_iter()
            .chain(&self.owners)
        {
            hash.update((sid.bytes().len() as u64).to_be_bytes());
            hash.update(sid.bytes());
        }
        format!("{:x}", hash.finalize())
    }
    pub(crate) fn texts(&self) -> Vec<String> {
        self.owners.iter().map(Sid::canonical).collect()
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Role {
    Primary,
    TokenChild,
}
impl Role {
    pub fn argument(self) -> &'static str {
        match self {
            Self::Primary => "--quota-primary",
            Self::TokenChild => "--quota-token-child",
        }
    }
    pub fn name(self) -> &'static str {
        match self {
            Self::Primary => "primary",
            Self::TokenChild => "token-child",
        }
    }
}

/// The controller supplies only its fixed prepared roots; the worker executes no supplied program.
#[derive(Clone)]
pub struct WorkerPlan {
    pub role: Role,
    pub run: String,
    pub scratch: String,
    pub package: String,
    pub readonly_root: PathBuf,
    pub auxiliary_image: PathBuf,
    pub host_canary: PathBuf,
    pub profile_ac: PathBuf,
}
fn path_text(path: &std::path::Path) -> Result<&str> {
    let text = path
        .to_str()
        .ok_or_else(|| anyhow::anyhow!("worker path is not Unicode"))?;
    let bytes = text.as_bytes();
    ensure!(
        bytes.len() >= 3
            && bytes[0].is_ascii_alphabetic()
            && &bytes[1..3] == b":\\"
            && !text.contains(['\0', '"', '/'])
            && text.encode_utf16().count() < 512
            && text[3..]
                .split('\\')
                .all(|part| part != "." && part != ".."),
        "invalid fixed quota worker path"
    );
    Ok(text)
}
impl WorkerPlan {
    pub fn validate(&self) -> Result<()> {
        ensure!(
            crate::tex_supervisor::valid_token(&self.run),
            "invalid quota run binding"
        );
        ensure!(
            self.scratch.len() == 3
                && (b'D'..=b'Z').contains(&self.scratch.as_bytes()[0])
                && &self.scratch.as_bytes()[1..] == b":\\",
            "quota worker requires an owned drive root"
        );
        super::package_sid(&self.package)?;
        for path in [
            &self.readonly_root,
            &self.auxiliary_image,
            &self.host_canary,
            &self.profile_ac,
        ] {
            path_text(path)?;
        }
        ensure!(
            path_text(&self.profile_ac)?.ends_with("\\AC") && self.profile_ac.parent().is_some(),
            "quota worker profile AC binding differs"
        );
        Ok(())
    }
    pub fn arguments(&self, role: Role) -> Result<Vec<String>> {
        self.validate()?;
        Ok(vec![
            role.argument().into(),
            self.run.clone(),
            self.scratch.clone(),
            self.package.clone(),
            path_text(&self.readonly_root)?.into(),
            path_text(&self.auxiliary_image)?.into(),
            path_text(&self.host_canary)?.into(),
            path_text(&self.profile_ac)?.into(),
        ])
    }
    pub fn parse(args: &[String]) -> Result<Self> {
        ensure!(args.len() == 8, "quota worker argument count differs");
        let role = match args[0].as_str() {
            "--quota-primary" => Role::Primary,
            "--quota-token-child" => Role::TokenChild,
            _ => anyhow::bail!("unsupported quota worker role"),
        };
        let value = Self {
            role,
            run: args[1].clone(),
            scratch: args[2].clone(),
            package: args[3].clone(),
            readonly_root: args[4].clone().into(),
            auxiliary_image: args[5].clone().into(),
            host_canary: args[6].clone().into(),
            profile_ac: args[7].clone().into(),
        };
        value.validate()?;
        Ok(value)
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct TokenRecord {
    detached_stdio: bool,
    owners: Vec<String>,
    phase: String,
}
pub(crate) fn token_record(inventory: &OwnerInventory) -> Result<String> {
    let value = TokenRecord {
        detached_stdio: true,
        owners: inventory.texts(),
        phase: "token-child".into(),
    };
    let text = serde_json::to_string(&value)? + "\n";
    ensure!(
        text.len() <= DESCENDANT_BYTES,
        "quota descendant record exceeds bound"
    );
    Ok(text)
}
pub(crate) fn require_token_record(bytes: &[u8], inventory: &OwnerInventory) -> Result<()> {
    ensure!(
        !bytes.is_empty()
            && bytes.len() <= DESCENDANT_BYTES
            && bytes.is_ascii()
            && bytes.last() == Some(&b'\n')
            && !bytes[..bytes.len() - 1].contains(&b'\n'),
        "invalid quota descendant transport"
    );
    let value: TokenRecord = serde_json::from_slice(bytes)
        .map_err(|_| anyhow::anyhow!("invalid quota descendant JSON"))?;
    ensure!(
        value.phase == "token-child"
            && value.detached_stdio
            && value.owners == inventory.texts()
            && bytes == token_record(inventory)?.as_bytes(),
        "descendant quota owner inventory or detached handles changed"
    );
    Ok(())
}

pub(crate) fn success(plan: &WorkerPlan, inventory: &OwnerInventory) -> String {
    format!(
        "WINDOWS_QUOTA_CONTROL role=primary run={} status=passed owner_count={} owner_digest={} owner_matches_user=True descendant_equal=True ordinary_eof_denied=True sparse_eof_denied=True aggregate_denied=True private_creator_qualified=True raw_volume_denied=True quota_bytes=16777216\n",
        plan.run,
        inventory.owner_count(),
        inventory.digest()
    )
}

/// Joins one actual fixed primary observation to its prepared run and token inventory.
/// A parsed record alone is not native evidence; the completion owner also requires actual exit/cleanup.
pub fn require_primary_record(
    bytes: &[u8],
    plan: &WorkerPlan,
    inventory: &OwnerInventory,
) -> Result<()> {
    plan.validate()?;
    ensure!(
        plan.role == Role::Primary
            && bytes.len() <= 1024
            && bytes.is_ascii()
            && bytes == success(plan, inventory).as_bytes(),
        "quota primary record differs from actual prepared run or owner inventory"
    );
    Ok(())
}
