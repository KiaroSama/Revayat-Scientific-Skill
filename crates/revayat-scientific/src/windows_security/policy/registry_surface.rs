//! Bounded fixed-key registry surface inventory. Only digests and counts can leave the reader.
use crate::windows_security::{activation::Failures, sxs::ordinal_path_equal};
use anyhow::{Result, ensure};
use base64::{Engine, engine::general_purpose::STANDARD};
use sha2::{Digest, Sha256};
use std::fmt;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Snapshot {
    pub digest: Vec<u8>,
    pub values: u32,
    pub subkeys: u32,
    pub types: u32,
}
impl Snapshot {
    pub fn require_equal(&self, other: &Self) -> Result<()> {
        ensure!(self == other, "registry surface changed");
        Ok(())
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Information {
    pub values: u32,
    pub subkeys: u32,
    pub modified: i64,
}
pub struct Value {
    pub name: Vec<u16>,
    pub kind: u32,
    pub data: Vec<u8>,
}
impl Drop for Value {
    fn drop(&mut self) {
        self.name.fill(0);
        self.data.fill(0);
    }
}
pub trait SurfaceIo {
    fn information(&mut self) -> Result<Information>;
    fn value(&mut self, index: u32) -> Result<Option<Value>>;
    fn subkey(&mut self, index: u32) -> Result<Option<Vec<u16>>>;
    fn descriptor(&mut self) -> Result<Vec<u8>>;
    fn deadline(&mut self) -> Result<()>;
    fn close(&mut self) -> Result<()>;
}
#[derive(Debug)]
pub struct NameEncoding(std::string::FromUtf16Error);
impl fmt::Display for NameEncoding {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("registry name cannot be encoded")
    }
}
impl std::error::Error for NameEncoding {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.0)
    }
}
fn name(units: &[u16]) -> Result<String> {
    ensure!(
        !units.contains(&0),
        "registry name contains an embedded terminator"
    );
    String::from_utf16(units).map_err(|error| NameEncoding(error).into())
}
pub fn validate_value(kind: u32, data: &[u8]) -> Result<()> {
    ensure!(
        data.len() <= 4096 && [0, 1, 2, 3, 4, 5, 7, 11].contains(&kind),
        "registry value kind or size unsupported"
    );
    match kind {
        4 | 5 => ensure!(data.len() == 4, "registry DWORD size differs"),
        11 => ensure!(data.len() == 8, "registry QWORD size differs"),
        1 | 2 | 7 => {
            ensure!(
                data.len() >= if kind == 7 { 4 } else { 2 } && data.len().is_multiple_of(2),
                "registry string size differs"
            );
            let units = data
                .as_chunks::<2>()
                .0
                .iter()
                .map(|b| u16::from_le_bytes([b[0], b[1]]))
                .collect::<Vec<_>>();
            String::from_utf16(&units)?;
            ensure!(
                units.ends_with(if kind == 7 { &[0, 0] } else { &[0] }),
                "registry string termination differs"
            );
        }
        _ => {}
    }
    Ok(())
}
pub struct PrivateFailure {
    original: anyhow::Error,
    category: &'static str,
}
impl PrivateFailure {
    pub fn original(&self) -> &anyhow::Error {
        &self.original
    }
}
impl fmt::Display for PrivateFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "fixed registry surface failed phase=inventory category={} raw_error_withheld=True",
            self.category
        )
    }
}
impl fmt::Debug for PrivateFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}
impl std::error::Error for PrivateFailure {}
pub fn sanitize(error: anyhow::Error) -> anyhow::Error {
    if error.is::<PrivateFailure>() {
        return error;
    }
    let error = match error.downcast::<Failures>() {
        Ok(group) => {
            return Failures {
                errors: group.errors.into_iter().map(sanitize).collect(),
            }
            .into();
        }
        Err(error) => error,
    };
    let category = if error.is::<NameEncoding>() {
        "encode"
    } else if error.is::<std::string::FromUtf16Error>() {
        "decode"
    } else if error.is::<crate::runtime::DeadlineExceeded>() {
        "timeout"
    } else {
        "control"
    };
    PrivateFailure {
        original: error,
        category,
    }
    .into()
}
pub fn read(io: &mut impl SurfaceIo) -> Result<Snapshot> {
    let operation = (|| {
        let before = io.information()?;
        ensure!(
            before.values <= 32 && before.subkeys <= 256,
            "registry inventory exceeds bounds"
        );
        let mut fields = Vec::new();
        let mut names = Vec::<String>::new();
        let (mut values, mut subkeys, mut types, mut total) = (0, 0, 0, 0usize);
        for index in 0..=32 {
            io.deadline()?;
            let Some(value) = io.value(index)? else {
                ensure!(index == before.values, "registry value count changed");
                break;
            };
            ensure!(
                index < 32 && value.name.len() < 512,
                "registry value name exceeds bounds"
            );
            let text = name(&value.name)?;
            for prior in &names {
                ensure!(
                    !ordinal_path_equal(prior, &text)?,
                    "registry value names collide"
                );
            }
            names.push(text);
            validate_value(value.kind, &value.data)?;
            total = total
                .checked_add(value.data.len())
                .ok_or_else(|| anyhow::anyhow!("registry value budget overflow"))?;
            ensure!(total <= 32768, "registry values exceed total budget");
            let encoded = value
                .name
                .iter()
                .flat_map(|u| u.to_le_bytes())
                .collect::<Vec<_>>();
            fields.push(format!(
                "v:{}:{}:{}",
                STANDARD.encode(encoded),
                value.kind,
                STANDARD.encode(&value.data)
            ));
            values += 1;
            types |= 1u32 << value.kind;
        }
        names.clear();
        for index in 0..=256 {
            io.deadline()?;
            let Some(mut units) = io.subkey(index)? else {
                ensure!(index == before.subkeys, "registry subkey count changed");
                break;
            };
            ensure!(
                index < 256 && !units.is_empty() && units.len() < 512,
                "registry subkey name exceeds bounds"
            );
            let text = name(&units)?;
            for prior in &names {
                ensure!(
                    !ordinal_path_equal(prior, &text)?,
                    "registry subkey names collide"
                );
            }
            names.push(text);
            fields.push(format!(
                "k:{}",
                STANDARD.encode(
                    units
                        .iter()
                        .flat_map(|u| u.to_le_bytes())
                        .collect::<Vec<_>>()
                )
            ));
            units.fill(0);
            subkeys += 1;
        }
        ensure!(
            io.information()? == before,
            "registry inventory changed while sampled"
        );
        let mut descriptor = io.descriptor()?;
        ensure!(
            (20..=65536).contains(&descriptor.len()),
            "registry descriptor exceeds bounds"
        );
        fields.push(format!("sd:{}", STANDARD.encode(&descriptor)));
        descriptor.fill(0);
        fields.sort_unstable();
        let mut bytes = fields.join("\n").into_bytes();
        let digest = Sha256::digest(&bytes).to_vec();
        bytes.fill(0);
        io.deadline()?;
        Ok(Snapshot {
            digest,
            values,
            subkeys,
            types,
        })
    })();
    let closed = io.close();
    match (operation, closed) {
        (Ok(value), Ok(())) => Ok(value),
        (Err(primary), Ok(())) => Err(sanitize(primary)),
        (Ok(_), Err(error)) => Err(sanitize(error)),
        (Err(primary), Err(cleanup)) => Err(sanitize(
            Failures {
                errors: vec![primary, cleanup],
            }
            .into(),
        )),
    }
}
pub fn check_validation() -> Result<()> {
    for kind in [0, 3, 4, 5, 11] {
        validate_value(kind, &vec![0; if kind == 11 { 8 } else { 4 }])?;
    }
    validate_value(1, &[65, 0, 0, 0])?;
    for (kind, size) in [(6, 4), (4, 8), (11, 4), (1, 1), (7, 2)] {
        ensure!(
            validate_value(kind, &vec![0; size]).is_err(),
            "invalid registry value accepted"
        );
    }
    let original = Snapshot {
        digest: vec![1, 2],
        values: 1,
        subkeys: 2,
        types: 8,
    };
    original.require_equal(&original.clone())?;
    for mode in 0..4 {
        let mut changed = original.clone();
        match mode {
            0 => changed.digest.reverse(),
            1 => changed.values += 1,
            2 => changed.subkeys += 1,
            _ => changed.types += 1,
        };
        ensure!(
            original.require_equal(&changed).is_err(),
            "registry surface mismatch accepted"
        );
    }
    for encoding in [false, true] {
        let raw = if encoding {
            name(&[0xd800]).unwrap_err()
        } else {
            validate_value(1, &[0x37, 0xd8, 0, 0]).unwrap_err()
        };
        let raw_address = raw.as_ref() as *const (dyn std::error::Error + Send + Sync);
        let cleanup = anyhow::anyhow!("private-close-sentinel");
        let error = sanitize(
            Failures {
                errors: vec![raw, cleanup],
            }
            .into(),
        );
        let group = error.downcast_ref::<Failures>().unwrap();
        let first = group.errors[0].downcast_ref::<PrivateFailure>().unwrap();
        ensure!(
            std::ptr::addr_eq(
                first.original().as_ref() as *const (dyn std::error::Error + Send + Sync),
                raw_address
            ) && first.to_string().contains(if encoding {
                "category=encode"
            } else {
                "category=decode"
            }) && group.errors[1].is::<PrivateFailure>()
                && !format!("{error:?}").contains("sentinel"),
            "registry surface privacy or cause identity differs"
        );
    }
    Ok(())
}
