//! Fixed ASCII metadata, never Python exception messages or arbitrary object representations.
use super::object::{Result, require};

pub struct Text<const N: usize> {
    bytes: [u8; N],
    length: usize,
}
impl<const N: usize> Text<N> {
    pub fn new() -> Self {
        Self {
            bytes: [0; N],
            length: 0,
        }
    }
    pub fn text(&self) -> &str {
        // push admits only ASCII and maintains length <= N.
        unsafe {
            core::str::from_utf8_unchecked(core::slice::from_raw_parts(
                self.bytes.as_ptr(),
                self.length,
            ))
        }
    }
    pub fn push(&mut self, text: &str) -> Result<()> {
        require(text.is_ascii() && text.len() <= N - self.length)?;
        self.bytes
            .get_mut(self.length..self.length + text.len())
            .ok_or(super::object::Fault::Control)?
            .copy_from_slice(text.as_bytes());
        self.length += text.len();
        Ok(())
    }
    pub fn hex(&mut self, value: u64, width: usize) -> Result<()> {
        require((1..=16).contains(&width) && (width == 16 || value < 1u64 << (width * 4)))?;
        for shift in (0..width).rev() {
            let digit = ((value >> (shift * 4)) & 15) as u8;
            let byte = [if digit < 10 {
                b'0' + digit
            } else {
                b'A' + digit - 10
            }];
            self.push(unsafe { core::str::from_utf8_unchecked(&byte) })?;
        }
        Ok(())
    }
}
impl<const N: usize> Drop for Text<N> {
    fn drop(&mut self) {
        self.bytes.fill(0);
        self.length = 0;
    }
}
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Role {
    Primary,
    Descendant,
}
impl Role {
    pub fn name(self) -> &'static str {
        match self {
            Self::Primary => "primary",
            Self::Descendant => "descendant",
        }
    }
}
pub fn bootstrap(role: Role, phase: &str, category: &str) -> Result<Text<128>> {
    let mut text = Text::new();
    for fragment in [
        "REGISTRY_AUTHORITY_FAILURE role=",
        role.name(),
        " child_exit=none errors=",
        phase,
        ":",
        category,
        "\n",
    ] {
        text.push(fragment)?;
    }
    Ok(text)
}
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Loader {
    Unqualified,
    Failed(u32),
    Released,
    ReleaseFailed(u32),
}
impl Loader {
    pub fn from_fields(loaded: u64, error: u64, release: u64, version: u64) -> Result<Self> {
        require(
            version == 1 && loaded <= 1 && error <= u32::MAX as u64 && release <= u32::MAX as u64,
        )?;
        require(if loaded == 0 {
            error != 0 && release == 0
        } else {
            error == 0
        })?;
        Ok(if loaded == 0 {
            Self::Failed(error as u32)
        } else if release == 0 {
            Self::Released
        } else {
            Self::ReleaseFailed(release as u32)
        })
    }
    pub fn followup(self, role: Role) -> Result<Text<256>> {
        let mut text = Text::new();
        for fragment in ["REGISTRY_LOADER_FOLLOWUP role=", role.name(), " errors="] {
            text.push(fragment)?;
        }
        match self {
            Self::Unqualified => text.push("loader:unqualified")?,
            Self::Failed(code) => {
                require(code != 0)?;
                text.push("loader:win32-")?;
                text.hex(code as u64, 8)?;
            }
            Self::Released => text.push("loader:loaded,loader-release:released")?,
            Self::ReleaseFailed(code) => {
                require(code != 0)?;
                text.push("loader:loaded,loader-release:win32-")?;
                text.hex(code as u64, 8)?;
            }
        }
        text.push("\n")?;
        Ok(text)
    }
}
