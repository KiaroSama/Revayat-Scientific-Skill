//! Actual held release3.11 headers/import library; the C-API layout is owned Rust source.
use super::*;
use std::{ffi::c_void, os::windows::ffi::OsStrExt};
#[link(name = "version")]
unsafe extern "system" {
    fn GetFileVersionInfoSizeW(path: *const u16, handle: *mut u32) -> u32;
    fn GetFileVersionInfoW(path: *const u16, handle: u32, length: u32, data: *mut c_void) -> i32;
    fn VerQueryValueW(
        data: *const c_void,
        key: *const u16,
        value: *mut *mut c_void,
        length: *mut u32,
    ) -> i32;
}
fn release_version(path: &Path) -> Result<()> {
    let path = path
        .as_os_str()
        .encode_wide()
        .chain(Some(0))
        .collect::<Vec<_>>();
    ensure!(
        !path[..path.len() - 1].contains(&0),
        "Python SDK source path contains NUL"
    );
    let mut unused = 0;
    let length = unsafe { GetFileVersionInfoSizeW(path.as_ptr(), &mut unused) };
    ensure!(
        (52..=1048576).contains(&length),
        "actual Python file version is unavailable or unbounded"
    );
    let mut bytes = Bytes(vec![0; length as usize]);
    ensure!(
        unsafe { GetFileVersionInfoW(path.as_ptr(), 0, length, bytes.0.as_mut_ptr().cast()) } != 0,
        "actual Python file version read failed"
    );
    let mut info = std::ptr::null_mut();
    let mut count = 0;
    ensure!(
        unsafe {
            VerQueryValueW(
                bytes.0.as_ptr().cast(),
                [92u16, 0].as_ptr(),
                &mut info,
                &mut count,
            )
        } != 0
            && count >= 52,
        "actual Python fixed version is unavailable"
    );
    let start = info as usize;
    let base = bytes.0.as_ptr() as usize;
    ensure!(
        start >= base
            && start - base <= bytes.0.len()
            && count as usize <= bytes.0.len() - (start - base),
        "actual Python version pointer exceeds buffer"
    );
    let fixed = &bytes.0[start - base..start - base + 52];
    let word = |offset: usize| u32::from_le_bytes(fixed[offset..offset + 4].try_into().unwrap());
    ensure!(
        word(0) == 0xfeef04bd && word(8) >> 16 == 3 && word(8) & 0xffff == 11 && word(28) & 1 == 0,
        "actual Python SDK is not non-debug3.11"
    );
    Ok(())
}
fn define(text: &str, key: &str, expected: &str) -> Result<()> {
    let values = text
        .lines()
        .filter_map(|line| {
            let mut parts = line.split_whitespace();
            if parts.next() == Some("#define") && parts.next() == Some(key) {
                Some(parts.next())
            } else {
                None
            }
        })
        .collect::<Vec<_>>();
    ensure!(
        values == [Some(expected)],
        "actual Python SDK macro differs from fixed release ABI"
    );
    Ok(())
}
pub(super) fn qualify(base: &PreparedPythonBase, inputs: &mut Inputs) -> Result<PathBuf> {
    let (original, expected) = &base.provenance().images[0];
    ensure!(
        original
            .file_name()
            .is_some_and(|name| name == "python.exe"),
        "actual Python SDK executable name differs"
    );
    inputs.open(original, 16 * 1024 * 1024)?;
    let bytes = Bytes(inputs.bytes(original)?);
    io::require_identity(&bytes.0, expected.size, &expected.sha256)?;
    base.runtime().identity().require_image(&bytes.0)?;
    release_version(original)?;
    let home = original.parent().unwrap();
    let includes = home.join("include");
    io::plain(&includes, false)?;
    for name in [
        "Python.h",
        "pyconfig.h",
        "patchlevel.h",
        "modsupport.h",
        "moduleobject.h",
        "object.h",
    ] {
        let path = includes.join(name);
        inputs.open(&path, 65536)?;
        if name == "patchlevel.h" || name == "modsupport.h" || name == "pyconfig.h" {
            let bytes = Bytes(inputs.bytes(&path)?);
            let text = std::str::from_utf8(&bytes.0)?;
            if name == "patchlevel.h" {
                define(text, "PY_MAJOR_VERSION", "3")?;
                define(text, "PY_MINOR_VERSION", "11")?;
            } else if name == "modsupport.h" {
                define(text, "PYTHON_API_VERSION", "1013")?;
                define(text, "PYTHON_ABI_VERSION", "3")?;
            } else {
                ensure!(
                    !text.lines().any(|line| {
                        let mut words = line.split_whitespace();
                        words.next() == Some("#define") && words.next() == Some("Py_TRACE_REFS")
                    }),
                    "trace-reference Python ABI is outside fixed module layout"
                );
            }
        }
    }
    let library = home.join("libs").join("python311.lib");
    inputs.open(&library, 16 * 1024 * 1024)?;
    Ok(library)
}
