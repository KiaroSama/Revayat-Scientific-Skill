//! Non-linguistic path comparison. Windows delegates to the operating system's ordinal tables.
use anyhow::{Result, ensure};
#[cfg(windows)]
#[link(name = "kernel32")]
unsafe extern "system" {
    fn CompareStringOrdinal(
        first: *const u16,
        first_count: i32,
        second: *const u16,
        second_count: i32,
        ignore_case: i32,
    ) -> i32;
    fn GetLastError() -> u32;
}
pub fn ordinal_path_equal(first: &str, second: &str) -> Result<bool> {
    ensure!(
        first.encode_utf16().count() <= 32768 && second.encode_utf16().count() <= 32768,
        "SxS ordinal path exceeds bound"
    );
    #[cfg(windows)]
    {
        let first: Vec<_> = first.encode_utf16().collect();
        let second: Vec<_> = second.encode_utf16().collect();
        // SAFETY: both counted UTF-16 slices remain live; TRUE must be exactly 1.
        let result = unsafe {
            CompareStringOrdinal(
                first.as_ptr(),
                first.len() as i32,
                second.as_ptr(),
                second.len() as i32,
                1,
            )
        };
        let code = if result == 0 {
            Some(unsafe { GetLastError() })
        } else {
            None
        };
        ensure!(
            (1..=3).contains(&result),
            "SxS ordinal comparison failed winerror={code:?}"
        );
        Ok(result == 2)
    }
    #[cfg(not(windows))]
    {
        // Portable reference only, not proof of Windows NLS version/table behavior. Never expand
        // sharp-s/ligatures or normalize combining characters into a different path identity.
        fn upper(value: char) -> char {
            if matches!(value, '\u{131}' | '\u{17f}') {
                return value;
            }
            let mut uppercase = value.to_uppercase();
            let first = uppercase.next().unwrap();
            if uppercase.next().is_none() {
                first
            } else {
                value
            }
        }
        Ok(
            first.encode_utf16().count() == second.encode_utf16().count()
                && first.chars().map(upper).eq(second.chars().map(upper)),
        )
    }
}
