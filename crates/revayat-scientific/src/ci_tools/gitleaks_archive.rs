//! Decode only the fixed regular executable from a checksum-verified tarball.
use anyhow::{Result, ensure};
use std::io::Read;

const EXPANDED_LIMIT: usize = 64 * 1024 * 1024;
const BINARY_LIMIT: usize = 32 * 1024 * 1024;

fn octal(bytes: &[u8]) -> Result<usize> {
    let text = std::str::from_utf8(bytes)?.trim_matches(['\0', ' ']);
    ensure!(
        !text.is_empty() && text.bytes().all(|b| (b'0'..=b'7').contains(&b)),
        "invalid TAR numeric field"
    );
    Ok(usize::from_str_radix(text, 8)?)
}

pub(super) fn executable(bytes: &[u8]) -> Result<Vec<u8>> {
    let mut decoded = Vec::new();
    flate2::read::GzDecoder::new(bytes)
        .take(EXPANDED_LIMIT as u64 + 1)
        .read_to_end(&mut decoded)?;
    ensure!(
        decoded.len() <= EXPANDED_LIMIT,
        "Gitleaks archive expansion exceeds bound"
    );
    let mut cursor = 0usize;
    let mut found = None;
    let mut count = 0;
    loop {
        let header = decoded
            .get(cursor..cursor + 512)
            .ok_or_else(|| anyhow::anyhow!("truncated TAR header"))?;
        cursor += 512;
        if header.iter().all(|b| *b == 0) {
            ensure!(
                decoded
                    .get(cursor..cursor + 512)
                    .is_some_and(|block| block.iter().all(|b| *b == 0)),
                "incomplete TAR terminator"
            );
            ensure!(
                decoded[cursor..].iter().all(|b| *b == 0),
                "unexpected TAR trailing bytes"
            );
            break;
        }
        count += 1;
        ensure!(count <= 16, "Gitleaks archive member count exceeds bound");
        let checksum: usize = header
            .iter()
            .enumerate()
            .map(|(i, b)| {
                if (148..156).contains(&i) {
                    b' ' as usize
                } else {
                    *b as usize
                }
            })
            .sum();
        ensure!(
            octal(&header[148..156])? == checksum,
            "invalid TAR header checksum"
        );
        ensure!(
            &header[257..262] == b"ustar" && header[345..500].iter().all(|b| *b == 0),
            "unsupported TAR member path"
        );
        ensure!(
            matches!(header[156], 0 | b'0') && header[157..257].iter().all(|b| *b == 0),
            "nonregular TAR member refused"
        );
        let end = header[..100].iter().position(|b| *b == 0).unwrap_or(100);
        let name = &header[..end];
        let size = octal(&header[124..136])?;
        ensure!(size <= BINARY_LIMIT, "TAR member exceeds bound");
        let body = decoded
            .get(
                cursor
                    ..cursor
                        .checked_add(size)
                        .ok_or_else(|| anyhow::anyhow!("TAR size overflow"))?,
            )
            .ok_or_else(|| anyhow::anyhow!("truncated TAR member"))?;
        if name == b"gitleaks" {
            ensure!(
                found.is_none() && body.starts_with(b"\x7fELF"),
                "invalid or duplicate Gitleaks executable"
            );
            found = Some(body.to_vec());
        }
        cursor = cursor
            .checked_add(size.div_ceil(512) * 512)
            .ok_or_else(|| anyhow::anyhow!("TAR offset overflow"))?;
    }
    found.ok_or_else(|| anyhow::anyhow!("verified archive omitted Gitleaks executable"))
}
