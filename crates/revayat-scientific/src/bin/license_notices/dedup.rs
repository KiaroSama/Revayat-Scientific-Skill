//! Exact-byte notice bodies shared without dropping occurrence attribution.
use super::{BUNDLE_LIMIT, Notice, digest, fence};
use anyhow::{Result, ensure};
use std::collections::BTreeMap;

/// Logical retained material, not allocator RSS. Duplicate occurrences remain admitted.
/// 256 MiB permits the incumbent duplicate-heavy inventory; output stays bounded at 64 MiB.
pub(super) struct MaterialBudget {
    used: usize,
    limit: usize,
}
impl Default for MaterialBudget {
    fn default() -> Self {
        Self {
            used: 0,
            limit: 256 * 1024 * 1024,
        }
    }
}
impl MaterialBudget {
    pub(super) fn reserve(&mut self, lengths: &[usize]) -> Result<()> {
        let total = lengths
            .iter()
            .try_fold(self.used, |sum, length| sum.checked_add(*length));
        ensure!(
            total.is_some_and(|total| total <= self.limit),
            "notice retained material exceeds 256 MiB"
        );
        self.used = total.unwrap();
        Ok(())
    }
    pub(super) fn read(&mut self, reader: impl std::io::Read, limit: u64) -> Result<Vec<u8>> {
        use std::io::Read;
        let mut reader = reader.take(limit + 1);
        let mut bytes = Vec::new();
        let mut chunk = [0; 8192];
        loop {
            let count = reader.read(&mut chunk)?;
            if count == 0 {
                break;
            }
            ensure!(
                bytes
                    .len()
                    .checked_add(count)
                    .is_some_and(|size| size as u64 <= limit),
                "source notice grew beyond limit"
            );
            self.reserve(&[count])?;
            bytes.extend_from_slice(&chunk[..count]);
        }
        Ok(bytes)
    }
}

#[derive(Default)]
pub(super) struct Bodies(BTreeMap<String, String>, usize);

fn output_capacity(current: usize, additional: usize) -> Result<()> {
    ensure!(
        current
            .checked_add(additional)
            .is_some_and(|size| size <= BUNDLE_LIMIT),
        "complete notice bundle exceeds 64 MiB"
    );
    Ok(())
}

pub(super) fn push(output: &mut String, text: &str) -> Result<()> {
    output_capacity(output.len(), text.len())?;
    output.push_str(text);
    Ok(())
}

impl Bodies {
    pub(super) fn occurrence(&mut self, output: &mut String, notice: &Notice) -> Result<()> {
        ensure!(
            digest(notice.text.as_bytes()) == notice.sha256,
            "notice body hash differs"
        );
        let size = notice
            .name
            .len()
            .checked_add(notice.provenance.len())
            .and_then(|size| size.checked_add(5 * notice.sha256.len() + 128));
        ensure!(
            size.and_then(|size| output.len().checked_add(size))
                .is_some_and(|size| size <= BUNDLE_LIMIT),
            "complete notice bundle exceeds 64 MiB"
        );
        if let Some(previous) = self.0.get(&notice.sha256) {
            ensure!(
                previous == &notice.text,
                "same notice hash has different bytes"
            );
        } else {
            let retained = self
                .1
                .checked_add(notice.text.len())
                .and_then(|size| size.checked_add(notice.sha256.len() + 128));
            ensure!(
                retained.is_some_and(|size| size <= BUNDLE_LIMIT),
                "shared notice material exceeds 64 MiB"
            );
            self.1 = retained.unwrap();
            self.0.insert(notice.sha256.clone(), notice.text.clone());
        }
        push(
            output,
            &format!(
                "### {}\n\nProvenance: {}\n\nSHA-256: `{}`\n\nFull text: [notice-{}](#notice-{})\n\n",
                notice.name, notice.provenance, notice.sha256, notice.sha256, notice.sha256
            ),
        )?;
        Ok(())
    }

    pub(super) fn append(self, output: &mut String) -> Result<()> {
        push(
            output,
            "## Exact shared notice bodies\n\nEach occurrence above retains its filename and provenance. Only byte-identical bodies share a reference. Byte length excludes any Markdown separator newline.\n\n",
        )?;
        for (hash, text) in self.0 {
            push(
                output,
                &format!(
                    "<a id=\"notice-{hash}\"></a>\n\n### {hash}\n\nByte length: {}\n\n",
                    text.len()
                ),
            )?;
            let marker = fence(&text);
            push(output, &marker)?;
            push(output, "text\n")?;
            push(output, &text)?;
            if !text.ends_with('\n') {
                push(output, "\n")?;
            }
            push(output, &marker)?;
            push(output, "\n\n")?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn notice(name: &str, text: &str) -> Notice {
        Notice {
            name: name.into(),
            sha256: digest(text.as_bytes()),
            text: text.into(),
            provenance: format!("fixture/{name}"),
        }
    }

    fn expand<'a>(output: &'a str, hash: &str) -> &'a [u8] {
        let anchor = format!("<a id=\"notice-{hash}\"></a>");
        let tail = output.split_once(&anchor).unwrap().1;
        let (length, body) = tail
            .split_once("Byte length: ")
            .unwrap()
            .1
            .split_once("\n\n")
            .unwrap();
        let (_, text) = body.split_once("text\n").unwrap();
        &text.as_bytes()[..length.parse::<usize>().unwrap()]
    }

    #[test]
    fn shared_bodies_expand_to_every_original_byte_and_attribution() -> Result<()> {
        let originals = [
            notice("crate-a/LICENSE", "Copyright A\r\nExact terms\r\n"),
            notice("crate-b/COPYING", "Copyright A\r\nExact terms\r\n"),
            notice("crate-c/LICENSE", "Copyright B\nExact terms\n"),
            notice("crate-d/NOTICE", "متن بدون پایان ````"),
            notice("crate-e/NOTICE", "Copyright A\nExact terms\n"),
        ];
        let mut bodies = Bodies::default();
        let mut output = String::new();
        for original in &originals {
            bodies.occurrence(&mut output, original)?;
        }
        bodies.append(&mut output)?;
        assert_eq!(output.matches("<a id=\"notice-").count(), 4);
        for original in &originals {
            assert_eq!(expand(&output, &original.sha256), original.text.as_bytes());
            assert!(output.contains(&format!(
                "### {}\n\nProvenance: {}\n\nSHA-256: `{}`\n\nFull text: [notice-{}](#notice-{})",
                original.name,
                original.provenance,
                original.sha256,
                original.sha256,
                original.sha256
            )));
        }
        let hashes = originals
            .iter()
            .map(|n| n.sha256.as_str())
            .collect::<std::collections::BTreeSet<_>>();
        let positions = hashes
            .iter()
            .map(|hash| {
                output
                    .find(&format!("<a id=\"notice-{hash}\"></a>"))
                    .unwrap()
            })
            .collect::<Vec<_>>();
        assert!(positions.windows(2).all(|pair| pair[0] < pair[1]));
        let mut reversed = Bodies::default();
        let mut reverse_output = String::new();
        for original in originals.iter().rev() {
            reversed.occurrence(&mut reverse_output, original)?;
        }
        reversed.append(&mut reverse_output)?;
        let section = "## Exact shared notice bodies";
        assert_eq!(
            output.split_once(section).unwrap().1,
            reverse_output.split_once(section).unwrap().1
        );
        Ok(())
    }

    #[test]
    fn retained_budget_checks_boundaries_overflow_and_duplicate_occurrences_before_mutation() {
        let mut budget = MaterialBudget {
            used: 0,
            limit: 256,
        };
        budget.reserve(&[128, 128]).unwrap();
        assert_eq!(budget.used, 256);
        assert!(budget.reserve(&[1]).is_err());
        assert_eq!(budget.used, 256);
        assert!(budget.reserve(&[usize::MAX]).is_err());
        let mut exact_read = MaterialBudget { used: 0, limit: 4 };
        assert_eq!(
            exact_read.read(std::io::Cursor::new(b"1234"), 4).unwrap(),
            b"1234"
        );
        let mut grown = MaterialBudget { used: 0, limit: 4 };
        assert!(grown.read(std::io::Cursor::new(b"12345"), 8).is_err());
        assert_eq!(grown.used, 0); // Over-budget chunk never reaches retained Vec.
        let mut file_limit = MaterialBudget { used: 0, limit: 20 };
        assert!(file_limit.read(std::io::Cursor::new(b"12345"), 4).is_err());
        let mut duplicates = MaterialBudget::default();
        for _ in 0..128 {
            duplicates.reserve(&[1024 * 1024, 256]).unwrap();
        }
        assert!(duplicates.used > BUNDLE_LIMIT); // Legitimate duplicate-heavy input is not output-sized.
        let original = notice("LICENSE", "Exact legal text");
        let mut bodies = Bodies::default();
        let mut output = String::new();
        bodies.occurrence(&mut output, &original).unwrap();
        let retained = bodies.1;
        for _ in 0..128 {
            bodies.occurrence(&mut output, &original).unwrap();
        }
        assert_eq!(bodies.1, retained);
        let mut full = Bodies(BTreeMap::new(), BUNDLE_LIMIT);
        let before = output.clone();
        assert!(full.occurrence(&mut output, &original).is_err());
        assert!(full.0.is_empty());
        assert_eq!(output, before);
        assert!(output_capacity(BUNDLE_LIMIT - 1, 1).is_ok());
        assert!(output_capacity(BUNDLE_LIMIT, 1).is_err());
        assert!(output_capacity(usize::MAX, 1).is_err());
    }

    #[test]
    fn stale_hash_or_same_hash_with_different_bytes_fails_before_reference() -> Result<()> {
        let original = notice("LICENSE", "Original text");
        let mut bodies = Bodies::default();
        let mut output = String::new();
        bodies.occurrence(&mut output, &original)?;
        let before = output.clone();
        let mut changed = notice("COPYING", "Changed text");
        changed.sha256 = original.sha256.clone();
        assert!(bodies.occurrence(&mut output, &changed).is_err());
        assert_eq!(output, before);
        bodies
            .0
            .insert(original.sha256.clone(), "different bytes".into());
        assert!(bodies.occurrence(&mut output, &original).is_err());
        assert_eq!(output, before);
        Ok(())
    }
}
