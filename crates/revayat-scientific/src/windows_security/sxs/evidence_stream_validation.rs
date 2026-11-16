//! Fault injection through the production evidence reader, never native trace evidence.
use super::{
    evidence as core,
    fixture::{self, need, private, stage},
};
use crate::windows_security::{activation::Failures, sxs::PrivateFailure};
use anyhow::Result;
use std::sync::Arc;

#[derive(Debug)]
pub(super) struct Raw {
    pub(super) tag: Arc<()>,
    kind: &'static str,
}
impl std::fmt::Display for Raw {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "private-{}-sentinel", self.kind)
    }
}
impl std::error::Error for Raw {}
pub(super) fn raw(kind: &'static str) -> (Arc<()>, anyhow::Error) {
    let tag = Arc::new(());
    (tag.clone(), Raw { tag, kind }.into())
}
pub(super) struct Stream {
    pub(super) bytes: Vec<u8>,
    pub(super) mode: i32,
    pub(super) observed: Option<i64>,
    pub(super) allocation: Option<i64>,
    pub(super) lengths: usize,
    pub(super) reads: usize,
    pub(super) closes: usize,
    pub(super) cleared: bool,
    offset: usize,
}
impl Stream {
    pub(super) fn new(bytes: Vec<u8>) -> Self {
        Self {
            bytes,
            mode: 0,
            observed: None,
            allocation: None,
            lengths: 0,
            reads: 0,
            closes: 0,
            cleared: false,
            offset: 0,
        }
    }
}
impl core::EvidenceRead for Stream {
    fn length(&mut self) -> Result<i64> {
        self.lengths += 1;
        Ok(match (self.lengths, self.allocation) {
            (3, Some(allocation)) => allocation,
            _ => self.observed.unwrap_or(self.bytes.len() as i64),
        })
    }
    fn read(&mut self, bytes: &mut [u8]) -> Result<usize> {
        self.reads += 1;
        need(!bytes.is_empty())?;
        if self.mode == 2 || self.mode == 5 && self.reads == 2 || self.mode == 6 {
            return Err(raw("prefix-read").1);
        }
        if self.mode == 3 {
            return Ok(4);
        }
        let count = if self.mode == 1 || self.mode == 5 {
            1
        } else {
            bytes.len()
        }
        .min(self.bytes.len() - self.offset);
        bytes[..count].copy_from_slice(&self.bytes[self.offset..self.offset + count]);
        self.offset += count;
        Ok(count)
    }
    fn close(&mut self) -> Result<()> {
        self.closes += 1;
        if self.mode == 4 || self.mode == 6 {
            Err(raw("prefix-close").1)
        } else {
            Ok(())
        }
    }
    fn bytes_cleared(&mut self, bytes: &[u8]) {
        self.cleared = bytes.iter().all(|byte| *byte == 0);
    }
}
pub(super) fn read(stream: &mut Stream, manifest: &str) -> Result<String> {
    core::read_owned(
        || Ok(stream),
        |bytes| super::failure_evidence(bytes, manifest),
    )
}
pub(super) fn check_prefix_validation() -> Result<()> {
    for (bytes, signature, count) in [
        (None, "absent", 0),
        (Some(vec![]), "absent", 0),
        (Some(vec![239]), "other", 1),
        (Some(vec![239, 187]), "other", 2),
        (Some(vec![239, 187, 191]), "utf8-bom", 3),
        (Some(vec![255, 254]), "utf16le-prefix", 2),
        (Some(vec![255, 254, 0]), "utf16le-prefix", 3),
        (Some(vec![239, 187, 0]), "other", 3),
    ] {
        let report = core::inspect_array(bytes.as_deref())?
            .expect("prefix observation")
            .report;
        need(
            stage(&report)?
                == format!(
                    "evidence-prefix status=array signature={signature} transferred_bytes={count}"
                ),
        )?;
    }
    for mode in 0..=6 {
        let mut stream = Stream::new(vec![239, 187, 191]);
        stream.mode = mode;
        let caught = read(&mut stream, "private-manifest-sentinel")
            .expect_err("empty decoded evidence must fail");
        need(
            stream.lengths == 3
                && stream.closes == 1
                && stream.reads
                    == if mode == 1 {
                        3
                    } else if mode == 5 {
                        2
                    } else {
                        1
                    }
                && stream.cleared,
        )?;
        let raw_pointer = caught.downcast_ref::<Raw>().map(|raw| raw as *const Raw);
        let caught = super::super::safe(caught, "text-read");
        fixture::withheld(&caught)?;
        if mode == 4 || mode == 6 {
            let group = private(&caught)?
                .original()
                .downcast_ref::<Failures>()
                .ok_or_else(|| anyhow::anyhow!("missing evidence read/close group"))?;
            need(
                group.errors.len() == 2
                    && stage(&group.errors[0])?
                        == if mode == 4 {
                            "evidence-final"
                        } else {
                            "text-read"
                        }
                    && stage(&group.errors[1])? == "evidence-close",
            )?;
        } else if mode == 0 || mode == 1 {
            need(stage(&caught)? == "evidence-final")?;
        } else if mode == 3 {
            need(stage(&caught)? == "evidence-read-complete")?;
        } else {
            need(
                private(&caught)?
                    .original()
                    .downcast_ref::<Raw>()
                    .is_some_and(|raw| {
                        raw_pointer.is_some_and(|pointer| std::ptr::eq(raw, pointer))
                    }),
            )?;
        }
    }
    for size in 0..3 {
        let mut stream = Stream::new(vec![0; size]);
        stream.observed = Some(3);
        let caught =
            read(&mut stream, "private-manifest-sentinel").expect_err("short evidence must fail");
        need(
            stream.lengths == 3
                && stream.closes == 1
                && stream.reads == if size == 0 { 1 } else { 2 }
                && stream.cleared
                && stage(&caught)? == "evidence-read-complete",
        )?;
        fixture::withheld(&caught)?;
    }
    for size in [-1, 1, 1_048_577, i64::MAX] {
        let mut stream = Stream::new(vec![0; 2]);
        stream.allocation = Some(size);
        let caught = read(&mut stream, "private-manifest-sentinel")
            .expect_err("invalid evidence allocation must fail");
        need(
            stream.lengths == 3
                && stream.reads == 0
                && stream.closes == 1
                && stage(&caught)?.starts_with("evidence-length-allocation"),
        )?;
    }
    for size in [0, 1, 1_048_577] {
        let mut stream = Stream::new(vec![0; size]);
        let caught = read(&mut stream, "private-manifest-sentinel")
            .expect_err("invalid evidence stream length must fail");
        need(
            stream.reads == 0 && stream.closes == 1 && !stage(&caught)?.contains("evidence-prefix"),
        )?;
    }
    let manifest = "F:\\private-manifest-sentinel\\_ctypes.pyd";
    let block = fixture::block(manifest, "ERROR: Activation Context generation failed.");
    let mut positive = Stream::new(fixture::utf16(&block));
    positive.mode = 7;
    need(
        read(&mut positive, manifest)?.contains("activation_failed=True")
            && positive.lengths == 3
            && positive.reads == 1
            && positive.closes == 1
            && positive.cleared,
    )?;
    let (tag, open_error) = raw("open");
    let open_pointer = open_error.downcast_ref::<Raw>().expect("raw open input") as *const Raw;
    let failed: Result<String> =
        core::read_owned(|| Err::<Stream, _>(open_error), |_| unreachable!());
    let failed = failed.expect_err("failed open must propagate");
    let open_raw = failed.downcast_ref::<Raw>().expect("raw open");
    need(Arc::ptr_eq(&open_raw.tag, &tag) && std::ptr::eq(open_raw, open_pointer))?;
    for mode in 0..4 {
        let original = core::length_failure(
            "read-shape",
            "even",
            Some(3),
            core::TEXT_MAXIMUM,
            Some(false),
        );
        let original_pointer = private(&original)? as *const PrivateFailure;
        let safe = core::supplement(original, || match mode {
            0 => core::inspect_array(Some(&[239, 187, 191])),
            1 => Err(raw("callback").1),
            2 => Err(core::private(raw("callback").1, "unrelated-stage")),
            _ => Ok(None),
        });
        let group = private(&safe)?
            .original()
            .downcast_ref::<Failures>()
            .ok_or_else(|| anyhow::anyhow!("missing prefix supplement group"))?;
        need(
            group.errors.len() == 2
                && std::ptr::eq(private(&group.errors[0])?, original_pointer)
                && stage(&safe)?.contains(if mode == 0 {
                    "status=array signature=utf8-bom transferred_bytes=3"
                } else {
                    "status=unavailable signature=unavailable transferred_bytes=unavailable"
                })
                && !stage(&safe)?.contains("unrelated-stage"),
        )?;
        fixture::withheld(&safe)?;
        need(
            stage(&group.errors[0])?
                == "evidence-length-read-shape comparison=even observed_bytes=3 maximum_bytes=1048576 even=False",
        )?;
    }
    Ok(())
}
