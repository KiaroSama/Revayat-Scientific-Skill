use super::{
    evidence as core,
    fixture::{need, stage},
    stream::{self, Raw},
};
use anyhow::Result;
use std::sync::Arc;
pub(super) fn check_length_validation() -> Result<()> {
    let rows: [(&[i64], i32, Option<&str>); 9] = [
        (
            &[0],
            0,
            Some(
                "file-bound comparison=minimum observed_bytes=0 maximum_bytes=8 even=not-evaluated",
            ),
        ),
        (
            &[1, 9],
            0,
            Some(
                "file-bound comparison=maximum observed_bytes=9 maximum_bytes=8 even=not-evaluated",
            ),
        ),
        (&[8, 0], 0, None),
        (
            &[1],
            1,
            Some(
                "read-shape comparison=minimum observed_bytes=1 maximum_bytes=8 even=not-evaluated",
            ),
        ),
        (
            &[2, 9],
            1,
            Some(
                "read-shape comparison=maximum observed_bytes=9 maximum_bytes=8 even=not-evaluated",
            ),
        ),
        (&[3, 8], 1, None),
        (&[2, 8], 1, None),
        (
            &[i64::MIN],
            0,
            Some(
                "file-bound comparison=minimum observed_bytes=-9223372036854775808 maximum_bytes=8 even=not-evaluated",
            ),
        ),
        (
            &[1, i64::MAX],
            0,
            Some(
                "file-bound comparison=maximum observed_bytes=9223372036854775807 maximum_bytes=8 even=not-evaluated",
            ),
        ),
    ];
    for (values, phase, expected) in rows {
        let mut reads = 0;
        let result = core::require_length(
            || {
                need(reads < values.len())?;
                let value = values[reads];
                reads += 1;
                Ok(value)
            },
            8,
            core::LengthPhase::from_index(phase)?,
        );
        need(reads == values.len())?;
        match expected {
            None => need(result.is_ok())?,
            Some(expected) => need(
                stage(&result.expect_err("fixed length must fail"))?
                    == format!("evidence-length-{expected}"),
            )?,
        }
    }
    for maximum in [1_048_576, 8_388_608] {
        for phase in [core::LengthPhase::FileBound, core::LengthPhase::ReadShape] {
            let mut reads = 0;
            core::require_length(
                || {
                    reads += 1;
                    Ok(maximum)
                },
                maximum,
                phase,
            )?;
            need(reads == 2)?;
        }
    }
    for phase in 0..3 {
        for fail_at in 1..=2 {
            let (tag, error) = stream::raw("length");
            let mut error = Some(error);
            let mut reads = 0;
            let result = core::require_length(
                || {
                    reads += 1;
                    if reads == fail_at {
                        Err(error.take().expect("one raw length failure"))
                    } else {
                        Ok(2)
                    }
                },
                8,
                core::LengthPhase::from_index(phase)?,
            );
            let caught = result.expect_err("raw length failure must propagate");
            need(
                reads == fail_at
                    && caught
                        .downcast_ref::<Raw>()
                        .is_some_and(|error| Arc::ptr_eq(&error.tag, &tag)),
            )?;
        }
    }
    for invalid in [-1, 3, i32::MAX] {
        let mut reads = 0;
        let result = core::LengthPhase::from_index(invalid).and_then(|phase| {
            core::require_length(
                || {
                    reads += 1;
                    Ok(2)
                },
                8,
                phase,
            )
        });
        need(result.is_err() && reads == 0)?;
    }
    Ok(())
}
