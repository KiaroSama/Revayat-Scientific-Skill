//! Exact call-pair and clean-trace continuation contracts, not an observed CSR operation.
use revayat_scientific::windows_security::activation::dispatch::*;
use revayat_scientific::windows_security::activation::{CONTEXT_SIZE, Failures};
use std::cell::RefCell;
fn put(context: &mut [u8], offset: usize, value: u64) {
    context[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
}
#[test]
fn fixed_csr_target_read_consumes_attempt_before_region_and_requires_exact_eight_bytes() {
    let readable = DispatchRegion {
        address: 0x8000,
        allocation: 0x7000,
        size: 4096,
        state: 0x1000,
        kind: 0x1000000,
        protect: 2,
    };
    for protection in [2, 4, 8, 0x20, 0x40, 0x80] {
        assert!(
            DispatchRegion {
                protect: protection,
                ..readable
            }
            .readable(0x8100, 0x7000)
        );
    }
    for region in [
        DispatchRegion {
            size: 7,
            ..readable
        },
        DispatchRegion {
            state: 0x2000,
            ..readable
        },
        DispatchRegion {
            kind: 0x20000,
            ..readable
        },
        DispatchRegion {
            protect: 0x102,
            ..readable
        },
        DispatchRegion {
            protect: 0x10,
            ..readable
        },
        DispatchRegion {
            allocation: 0x6000,
            ..readable
        },
    ] {
        assert!(!region.readable(0x8000, 0x7000));
    }
    for mode in 0..5 {
        let mut target = DispatchTarget::default();
        let mut reads = 0;
        let result = target.read(
            0x8100,
            0x7000,
            0x9000,
            || {
                if mode == 1 {
                    Err(anyhow::anyhow!("region"))
                } else {
                    Ok(readable)
                }
            },
            |bytes| {
                reads += 1;
                bytes.copy_from_slice(
                    &(if mode == 3 { 0x9001u64 } else { 0x9000u64 }).to_le_bytes(),
                );
                if mode == 4 {
                    anyhow::bail!("read");
                }
                Ok(if mode == 2 { 7 } else { 8 })
            },
        );
        assert_eq!(result.is_ok(), mode == 0);
        assert_eq!(reads, usize::from(mode != 1));
        assert!(
            target
                .read(
                    0x8100,
                    0x7000,
                    0x9000,
                    || panic!("consumed"),
                    |_| panic!("consumed")
                )
                .is_err()
        );
    }
}
fn call() -> Vec<u8> {
    let mut bytes = vec![0; CONTEXT_SIZE];
    for (offset, value) in [(152, 0x8000), (184, 0x1001001e), (192, 0x1f8)] {
        put(&mut bytes, offset, value);
    }
    bytes
}

#[test]
fn csr_pair_consumes_one_attempt_binds_generation_stack_and_disarms_entry() {
    for (first, post) in [
        (0, 7),
        (1, 9),
        (u64::MAX, 6),
        (0x8000000000000000, 0x8000000000000007),
    ] {
        assert!(CsrPair::new(first, post).is_err());
    }
    let mut pair = CsrPair::new(0x1000, 0x1007).unwrap();
    assert_eq!(pair.sites(1), [0x1000, 0x1007]);
    let context = call();
    pair.begin(1, &context).unwrap();
    assert_eq!(pair.sites(1), [0, 0x1007]);
    assert_eq!(pair.sites(2), [0, 0]);
    let mut returned = context.clone();
    put(&mut returned, 184, u64::MAX);
    put(&mut returned, 192, 0);
    put(&mut returned, 120, 0x12345678c0150002);
    pair.end(1, &returned).unwrap();
    assert!(pair.paired());
    assert_eq!(pair.result().unwrap(), 0xc0150002);
    assert_eq!(pair.sites(1), [0, 0]);
    assert!(pair.end(1, &returned).is_err());
    for offset in [152, 184, 192] {
        let mut bad = context.clone();
        bad[offset] ^= 1;
        let mut pair = CsrPair::new(0x1000, 0x1007).unwrap();
        assert!(pair.begin(1, &bad).is_err());
        assert!(pair.started() && !pair.paired());
        assert!(pair.begin(1, &context).is_err());
    }
    for mode in 0..4 {
        let mut pair = CsrPair::new(0x1000, 0x1007).unwrap();
        if mode == 0 {
            assert!(pair.end(1, &context).is_err());
        } else {
            pair.begin(1, &context).unwrap();
            if mode == 1 {
                assert!(pair.begin(1, &context).is_err());
            }
            if mode == 2 {
                assert!(pair.end(2, &context).is_err());
            }
            if mode == 3 {
                let mut nested = context.clone();
                put(&mut nested, 152, 0x7f00);
                assert!(pair.end(1, &nested).is_err());
            }
        }
        assert!(pair.end(1, &context).is_err());
    }
}

#[test]
fn trace_finalization_allows_undebugged_only_after_observed_destroyed_clean_state() {
    for mode in 0..7 {
        let order = RefCell::new(Vec::new());
        let result = execute_trace(
            || {
                order.borrow_mut().push("trace");
                if mode == 4 {
                    anyhow::bail!("operation");
                }
                let cleanup = if mode == 5 {
                    vec![anyhow::anyhow!("cleanup")]
                } else {
                    vec![]
                };
                let primary = if matches!(mode, 1 | 3 | 5 | 6) {
                    Some(anyhow::anyhow!("operation"))
                } else {
                    None
                };
                finish_trace(
                    primary,
                    cleanup,
                    true,
                    mode != 6,
                    || Ok("fixed".to_owned()),
                    |_| Ok(()),
                )
            },
            || {
                order.borrow_mut().push("undebugged");
                if mode == 2 || mode == 3 {
                    anyhow::bail!("later");
                }
                Ok(())
            },
        );
        assert_eq!(
            *order.borrow(),
            if mode < 4 {
                vec!["trace", "undebugged"]
            } else {
                vec!["trace"]
            }
        );
        assert_eq!(result.is_ok(), mode == 0);
        if mode == 3 || mode == 5 {
            assert_eq!(
                result
                    .unwrap_err()
                    .downcast_ref::<Failures>()
                    .unwrap()
                    .errors
                    .len(),
                2
            );
        }
    }
    for observed in [false, true] {
        for destroyed in [false, true] {
            let result = finish_trace(
                Some(anyhow::anyhow!("primary")),
                vec![],
                observed,
                destroyed,
                || Ok("fixed".to_owned()),
                |_| Ok(()),
            );
            assert_eq!(
                result.unwrap_err().is::<QualifiedFailure>(),
                observed && destroyed
            );
        }
    }
    let mut emitted = 0;
    finish_trace(
        None,
        vec![],
        true,
        true,
        || Ok("fixed".to_owned()),
        |_| {
            emitted += 1;
            Ok(())
        },
    )
    .unwrap();
    assert_eq!(emitted, 1);
    let error = finish_trace(
        Some(anyhow::anyhow!("primary")),
        vec![],
        true,
        true,
        || Ok("fixed".to_owned()),
        |_| anyhow::bail!("report"),
    )
    .unwrap_err();
    let qualified = error.downcast_ref::<QualifiedFailure>().unwrap();
    assert_eq!(
        qualified
            .original()
            .downcast_ref::<Failures>()
            .unwrap()
            .errors
            .len(),
        2
    );
}
