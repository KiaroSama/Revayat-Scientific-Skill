//! Source37: role mutations and semantic call-order/ABI counterparts of immutable C checks.
use super::*;
pub fn check_self_source_validation() -> Result<()> {
    with_owned(
        &owned_directory(),
        &["self_host.rs", "abi.rs", "emit.rs"],
        check_source_contracts,
    )
}
fn check_source_contracts() -> Result<()> {
    require_source(SELF_HOST, SELF_SHA256)?;
    require_source(ABI, ABI_SHA256)?;
    require_source(EMIT, EMIT_SHA256)?;
    let manual = self_source(SELF_HOST, SelfRole::Manual)?;
    ensure!(
        manual
            == SELF_HOST
                .replace(
                    "pub const RESOURCE_ID: u16 = 2;",
                    "pub const RESOURCE_ID: u16 = 101;"
                )
                .replace("WINDOWS_SELF_ACTIVATION", "WINDOWS_MANUAL_ACTIVATION"),
        "manual Rust source transformation differs"
    );
    let explicit = self_source(SELF_HOST, SelfRole::ExplicitId2)?;
    ensure!(
        io::digest(explicit.as_bytes()) == EXPLICIT_SHA256
            && explicit.contains("pub const PRE_CALL_RECEIPT: bool = true;")
            && explicit.contains("pub const RESOURCE_ID: u16 = 2;"),
        "explicit Rust source resource/pre-call binding differs"
    );
    let marker = explicit
        .find("emit(output, b\"EXPLICIT_ID2_BEFORE_CALL\\n\", 122)")
        .ok_or_else(|| anyhow::anyhow!("explicit pre-call source marker absent"))?;
    let call = explicit
        .find("let handle = unsafe { abi::CreateActCtxW(&context) }")
        .ok_or_else(|| anyhow::anyhow!("fixed Rust activation call absent"))?;
    let error = explicit
        .find("let error = if handle as usize == usize::MAX")
        .ok_or_else(|| anyhow::anyhow!("immediate Rust activation error capture absent"))?;
    let release = explicit
        .find("abi::ReleaseActCtx(handle)")
        .ok_or_else(|| anyhow::anyhow!("fixed Rust activation release absent"))?;
    let output = explicit
        .find("let mut line = Record::new()")
        .ok_or_else(|| anyhow::anyhow!("fixed Rust activation output absent"))?;
    ensure!(
        marker < call
            && call < error
            && error < release
            && release < output
            && !explicit[call..error].contains("abi::GetStdHandle"),
        "pre-call/error/release/output source order differs"
    );
    for literal in [
        "module: own",
        "abi::GetStdHandle(-11i32 as u32)",
        "WINDOWS_SELF_ACTIVATION",
    ] {
        ensure!(
            replace_once("unrelated", literal, "fixed").is_err()
                && replace_once(&format!("{literal}\n{literal}"), literal, "fixed").is_err(),
            "missing/duplicate source edit accepted"
        );
    }
    for role in [SelfRole::ExplicitId2, SelfRole::Manual] {
        ensure!(
            self_source(&(SELF_HOST.to_owned() + " "), role).is_err(),
            "changed source accepted"
        );
        let changed = SELF_HOST.replace(
            "pub const RESOURCE_ID: u16 = 2;",
            if role == SelfRole::ExplicitId2 {
                "pub const RESOURCE_ID: u16 = 101;"
            } else {
                "pub const RESOURCE_ID: u16 = 3;"
            },
        );
        ensure!(
            self_source(&changed, role).is_err(),
            "cross-role resource source accepted"
        );
    }
    for literal in [
        "size_of::<ActCtx>() == 56",
        "offset_of!(ActCtx, module) == 48",
    ] {
        ensure!(
            ABI.contains(literal),
            "fixed Rust ACTCTX ABI source guard absent"
        );
    }
    ensure!(
        SELF_HOST.contains("flags: 0x88")
            && SELF_HOST.contains("source: core::ptr::null()")
            && SELF_HOST.contains("abi::GetModuleHandleW(core::ptr::null())")
            && SELF_HOST.contains("module: own"),
        "fixed self-module Rust source ABI changed"
    );
    Ok(())
}
