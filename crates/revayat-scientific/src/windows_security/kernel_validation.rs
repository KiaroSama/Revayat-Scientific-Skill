//! Portable fixed-plan checks only; no native control or wall retirement evidence is produced.
use super::*;
use crate::windows_security::quota_controls::{Role as QuotaRole, Sid};
use anyhow::{Result, ensure};
pub fn check_validation() -> Result<()> {
    let plan = KernelPlan {
        role: Role::KernelPrimary,
        quota: WorkerPlan {
            role: QuotaRole::Primary,
            run: "a".repeat(32),
            scratch: "D:\\".into(),
            package: "S-1-15-2-1-2-3-4-5-6-7".into(),
            readonly_root: "C:\\prepared\\runtime".into(),
            auxiliary_image: "C:\\prepared\\auxiliary\\fixed.exe".into(),
            host_canary: "C:\\prepared\\host-canary".into(),
            profile_ac: "C:\\profiles\\owned\\AC".into(),
        },
        system_root: "C:\\Windows".into(),
        chromium: "C:\\browser\\chromium.exe".into(),
        tcp_port: 12345,
        udp_port: 23456,
    };
    plan.validate()?;
    let mut digests = std::collections::BTreeSet::new();
    for role in [
        Role::KernelPrimary,
        Role::KernelWall,
        Role::TokenChild,
        Role::PidHold,
        Role::PidExtra,
        Role::WallHold,
    ] {
        let args = plan.arguments(role)?;
        ensure!(
            args.len() == 12 && args[0] == role.argument(),
            "kernel fixed role arguments differ"
        );
        let parsed = KernelPlan::parse(&args)?;
        ensure!(
            parsed.role == role
                && parsed.arguments(role)? == args
                && parsed.environment()? == plan.environment()?
                && digests.insert(plan.arguments_digest(role)?),
            "kernel role roundtrip/digest separation differs"
        );
    }
    let environment = plan.environment()?;
    ensure!(
        environment.len() == 13
            && environment.keys().map(String::as_str).collect::<Vec<_>>()
                == [
                    "APPDATA",
                    "DOTNET_CLI_HOME",
                    "HOME",
                    "LOCALAPPDATA",
                    "PATH",
                    "PYTHONIOENCODING",
                    "REVAYAT_CHROMIUM",
                    "SYSTEMROOT",
                    "TEMP",
                    "TMP",
                    "USERPROFILE",
                    "WINDIR",
                    "XDG_CACHE_HOME"
                ],
        "kernel environment key set differs"
    );
    ensure!(
        environment["HOME"] == "D:\\home"
            && environment["TEMP"] == "D:\\temp"
            && environment["XDG_CACHE_HOME"] == "D:\\home\\cache"
            && environment["PATH"] == "C:\\prepared\\runtime;C:\\prepared\\auxiliary"
            && environment["PYTHONIOENCODING"] == "utf-8"
            && !environment.contains_key("SCIENTIFIC_AMBIENT_CANARY"),
        "kernel environment values differ"
    );
    let block = plan.environment_block()?;
    ensure!(
        block.ends_with(&[0, 0])
            && !block[..block.len() - 2]
                .windows(2)
                .any(|part| part == [0, 0]),
        "kernel environment block framing differs"
    );
    let decoded = String::from_utf16(&block[..block.len() - 1])?;
    let mut reparsed = BTreeMap::new();
    for entry in decoded.trim_end_matches('\0').split('\0') {
        let (name, value) = entry
            .split_once('=')
            .ok_or_else(|| anyhow::anyhow!("kernel block entry lacks separator"))?;
        ensure!(
            reparsed.insert(name.to_owned(), value.to_owned()).is_none(),
            "kernel environment alias accepted"
        );
    }
    ensure!(
        reparsed == environment,
        "kernel exact Unicode environment roundtrip changed"
    );
    let user = Sid::text("S-1-5-21-1-2-3-1000")?;
    let package = Sid::text(&plan.quota.package)?;
    let inventory = OwnerInventory::new(user.clone(), package.clone(), user, &[])?;
    let record = primary_record(&plan, &inventory)?;
    require_primary_record(record.as_bytes(), &plan, &inventory)?;
    for bad in [
        record.replace("status=passed", "status=failed"),
        record.replace("run=aaaa", "run=bbbb"),
        record.replace("owner_count=2", "owner_count=3"),
        record.replace("process_memory_mib=384", "process_memory_mib=385"),
        record.replace("cpu_rate=1000", "cpu_rate=1001"),
        format!("{record}private-tail"),
    ] {
        ensure!(
            require_primary_record(bad.as_bytes(), &plan, &inventory).is_err(),
            "kernel record accepted changed binding/control"
        );
    }
    let mut changed = plan.clone();
    changed.tcp_port += 1;
    ensure!(
        changed.arguments_digest(Role::KernelPrimary)?
            != plan.arguments_digest(Role::KernelPrimary)?
            && require_primary_record(record.as_bytes(), &changed, &inventory).is_err(),
        "kernel endpoint binding did not affect record"
    );
    changed = plan.clone();
    changed.chromium = "C:\\other\\chromium.exe".into();
    ensure!(
        changed.environment_digest()? != plan.environment_digest()?
            && require_primary_record(record.as_bytes(), &changed, &inventory).is_err(),
        "kernel environment binding did not affect record"
    );
    changed = plan.clone();
    changed.role = Role::KernelWall;
    ensure!(
        require_primary_record(record.as_bytes(), &changed, &inventory).is_err(),
        "kernel wall role accepted natural primary record"
    );
    for (index, value) in [
        (0, "--kernel-unknown"),
        (1, "bad-run"),
        (2, "C:\\"),
        (2, "D:\\nested"),
        (3, "S-1-15-2-1"),
        (4, "C:\\x\\..\\escape"),
        (8, "C:\\Windows\0tail"),
        (9, "C:\\browser\\\"quote.exe"),
        (9, "C:\\browser;injected\\chrome.exe"),
        (10, "0"),
        (10, "65536"),
        (10, "001"),
        (10, "+1"),
        (11, "-1"),
    ] {
        let mut args = plan.arguments(Role::KernelPrimary)?;
        args[index] = value.into();
        ensure!(
            KernelPlan::parse(&args).is_err(),
            "kernel malformed argument was accepted"
        );
    }
    let mut args = plan.arguments(Role::KernelPrimary)?;
    args.push("extra".into());
    ensure!(
        KernelPlan::parse(&args).is_err() && KernelPlan::parse(&args[..11]).is_err(),
        "kernel argument bounds changed"
    );
    changed = plan.clone();
    changed.quota.role = QuotaRole::TokenChild;
    ensure!(
        changed.validate().is_err(),
        "kernel embedded quota role changed"
    );
    ensure!(
        WALL_MARKER == b"trusted wall-tree negative control started\n" && digests.len() == 6,
        "kernel wall marker or closed role census changed"
    );
    Ok(())
}
