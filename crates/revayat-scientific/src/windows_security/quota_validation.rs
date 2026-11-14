//! Portable hostile-input checks only; success supplies no native token or quota evidence.
use super::*;
use anyhow::{Result, ensure};
use std::path::PathBuf;

pub fn check_validation() -> Result<()> {
    let user = Sid::text("S-1-5-21-1-2-3-1000")?;
    let package = Sid::text("S-1-15-2-1-2-3-4-5-6-7")?;
    for text in [
        "",
        "S-1",
        "S-1-05-1",
        "S-1-281474976710656-1",
        "S-1-5-4294967296",
        "S-1-5--1",
        "S-1-5-01",
    ] {
        ensure!(
            Sid::text(text).is_err(),
            "invalid quota SID text was accepted"
        );
    }
    for bytes in [
        vec![],
        vec![1; 7],
        vec![2, 0, 0, 0, 0, 0, 0, 5],
        vec![1, 16, 0, 0, 0, 0, 0, 5],
        vec![1, 1, 0, 0, 0, 0, 0, 5],
    ] {
        ensure!(
            Sid::binary(&bytes).is_err(),
            "invalid quota SID buffer was accepted"
        );
    }
    ensure!(
        Sid::binary(user.bytes())? == user && Sid::text(&user.canonical())? == user,
        "quota SID round trip changed identity"
    );
    let inventory = OwnerInventory::new(user.clone(), package.clone(), user.clone(), &[])?;
    ensure!(
        inventory.owner_count() == 2 && !format!("{inventory:?}").contains(&user.canonical()),
        "quota inventory count or private Debug differs"
    );
    ensure!(
        OwnerInventory::new(user.clone(), package.clone(), package.clone(), &[]).is_err(),
        "quota token non-user owner was accepted"
    );
    let admin = Sid::text("S-1-5-32-544")?;
    for attributes in [0, 2, 4, 8, 16 | 2, 16 | 4, 16 | 8] {
        ensure!(
            OwnerInventory::new(
                user.clone(),
                package.clone(),
                user.clone(),
                &[(admin.clone(), attributes)]
            )
            .is_err(),
            "Administrators quota-owner authority was accepted"
        );
    }
    ensure!(
        OwnerInventory::new(
            user.clone(),
            package.clone(),
            user.clone(),
            &[(admin, 16), (user.clone(), 8), (package.clone(), 8)]
        )?
        .owner_count()
            == 2,
        "finite quota owners did not deduplicate"
    );
    let groups = (0..15)
        .map(|index| Ok((Sid::text(&format!("S-1-5-21-1-2-3-{}", 2000 + index))?, 8)))
        .collect::<Result<Vec<_>>>()?;
    ensure!(
        OwnerInventory::new(user.clone(), package.clone(), user.clone(), &groups[..14])?
            .owner_count()
            == 16
            && OwnerInventory::new(user.clone(), package.clone(), user.clone(), &groups).is_err(),
        "finite quota-owner bound changed"
    );
    let too_many = vec![(user.clone(), 0); 257];
    ensure!(
        OwnerInventory::new(user.clone(), package.clone(), user.clone(), &too_many).is_err(),
        "quota group bound changed"
    );
    let record = token_record(&inventory)?;
    require_token_record(record.as_bytes(), &inventory)?;
    for wire in [
        record.trim_end().to_owned(),
        format!("{record}x"),
        format!("{record}\n"),
        record.replace("true", "false"),
        record.replace("token-child", "primary"),
        record.replace("\"phase\":", "\"extra\":0,\"phase\":"),
        record.replace(&user.canonical(), "S-1-5-21-1-2-3-9999"),
    ] {
        ensure!(
            require_token_record(wire.as_bytes(), &inventory).is_err(),
            "malformed quota descendant record was accepted"
        );
    }
    ensure!(
        require_token_record(&vec![b'x'; DESCENDANT_BYTES + 1], &inventory).is_err(),
        "quota descendant transport bound changed"
    );
    let plan = WorkerPlan {
        role: Role::Primary,
        run: "a".repeat(32),
        scratch: "D:\\".into(),
        package: package.canonical(),
        readonly_root: PathBuf::from("C:\\prepared\\readonly"),
        auxiliary_image: PathBuf::from(
            "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
        ),
        host_canary: PathBuf::from("C:\\prepared\\host-canary"),
        profile_ac: PathBuf::from("C:\\profiles\\owned\\AC"),
    };
    plan.validate()?;
    for role in [Role::Primary, Role::TokenChild] {
        ensure!(
            WorkerPlan::parse(&plan.arguments(role)?)?.role == role,
            "closed quota role changed"
        );
    }
    let wire = success(&plan, &inventory);
    require_primary_record(wire.as_bytes(), &plan, &inventory)?;
    for bad in [
        wire.replace("run=aaaa", "run=bbbb"),
        wire.replace("owner_count=2", "owner_count=3"),
        wire.replace("16777216", "33554432"),
        format!("{wire}private"),
    ] {
        ensure!(
            require_primary_record(bad.as_bytes(), &plan, &inventory).is_err(),
            "quota primary observation binding changed"
        );
    }
    for (index, value) in [
        (0, "--other"),
        (1, "private-run"),
        (2, "C:\\"),
        (2, "D:\\nested"),
        (3, "S-1-15-2-1"),
        (4, "C:\\x\\..\\y"),
        (7, "C:\\profiles\\owned\\OTHER"),
    ] {
        let mut args = plan.arguments(Role::Primary)?;
        args[index] = value.into();
        ensure!(
            WorkerPlan::parse(&args).is_err(),
            "invalid quota fixed plan was accepted"
        );
    }
    Ok(())
}
