//! ModuleActivationFixture.CheckValidation and direct lease/sidecar dependencies.
use super::*;
use std::fs;
pub fn check_module_validation(work: &Path) -> Result<()> {
    require_role(true, &[false; 8])?;
    for index in 0..9 {
        let mut flags = [false; 8];
        if index < 8 {
            flags[index] = true;
        }
        ensure!(
            require_role(index != 8, &flags).is_err(),
            "module role overlap accepted"
        );
    }
    ensure!(
        script(1033) == "LANGUAGE 9,1\n2 24 \"module-activation-payload.bin\"\n",
        "module resource language script differs"
    );
    ensure!(
        result(true, 0, Some(GOOD), Some(""))?.contains("association_proved=True")
            && result(false, 0, Some(FAILURE), Some(""))?.contains("association_proved=False"),
        "module association literals differ"
    );
    let absent = result(true, 0xc0150002, Some(""), Some(""))?;
    ensure!(
        absent == "entry_observed=False association_proved=False exit=0xC0150002"
            && require_unentered(&absent)? == 0xc0150002
            && compare_callback(0xc0150002, 0xc0150002, Some(""), Some(""))?
                == "WINDOWS_MODULE_CALLBACK returned_exit_equal=True observation_only=True cause_claimed=False",
        "module absent/callback comparison differs"
    );
    ensure!(
        require_unentered(&result(true, 0, Some(GOOD), Some(""))?).is_err(),
        "entered module classified unentered"
    );
    for code in [0, 1, 0xc0000022] {
        ensure!(
            compare_callback(0xc0150002, code, Some(""), Some("")).is_err(),
            "unequal callback exit accepted"
        );
    }
    ensure!(
        compare_callback(0xc0150002, 0xc0150002, Some(GOOD), Some("")).is_err()
            && compare_callback(0xc0150002, 0xc0150002, Some(""), Some("private-sentinel"))
                .is_err()
            && result(false, 0xc0150002, Some(""), Some("")).is_err()
            && result(true, 0, Some(FAILURE), Some("")).is_err(),
        "module role or transport confusion accepted"
    );
    for bad in [
        GOOD.repeat(2),
        GOOD.trim_end_matches('\n').into(),
        GOOD.replace("attach=1", "attach=0"),
        GOOD.replace("root_is_module=1", "root_is_module=0"),
        GOOD.replace("00000080", "00010001"),
        GOOD.replace("00000003", "00000011"),
        GOOD.replace("00000000", "00000005"),
        GOOD.replace("query_succeeded=1", "query_succeeded=0"),
        GOOD.replace("root_evaluated=1", "root_evaluated=0"),
        "private-sentinel".into(),
    ] {
        ensure!(
            result(true, 0, Some(&bad), Some("")).is_err(),
            "malformed module result accepted"
        );
    }
    for code in [1, 121, 0x7fffffff, 0xc0000022] {
        ensure!(
            result(true, code, Some(GOOD), Some("")).is_err(),
            "module unrelated exit/entry pair accepted"
        );
    }
    ensure!(
        result(true, 0, Some(GOOD), Some("private-sentinel")).is_err()
            && condition(
                "private-sentinel",
                true,
                Some(&result(true, 0, Some(GOOD), Some(""))?)
            )
            .is_err(),
        "module stderr or unknown condition accepted"
    );
    ensure!(
        condition(
            "original",
            true,
            Some(&result(true, 0, Some(GOOD), Some(""))?)
        )?
        .ends_with(
            "active_at_entry_claimed=False python_equivalence_claimed=False cause_claimed=False"
        ),
        "module condition overclaimed attribution"
    );
    lease::check_module_lease_validation()?;
    let directory = tempfile::Builder::new()
        .prefix("module-activation-validation-")
        .tempdir_in(work)?;
    let path = directory.path().join("owned.bin");
    io::create(&path, &[1, 2, 3], 1048576)?.close()?;
    ensure!(
        io::create(&path, &[9], 1048576).is_err() && fs::read(&path)? == [1, 2, 3],
        "module collision changed owned bytes"
    );
    let image = directory.path().join("startup-module.exe");
    let sidecar = directory.path().join("startup-module.exe.config");
    fs::write(&sidecar, b"unchanged")?;
    ensure!(
        io::no_overrides(&image).is_err() && fs::read(&sidecar)? == b"unchanged",
        "module override collision changed sentinel"
    );
    fs::remove_file(&sidecar)?;
    super::super::source::directory_link(&directory.path().join("absent"), &sidecar)?;
    ensure!(
        io::no_overrides(&image).is_err() && crate::identity::is_link(&sidecar)?,
        "module dangling override collision changed or accepted"
    );
    super::super::source::remove_directory_link(&sidecar)
}
