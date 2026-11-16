//! Original separate-role guards, evaluated before native process or token acquisition.
use super::{
    csr::{Observation as Dispatch, Role},
    preparation::Observation,
    self_result::SelfRole,
};
use anyhow::{Result, ensure};
use std::path::Path;
pub struct SandboxRoles {
    pub preflight: bool,
    pub probes: [bool; 7],
    pub registry_status: Option<i32>,
    pub default_activation: bool,
    pub module_role: u8,
    pub callback_exit: Option<u32>,
    pub self_activation: bool,
    pub self_role: SelfRole,
    pub self_entry: bool,
    pub self_resource: bool,
    pub dll_request: bool,
    pub python_condition: bool,
    pub default_dacl: bool,
    pub dispatch: bool,
}
impl Default for SandboxRoles {
    fn default() -> Self {
        Self {
            preflight: true,
            probes: [false; 7],
            registry_status: Some(0),
            default_activation: false,
            module_role: 0,
            callback_exit: None,
            self_activation: false,
            self_role: SelfRole::Original,
            self_entry: false,
            self_resource: false,
            dll_request: false,
            python_condition: false,
            default_dacl: false,
            dispatch: false,
        }
    }
}
impl SandboxRoles {
    fn common(&self) -> bool {
        self.preflight
            && self.probes.iter().all(|v| !*v)
            && !self.default_activation
            && self.callback_exit.is_none()
            && !self.self_entry
            && !self.dll_request
            && !self.python_condition
            && !self.default_dacl
            && self.registry_status == Some(0)
    }
    pub fn require_preparation(&self, observation: &Observation) -> Result<()> {
        ensure!(
            self.common()
                && self.module_role == 0
                && !self.self_activation
                && self.self_role == SelfRole::Original
                && !self.self_resource
                && !self.dispatch,
            "Python preparation requires its fixed undebugged readable-key role"
        );
        observation.require_fresh()
    }
    pub fn require_dispatch(&self, value: &Dispatch) -> Result<()> {
        ensure!(
            self.common()
                && !value.recorded()
                && match value.role() {
                    Role::PythonPass =>
                        self.module_role == 0
                            && !self.self_activation
                            && !self.self_resource
                            && self.self_role == SelfRole::Original,
                    Role::Module =>
                        self.module_role == 2
                            && !self.self_activation
                            && !self.self_resource
                            && self.self_role == SelfRole::Original,
                    Role::ExplicitId2 =>
                        self.module_role == 0
                            && self.self_activation
                            && self.self_role == SelfRole::ExplicitId2
                            && self.self_resource == value.traced(),
                },
            "CSR dispatch requires its separate fixed readable-key role"
        );
        Ok(())
    }
}
pub struct HostSetup {
    pub internal: bool,
    pub resource: bool,
    pub dispatch: bool,
    pub module: bool,
    pub python: bool,
    pub dll_request: bool,
    pub self_role: SelfRole,
    pub entry_image: bool,
    pub retain_metadata: bool,
}
impl HostSetup {
    pub fn fixed(role: Role) -> Self {
        Self {
            internal: true,
            resource: true,
            dispatch: true,
            module: role == Role::Module,
            python: role == Role::PythonPass,
            dll_request: false,
            self_role: if role == Role::ExplicitId2 {
                SelfRole::ExplicitId2
            } else {
                SelfRole::Original
            },
            entry_image: true,
            retain_metadata: true,
        }
    }
    pub fn require(&self, role: Role) -> Result<()> {
        ensure!(
            self.internal
                && self.resource
                && self.dispatch
                && !self.dll_request
                && self.entry_image
                && self.retain_metadata
                && self.module == (role == Role::Module)
                && self.python == (role == Role::PythonPass)
                && self.self_role
                    == if role == Role::ExplicitId2 {
                        SelfRole::ExplicitId2
                    } else {
                        SelfRole::Original
                    },
            "unsupported fixed CSR host role"
        );
        Ok(())
    }
}
pub fn require_module_launch(image: &Path, arguments: Option<&[&str]>, cwd: &Path) -> Result<()> {
    ensure!(
        image.is_absolute()
            && cwd.is_absolute()
            && arguments == Some(&[][..])
            && image.file_name().is_some_and(|v| v == "startup-module.exe")
            && image.parent() == Some(cwd)
            && cwd.file_name().is_some_and(|v| v == "module-id2"),
        "unsupported fixed module CSR host launch"
    );
    Ok(())
}
pub fn setup_stage(tool: &str, stage: &str) -> Result<String> {
    ensure!(
        matches!(tool, "python.exe" | "startup-module.exe") && stage == "create-before",
        "unsupported fixed setup stage"
    );
    Ok(format!("WINDOWS_SETUP_STAGE tool={tool} stage={stage}"))
}
pub fn check_preparation_roles() -> Result<()> {
    use super::preparation::{Condition, Experiment};
    let fresh = || Observation::new(Condition::Baseline, Experiment::Token);
    SandboxRoles::default().require_preparation(&fresh())?;
    let mut variants = Vec::new();
    variants.push(SandboxRoles {
        preflight: false,
        ..Default::default()
    });
    for at in 0..7 {
        let mut v = SandboxRoles::default();
        v.probes[at] = true;
        variants.push(v);
    }
    for status in [None, Some(1)] {
        variants.push(SandboxRoles {
            registry_status: status,
            ..Default::default()
        });
    }
    for field in 0..11 {
        let mut v = SandboxRoles::default();
        match field {
            0 => v.default_activation = true,
            1 => v.module_role = 1,
            2 => v.callback_exit = Some(0),
            3 => v.self_activation = true,
            4 => v.self_role = SelfRole::ExplicitId2,
            5 => v.self_entry = true,
            6 => v.self_resource = true,
            7 => v.dll_request = true,
            8 => v.python_condition = true,
            9 => v.default_dacl = true,
            _ => v.dispatch = true,
        };
        variants.push(v);
    }
    ensure!(
        variants.len() == 21,
        "original preparation role product changed"
    );
    for v in variants {
        ensure!(
            v.require_preparation(&fresh()).is_err(),
            "incompatible preparation role accepted"
        );
    }
    Ok(())
}
pub fn check_module_roles() -> Result<()> {
    let cwd = std::env::current_dir()?.join("python/module-id2");
    let image = cwd.join("startup-module.exe");
    require_module_launch(&image, Some(&[]), &cwd)?;
    for (arguments, executable, directory) in [
        (None, image.clone(), cwd.clone()),
        (Some(&["private-sentinel"][..]), image.clone(), cwd.clone()),
        (
            Some(&[][..]),
            image.clone(),
            cwd.parent().unwrap().to_path_buf(),
        ),
        (
            Some(&[][..]),
            cwd.parent()
                .unwrap()
                .join("module-plain/startup-module.exe"),
            cwd.parent().unwrap().join("module-plain"),
        ),
        (
            Some(&[][..]),
            cwd.join("startup-explicit-id2.exe"),
            cwd.clone(),
        ),
    ] {
        let error = require_module_launch(&executable, arguments, &directory).unwrap_err();
        ensure!(
            !error.to_string().contains("private-sentinel"),
            "module launch leaked private argument"
        );
    }
    for mode in 0..3 {
        let mut setup = HostSetup::fixed(Role::Module);
        match mode {
            0 => setup.internal = false,
            1 => setup.dispatch = false,
            _ => setup.self_role = SelfRole::ExplicitId2,
        };
        ensure!(
            setup.require(Role::Module).is_err(),
            "incompatible module setup role accepted"
        );
    }
    ensure!(
        setup_stage("startup-module.exe", "create-before")?
            == "WINDOWS_SETUP_STAGE tool=startup-module.exe stage=create-before",
        "module setup stage differs"
    );
    Ok(())
}
pub fn check_python_roles() -> Result<()> {
    for mode in 0..5 {
        let mut setup = HostSetup::fixed(Role::PythonPass);
        match mode {
            0 => setup.internal = false,
            1 => setup.dispatch = false,
            2 => setup.self_role = SelfRole::ExplicitId2,
            3 => setup.module = true,
            _ => {
                setup.internal = false;
                setup.resource = false;
                setup.dispatch = false;
            }
        }
        ensure!(
            setup.require(Role::PythonPass).is_err(),
            "incompatible Python setup role accepted"
        );
    }
    for mode in 0..5 {
        let mut roles = SandboxRoles::default();
        match mode {
            0 => roles.preflight = false,
            1 => roles.module_role = 2,
            2 => roles.self_activation = true,
            3 => roles.self_resource = true,
            _ => roles.probes[1] = true,
        };
        ensure!(
            roles
                .require_dispatch(&Dispatch::new(true, Role::PythonPass))
                .is_err(),
            "incompatible Python sandbox role accepted"
        );
    }
    ensure!(
        setup_stage("python.exe", "create-before")?
            == "WINDOWS_SETUP_STAGE tool=python.exe stage=create-before",
        "Python setup stage differs"
    );
    Ok(())
}
