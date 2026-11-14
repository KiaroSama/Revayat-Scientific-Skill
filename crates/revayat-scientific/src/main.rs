use anyhow::{Result, bail};
use clap::Parser;
use revayat_scientific as revayat;
use std::{
    io::{self, Write},
    path::PathBuf,
    time::Duration,
};

#[derive(Parser)]
#[command(version, about = "Native scientific Persian document tools")]
struct Cli {
    /// Maximum wall time for the command's owned process tree.
    #[arg(long,default_value_t=300,value_parser=clap::value_parser!(u64).range(1..=1800))]
    timeout: u64,
    #[arg(long, hide = true)]
    worker: bool,
    #[arg(value_parser=["lint","figures","fonts","docx","pdf","pages","crop","term-brief","text-order","build","doctor","render-html","tex-container","run-check","package","install","validate","ci-status","check-workflows","check-commit-identity","check-sha","security-linux","security-windows","source-closure","ledger","migration-check","release-bundle"])]
    command: String,
    #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
    arguments: Vec<String>,
}

fn dispatch(cli: &Cli) -> Result<i32> {
    let args = &cli.arguments;
    match cli.command.as_str() {
        "lint" => revayat::lint::cli_lint(args),
        "figures" => revayat::images::cli(args),
        "fonts" => revayat::fonts::cli(args),
        "docx" => revayat::docx::cli(args),
        "pdf" => revayat::pdf::cli(args),
        "pages" => revayat::pdf::pages_cli(args),
        "crop" => revayat::crop::cli(args),
        "term-brief" => revayat::terms::cli_term_brief(args),
        "text-order" => revayat::text_order::cli_text_order(args),
        "build" => revayat::build::cli_build(args),
        "doctor" => revayat::build::cli_doctor(args),
        "render-html" => revayat::render::cli_render(args),
        "tex-container" => revayat::tex_container::cli(args),
        "run-check" => revayat::runtime::cli_run_check(args),
        "package" => revayat::distribution::cli_package(args),
        "install" => revayat::distribution::cli_install(args),
        "validate" => revayat::validation::cli(args),
        "security-linux" => revayat::sandbox::cli(args),
        "security-windows" => {
            #[cfg(windows)]
            {
                #[derive(Parser)]
                struct Options {
                    #[arg(long, conflicts_with = "image", required_unless_present = "image")]
                    authority_image: Option<PathBuf>,
                    #[arg(
                        conflicts_with = "authority_image",
                        required_unless_present = "authority_image"
                    )]
                    image: Option<PathBuf>,
                    #[arg(long, hide = true, num_args = 4)]
                    owned_run: Vec<std::ffi::OsString>,
                    /// Compare original, temporary and restored machine registry policy.
                    #[arg(long, conflicts_with_all = ["machine_quota", "machine_kernel"])]
                    machine_authority: bool,
                    /// Include the real fixed NTFS/quota actor in the same disposable profile.
                    #[arg(long, conflicts_with_all = ["machine_authority", "machine_kernel"])]
                    machine_quota: bool,
                    /// Include full fixed kernel controls and the verified forced wall-tree.
                    #[arg(long, conflicts_with_all = ["machine_authority", "machine_quota"])]
                    machine_kernel: bool,
                    /// Run the original ordered 53 validators and three direct checks.
                    #[arg(long)]
                    bootstrap_checks: bool,
                }
                let options = Options::try_parse_from(
                    std::iter::once("security-windows".to_owned()).chain(args.iter().cloned()),
                )?;
                let image = options
                    .authority_image
                    .or(options.image)
                    .expect("required image argument checked by clap");
                anyhow::ensure!(
                    options.owned_run.len() == 4,
                    "native worker requires an owned run binding"
                );
                let view = revayat::windows_security::native::NativeRunView::from_arguments(
                    &options.owned_run,
                )?;
                if options.bootstrap_checks {
                    revayat::windows_security::native::run_bootstrap_checks(&view)?;
                }
                let report = if options.machine_kernel {
                    revayat::windows_security::native::run_machine_kernel_session(&image, &view)?
                } else if options.machine_quota {
                    revayat::windows_security::native::run_machine_quota_session(&image, &view)?
                } else if options.machine_authority {
                    revayat::windows_security::native::run_machine_authority_session(&image, &view)?
                } else {
                    revayat::windows_security::native::run_owned_registry_authority(&image, &view)?
                };
                println!("{report}");
                Ok(0)
            }
            #[cfg(not(windows))]
            {
                bail!("native Windows security verification requires Windows");
            }
        }
        "ci-status" => revayat::ci::cli_status(args),
        "release-bundle" => revayat::release_bundle::cli(args),
        "check-workflows" => revayat::ci_tools::cli_workflow(args),
        "check-commit-identity" => revayat::ci_tools::cli_commit_identity(args),
        "check-sha" => revayat::ci_tools::cli_sha(args),
        "migration-check" => revayat::migration::cli(args),
        "source-closure" | "ledger" => {
            anyhow::ensure!(args.len() == 1, "expected exactly one source path");
            let source = PathBuf::from(&args[0]);
            let value = if cli.command == "ledger" {
                serde_json::to_value(revayat::ledger::read_ledger(
                    &source,
                    &["source", "output"],
                )?)?
            } else {
                serde_json::to_value(revayat::tex::source_closure(&source, None)?)?
            };
            println!("{}", serde_json::to_string_pretty(&value)?);
            Ok(0)
        }
        _ => bail!("unknown command"),
    }
}

fn run(cli: Cli) -> Result<i32> {
    if cli.worker {
        return dispatch(&cli);
    }
    let directory = std::env::var_os("REVAYAT_LOG_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("logs"));
    let mut log = revayat::runtime::OperationLog::create("revayat-scientific", &directory, None)?;
    // The command is a fixed clap enum. Arguments, paths, manuscript contents,
    // child output and detailed errors never enter the operation log.
    log.info(&format!("command={}", cli.command));
    let result = run_owned(&cli);
    match &result {
        Ok(code) => log.write(
            if *code == 0 { "INFO" } else { "ERROR" },
            &format!("exit_code={code}"),
        ),
        Err(error) => log.write(
            "ERROR",
            if error
                .downcast_ref::<revayat::runtime::DeadlineExceeded>()
                .is_some()
            {
                "failed category=deadline"
            } else {
                "failed category=execution"
            },
        ),
    }
    result
}

fn run_owned(cli: &Cli) -> Result<i32> {
    // Dispatch before the ordinary worker boundary; GPG receives key bytes only through stdin.
    if cli.command == "release-bundle" {
        return dispatch(cli);
    }
    let mut command = revayat::runtime::CommandSpec::new(std::env::current_exe()?.into_os_string())
        .args([
            "--worker".to_owned(),
            "--timeout".into(),
            cli.timeout.to_string(),
            cli.command.clone(),
        ])
        .args(cli.arguments.iter().cloned());
    command.timeout = Duration::from_secs(cli.timeout);
    #[cfg(windows)]
    if cli.command == "security-windows" {
        command.windows_job = revayat::windows_security::JobLimits::security_bootstrap();
        command.idle_timeout = Some(Duration::from_secs(45));
        command.max_output = 1024 * 1024;
        anyhow::ensure!(
            !cli.arguments
                .iter()
                .any(|arg| arg == "--owned-run" || arg.starts_with("--owned-run=")),
            "owned native run locators are internal"
        );
        let mut owner = None;
        let prepared = revayat::windows_security::preparation::invoke_bootstrap_stage(
            "prerequisite",
            0,
            revayat::windows_security::preparation::bootstrap_progress,
            || {
                owner = Some(revayat::windows_security::native::NativeRunOwner::create(
                    &std::env::current_dir()?,
                )?);
                Ok(())
            },
        );
        if let Err(primary) = prepared {
            return revayat::runtime::with_cleanup(
                Err(primary),
                owner.as_mut().map_or(Ok(()), |owner| owner.close()),
            );
        }
        let mut owner = owner.expect("successful prerequisite created its owned state");
        command.args.push("--owned-run".into());
        command.args.extend(owner.worker_arguments());
        let binding = owner.recovery_binding().to_owned();
        let output = match revayat::runtime::run_with_recovery(&command, &binding, |proof| {
            owner.recover(proof)
        }) {
            Ok(output) => output,
            Err(error) => {
                // This fixed owned security worker already produces bounded public diagnostics.
                // Report its completed bytes even when later recovery fails; the error remains fatal.
                let reporting =
                    if let Some(output) = revayat::runtime::retained_command_output(&error) {
                        let stdout = io::stdout().write_all(&output.stdout).map_err(Into::into);
                        let stderr = io::stderr().write_all(&output.stderr).map_err(Into::into);
                        revayat::runtime::with_cleanup(stdout, stderr)
                    } else {
                        Ok(())
                    };
                return revayat::runtime::with_cleanup(Err(error), reporting);
            }
        };
        io::stdout().write_all(&output.stdout)?;
        io::stderr().write_all(&output.stderr)?;
        if output.code == 0
            && cli.arguments.iter().any(|a| a == "--bootstrap-checks")
            && cli.arguments.iter().any(|a| a == "--machine-kernel")
            && std::env::var("GITHUB_ACTIONS").as_deref() == Ok("true")
        {
            revayat::migration::execution::record_windows_security_receipt(
                &output.stdout,
                &output.stderr,
            )?;
        }
        return Ok(output.code);
    }
    let output = if [
        "build",
        "render-html",
        "tex-container",
        "run-check",
        "security-linux",
    ]
    .contains(&cli.command.as_str())
    {
        revayat::runtime::run_supervised(&command)?
    } else {
        revayat::runtime::run(&command)?
    };
    io::stdout().write_all(output.stdout_text().as_bytes())?;
    io::stderr().write_all(output.stderr_text().as_bytes())?;
    Ok(output.code)
}

fn main() {
    let code = match run(parse_cli()) {
        Ok(code) => code,
        Err(error) => {
            if let Some(usage) = error.downcast_ref::<clap::Error>() {
                let code = usage.exit_code();
                let _ = usage.print();
                code
            } else if let Some(diagnostic) = revayat::runtime::deadline_diagnostic(&error) {
                eprintln!("revayat-scientific: {diagnostic}");
                if error
                    .downcast_ref::<revayat::runtime::CleanupFailure>()
                    .is_some()
                {
                    eprintln!("revayat-scientific: {error:#}");
                }
                124
            } else {
                eprintln!("revayat-scientific: {error:#}");
                2
            }
        }
    };
    std::process::exit(code);
}

/// Global options end at the command token. A delegated command may itself
/// accept --timeout or --version; those options must never be consumed here.
fn parse_cli() -> Cli {
    let raw: Vec<String> = std::env::args().collect();
    let mut prefix = vec![
        raw.first()
            .cloned()
            .unwrap_or_else(|| "revayat-scientific".into()),
    ];
    let mut index = 1;
    while index < raw.len() {
        let argument = &raw[index];
        prefix.push(argument.clone());
        index += 1;
        if argument == "--timeout" {
            if index < raw.len() {
                prefix.push(raw[index].clone());
                index += 1;
            }
        } else if argument == "--worker" || argument.starts_with("--timeout=") {
            continue;
        } else if !argument.starts_with('-') {
            break;
        }
    }
    let mut cli = Cli::try_parse_from(prefix).unwrap_or_else(|error| error.exit());
    cli.arguments = raw[index..].to_vec();
    cli
}
