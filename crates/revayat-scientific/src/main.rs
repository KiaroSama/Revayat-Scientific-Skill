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
    #[arg(value_parser=["lint","figures","fonts","docx","pdf","pages","crop","term-brief","text-order","build","doctor","render-html","tex-container","run-check","package","install","validate","ci-status","check-workflows","check-commit-identity","check-sha","security-linux","security-windows","source-closure","ledger","migration-check"])]
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
                }
                let options = Options::try_parse_from(
                    std::iter::once("security-windows".to_owned()).chain(args.iter().cloned()),
                )?;
                let image = options
                    .authority_image
                    .or(options.image)
                    .expect("required image argument checked by clap");
                let report = revayat::windows_security::native::run_registry_authority(&image)?;
                println!("{report}");
                Ok(0)
            }
            #[cfg(not(windows))]
            {
                bail!("native Windows security verification requires Windows");
            }
        }
        "ci-status" => revayat::ci::cli_status(args),
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
    let mut command = revayat::runtime::CommandSpec::new(std::env::current_exe()?.into_os_string())
        .args([
            "--worker".to_owned(),
            "--timeout".into(),
            cli.timeout.to_string(),
            cli.command.clone(),
        ])
        .args(cli.arguments.iter().cloned());
    command.timeout = Duration::from_secs(cli.timeout);
    let output = if ["build", "tex-container", "run-check", "security-linux"]
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
            } else if error
                .downcast_ref::<revayat::runtime::DeadlineExceeded>()
                .is_some()
            {
                eprintln!("revayat-scientific: command timed out; owned process tree terminated");
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
