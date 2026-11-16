//! Native document-docx command options and content-free diagnostics.
use super::*;

pub fn cli(args: &[String]) -> Result<i32> {
    use clap::{Parser, Subcommand};
    #[derive(Parser)]
    #[command(
        name = "document-docx",
        about = "Inspect, create, edit and structurally validate DOCX"
    )]
    struct Options {
        #[command(subcommand)]
        command: Command,
    }
    #[derive(Subcommand)]
    enum Command {
        Inspect {
            input: PathBuf,
            #[arg(long)]
            output: PathBuf,
        },
        Edit {
            input: PathBuf,
            output: PathBuf,
            #[arg(long)]
            patch: PathBuf,
        },
        Create {
            input: PathBuf,
            output: PathBuf,
        },
        Validate {
            input: PathBuf,
        },
    }
    let parsed = Options::try_parse_from(
        std::iter::once("document-docx".to_owned()).chain(args.iter().cloned()),
    )?;
    let result = (|| -> Result<()> {
        match parsed.command {
            Command::Inspect { input, output } => {
                write_report(&inspect_package(&input)?, &output, &input)
            }
            Command::Edit {
                input,
                output,
                patch,
            } => {
                publication::validate_destination(&output, &[input.clone(), patch.clone()])?;
                let patches = load_json(&patch)?;
                edit_package(&input, &output, &patches, &[patch])
            }
            Command::Create { input, output } => create_document(&input, &output),
            Command::Validate { input } => require_editable(&read_package(&input)?.unsupported),
        }
    })();
    match result {
        Ok(()) => {
            println!("DOCX operation completed; layout/render verification remains separate.");
            Ok(0)
        }
        Err(_) => {
            eprintln!(
                "document-docx: invalid document or failed operation; original inputs preserved."
            );
            Ok(2)
        }
    }
}
