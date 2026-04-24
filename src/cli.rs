use std::path::PathBuf;

use clap::{Parser, Subcommand};

#[derive(Debug, Parser)]
#[command(
    name = "binscope",
    version,
    about = "PE/ELF/Mach-O binary analyzer and packer detector"
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Debug, Subcommand)]
pub enum Commands {
    Analyze {
        file: PathBuf,
        #[arg(long, help = "Emit JSON instead of the terminal report")]
        json: bool,
        #[arg(long, help = "Generate a YARA rule skeleton")]
        yara: bool,
        #[arg(
            long,
            value_parser = clap::value_parser!(u8).range(0..=100),
            help = "Exit with code 2 when the analyzed file risk score is at or above this threshold"
        )]
        fail_on_risk: Option<u8>,
        #[arg(
            long,
            help = "Only keep non-generic carved strings in the final report output"
        )]
        strings_interesting_only: bool,
    },
    Summarize {
        path: PathBuf,
        #[arg(long, help = "Emit JSON instead of the terminal report")]
        json: bool,
        #[arg(
            long,
            value_parser = clap::value_parser!(u8).range(0..=100),
            help = "Exit with code 2 when any summarized file risk score is at or above this threshold"
        )]
        fail_on_risk: Option<u8>,
        #[arg(
            long,
            help = "Only keep non-generic carved strings while scanning individual files"
        )]
        strings_interesting_only: bool,
    },
}
