mod analyzer;
mod cli;
mod entropy;
mod hash;
mod model;
mod render;
mod strings;

use anyhow::Result;
use clap::Parser;
use std::process;

use crate::analyzer::{AnalyzeOptions, analyze_path, summarize_path};
use crate::cli::{Cli, Commands};

pub use crate::analyzer::{
    AnalyzeOptions as PublicAnalyzeOptions, analyze_path as public_analyze_path,
    summarize_path as public_summarize_path,
};
pub use crate::model::{BinaryFormat, BinaryReport, SummaryReport};

pub fn run() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Analyze {
            file,
            json,
            yara,
            fail_on_risk,
            strings_interesting_only,
        } => {
            let report = analyze_path(
                &file,
                &AnalyzeOptions {
                    include_yara: yara,
                    strings_interesting_only,
                },
            )?;

            if json {
                println!("{}", serde_json::to_string_pretty(&report)?);
            } else {
                println!("{}", render::render_terminal(&report));
                if yara {
                    if let Some(rule) = &report.yara_rule {
                        println!();
                        println!("{rule}");
                    }
                }
            }

            if fail_on_risk.is_some_and(|threshold| report.risk_score >= threshold) {
                process::exit(2);
            }
        }
        Commands::Summarize {
            path,
            json,
            fail_on_risk,
            strings_interesting_only,
        } => {
            let summary = summarize_path(
                &path,
                &AnalyzeOptions {
                    include_yara: false,
                    strings_interesting_only,
                },
            )?;

            if json {
                println!("{}", serde_json::to_string_pretty(&summary)?);
            } else {
                println!("{}", render::render_summary(&summary));
            }

            if fail_on_risk.is_some_and(|threshold| {
                summary
                    .reports
                    .iter()
                    .any(|report| report.risk_score >= threshold)
            }) {
                process::exit(2);
            }
        }
    }

    Ok(())
}
