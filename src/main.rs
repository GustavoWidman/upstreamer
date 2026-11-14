//! `upstreamer run [--config] <file> [--workers N]`
//! `upstreamer check [--config] <file> [--expect-tcp P,..] [--expect-udp P,..]`
//! `upstreamer check --fragment <file>`
//!
//! Exit codes: 0 ok, 1 invalid config (diagnostics on stderr, one per line, each with the JSON
//! pointer of the offending value and the site/step name), 2 usage, 3 runtime failure.

use std::path::PathBuf;
use std::process::ExitCode;

use upstreamer::{CheckInput, ExpectedPorts, RunOptions, StartError};

const USAGE: &str = "usage:
  upstreamer run [--config] <file> [--workers N]
  upstreamer check [--config] <file> [--expect-tcp PORT,..] [--expect-udp PORT,..]
  upstreamer check --fragment <file>";

enum Command {
    Run(RunOptions),
    Check(CheckInput),
    Help,
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match parse(&args) {
        Ok(Command::Help) => {
            println!("{USAGE}");
            ExitCode::SUCCESS
        }
        Ok(Command::Run(opts)) => match upstreamer::run(opts) {
            Ok(()) => ExitCode::SUCCESS,
            Err(e @ StartError::Config(_)) => {
                eprintln!("{e}");
                ExitCode::from(1)
            }
            Err(e) => {
                eprintln!("upstreamer: {e}");
                ExitCode::from(3)
            }
        },
        Ok(Command::Check(input)) => match upstreamer::check(input) {
            Ok(report) => {
                for warning in &report.warnings {
                    eprintln!("{warning}");
                }
                println!("ok: {} sites, {} steps", report.sites, report.steps);
                ExitCode::SUCCESS
            }
            Err(diagnostics) => {
                for diagnostic in &diagnostics {
                    eprintln!("{diagnostic}");
                }
                ExitCode::from(1)
            }
        },
        Err(message) => {
            eprintln!("upstreamer: {message}\n{USAGE}");
            ExitCode::from(2)
        }
    }
}

fn parse(args: &[String]) -> Result<Command, String> {
    let (command, rest) = match args.split_first() {
        Some((command, rest)) => (command.as_str(), rest),
        None => return Err("missing command".into()),
    };
    let mut file: Option<PathBuf> = None;
    let mut fragment: Option<PathBuf> = None;
    let mut workers: Option<u16> = None;
    let mut expect: Option<ExpectedPorts> = None;
    let mut rest = rest.iter();
    while let Some(arg) = rest.next() {
        let mut value = |flag: &str| {
            rest.next()
                .cloned()
                .ok_or_else(|| format!("{flag} needs a value"))
        };
        match (command, arg.as_str()) {
            (_, "-h" | "--help") => return Ok(Command::Help),
            ("run" | "check", "--config") => {
                set_once(&mut file, value("--config")?.into(), "a config file")?
            }
            ("run", "--workers") => {
                let n = value("--workers")?;
                let n = n
                    .parse()
                    .ok()
                    .filter(|&n| n > 0)
                    .ok_or_else(|| format!("--workers: not a positive number: {n:?}"))?;
                workers = Some(n);
            }
            ("check", "--fragment") => set_once(
                &mut fragment,
                value("--fragment")?.into(),
                "a fragment file",
            )?,
            ("check", "--expect-tcp") => {
                expect.get_or_insert_with(ExpectedPorts::default).tcp =
                    ports(&value("--expect-tcp")?)?
            }
            ("check", "--expect-udp") => {
                expect.get_or_insert_with(ExpectedPorts::default).udp =
                    ports(&value("--expect-udp")?)?
            }
            ("run" | "check", flag) if flag.starts_with('-') => {
                return Err(format!("unknown option {flag}"));
            }
            ("run" | "check", path) => set_once(&mut file, path.into(), "a config file")?,
            _ => break,
        }
    }
    match command {
        "-h" | "--help" | "help" => Ok(Command::Help),
        "run" => Ok(Command::Run(RunOptions {
            config: file.ok_or("run needs a config file")?,
            workers,
        })),
        "check" => match (file, fragment) {
            (Some(path), None) => Ok(Command::Check(CheckInput::Config { path, expect })),
            (None, Some(path)) if expect.is_none() => {
                Ok(Command::Check(CheckInput::Fragment(path)))
            }
            (None, Some(_)) => {
                Err("--expect-tcp/--expect-udp apply to a config, not a fragment".into())
            }
            (Some(_), Some(_)) => Err("check takes a config or a fragment, not both".into()),
            (None, None) => Err("check needs a config file or --fragment <file>".into()),
        },
        other => Err(format!("unknown command {other:?}")),
    }
}

fn set_once(slot: &mut Option<PathBuf>, path: PathBuf, what: &str) -> Result<(), String> {
    match slot.replace(path) {
        None => Ok(()),
        Some(_) => Err(format!("more than one {what}")),
    }
}

/// `80,443`; empty means no ports (the NixOS module passes an empty list as-is).
fn ports(list: &str) -> Result<Vec<u16>, String> {
    list.split(',')
        .map(str::trim)
        .filter(|p| !p.is_empty())
        .map(|p| p.parse().map_err(|_| format!("not a port: {p:?}")))
        .collect()
}
