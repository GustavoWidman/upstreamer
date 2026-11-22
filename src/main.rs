//! `upstreamer run [--config] <file> [--workers N] [--reload-socket <path>]`
//! `upstreamer reload --reload-socket <path>`
//! `upstreamer check [--config] <file> [--expect-tcp P,..] [--expect-udp P,..]`
//! `upstreamer check --fragment <file>`
//! `upstreamer example [name | --list]`
//! `upstreamer convert <file>`
//!
//! A config is JSON, or TOML when the file name ends in `.toml`.
//!
//! Exit codes: 0 ok, 1 invalid config (diagnostics on stderr, one per line, each with the JSON
//! pointer of the offending value, the site/step name and, for TOML, the line and column), 2
//! usage, 3 runtime failure. `reload` exits 1 when the running process kept what it served, and
//! 3 when it could not be asked.

use std::path::{Path, PathBuf};
use std::process::ExitCode;

use upstreamer::{
    CheckInput, CheckReport, ExpectedPorts, ReloadError, ReloadOptions, RunOptions, StartError,
};

#[global_allocator]
static ALLOCATOR: mimalloc::MiMalloc = mimalloc::MiMalloc;

const USAGE: &str = "usage:
  upstreamer run [--config] <file> [--workers N] [--reload-socket PATH]
  upstreamer reload --reload-socket PATH
  upstreamer check [--config] <file> [--expect-tcp PORT,..] [--expect-udp PORT,..]
  upstreamer check --fragment <file>
  upstreamer example [NAME | --list]
  upstreamer convert <file>

A config is JSON, or TOML when its name ends in .toml.
`reload` asks the process that runs with the same --reload-socket to reload, waits until it
has, and fails when the reload did.
`example` prints a commented config to start from; `convert` prints a JSON file as TOML, or
a TOML file as JSON.";

/// The configs `upstreamer example` prints; the files in `examples/`, which the tests check.
const EXAMPLES: &[(&str, &str, &str)] = &[
    (
        "minimal",
        "one origin on port 8080",
        include_str!("../examples/minimal.toml"),
    ),
    (
        "acme",
        "HTTPS with certificates issued by upstreamer itself",
        include_str!("../examples/acme.toml"),
    ),
    (
        "load-balanced",
        "balancing, retries and health checks over several origins",
        include_str!("../examples/load-balanced.toml"),
    ),
    (
        "rate-limited-api",
        "a rate limit that answers 429 with Retry-After",
        include_str!("../examples/rate-limited-api.toml"),
    ),
    (
        "metrics",
        "a Prometheus endpoint on a loopback listener",
        include_str!("../examples/metrics.toml"),
    ),
    (
        "cloudflare",
        "the client address behind Cloudflare or another proxy",
        include_str!("../examples/cloudflare.toml"),
    ),
    (
        "kubernetes",
        "origins discovered from Kubernetes EndpointSlices",
        include_str!("../examples/kubernetes.toml"),
    ),
];

enum Command {
    Run(RunOptions),
    Reload(ReloadOptions),
    Check(CheckInput),
    Example(Option<String>),
    Convert(PathBuf),
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
        Ok(Command::Reload(opts)) => {
            let outcome = upstreamer::reload(opts);
            let done = outcome.is_ok();
            let (text, code) = reloaded(outcome, under_service_manager());
            if done {
                println!("{text}");
            } else {
                eprintln!("upstreamer: {text}");
            }
            ExitCode::from(code)
        }
        Ok(Command::Check(input)) => match upstreamer::check(input) {
            Ok(report) => {
                for warning in &report.warnings {
                    eprintln!("{warning}");
                }
                println!("{}", summary(&report));
                ExitCode::SUCCESS
            }
            Err(diagnostics) => {
                for diagnostic in &diagnostics {
                    eprintln!("{diagnostic}");
                }
                ExitCode::from(1)
            }
        },
        Ok(Command::Example(name)) => example(name.as_deref()),
        Ok(Command::Convert(path)) => convert_file(&path),
        Err(message) => {
            eprintln!("upstreamer: {message}\n{USAGE}");
            ExitCode::from(2)
        }
    }
}

/// Whether a service manager runs this process as the command that reloads a service:
/// systemd gives such a command the service's main process in `MAINPID`.
fn under_service_manager() -> bool {
    std::env::var_os("MAINPID").is_some()
}

/// What `reload` prints, and its exit code.
///
/// A running process that speaks no protocol version this program speaks was not asked. As
/// the reload command of a `Type=notify-reload` unit, exiting with success leaves the reload
/// to the signal systemd sends next, which reloads but cannot say that it failed; anywhere
/// else nothing would follow, so it is a failure.
fn reloaded(outcome: Result<String, ReloadError>, under_service_manager: bool) -> (String, u8) {
    match outcome {
        Ok(status) => (status, 0),
        Err(e @ ReloadError::Failed(_)) => (e.to_string(), 1),
        Err(e @ ReloadError::Incompatible { .. }) if under_service_manager => (
            format!(
                "{e}; leaving the reload to the service manager's signal, after which only the \
                 service's status says whether it failed"
            ),
            0,
        ),
        Err(e @ ReloadError::Incompatible { .. }) => {
            (format!("{e}; send it SIGHUP to reload it"), 3)
        }
        Err(e @ ReloadError::Unreachable(_)) => (e.to_string(), 3),
    }
}

/// What `check` prints on success: the sizes of the config, then what each feature it uses
/// costs at run time (nothing is said about a feature the config does not use).
fn summary(report: &CheckReport) -> String {
    let costs = &report.costs;
    let mut line = format!("ok: {} sites, {} steps", report.sites, report.steps);
    if costs.pools > 0 {
        line += &format!(
            ", {} ({}, {} probed)",
            count(costs.pools, "pool"),
            count(costs.origins, "origin"),
            costs.probed
        );
    }
    if costs.sources > 0 {
        line += &format!(", {}", count(costs.sources, "discovery source"));
    }
    if costs.limits > 0 {
        line += &format!(
            ", {} ({} KiB)",
            count(costs.limits, "limit"),
            costs.limit_bytes.div_ceil(1024)
        );
    }
    if let Some(series) = costs.series {
        line += &format!(", metrics on ({series} series)");
    }
    line
}

fn count(n: usize, noun: &str) -> String {
    format!("{n} {noun}{}", if n == 1 { "" } else { "s" })
}

fn example(name: Option<&str>) -> ExitCode {
    let Some(name) = name else {
        print!("{}", EXAMPLES[0].2);
        return ExitCode::SUCCESS;
    };
    if name == "--list" {
        for (name, about, _) in EXAMPLES {
            println!("{name:<18}{about}");
        }
        return ExitCode::SUCCESS;
    }
    match EXAMPLES.iter().find(|(n, ..)| *n == name) {
        Some((_, _, text)) => {
            print!("{text}");
            ExitCode::SUCCESS
        }
        None => {
            let names: Vec<&str> = EXAMPLES.iter().map(|(n, ..)| *n).collect();
            eprintln!(
                "upstreamer: no example named {name:?}; the examples are {}",
                names.join(", ")
            );
            ExitCode::from(2)
        }
    }
}

/// A `.toml` file as JSON, any other file as TOML, on stdout. Only the syntax is converted;
/// whether the document is a valid config is `check`'s question.
fn convert_file(path: &Path) -> ExitCode {
    let bytes = match std::fs::read(path) {
        Ok(bytes) => bytes,
        Err(e) => {
            eprintln!("{}: cannot read: {e}", path.display());
            return ExitCode::from(3);
        }
    };
    match convert_bytes(path, &bytes) {
        Ok(text) => {
            print!("{text}");
            ExitCode::SUCCESS
        }
        Err(message) => {
            eprintln!("{}: {message}", path.display());
            ExitCode::from(1)
        }
    }
}

fn convert_bytes(path: &Path, bytes: &[u8]) -> Result<String, String> {
    let text = std::str::from_utf8(bytes).map_err(|e| format!("not UTF-8: {e}"))?;
    if path
        .extension()
        .is_some_and(|e| e.eq_ignore_ascii_case("toml"))
    {
        upstreamer::convert::toml_to_json(text)
    } else {
        upstreamer::convert::json_to_toml(text)
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
    let mut reload_socket: Option<PathBuf> = None;
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
            ("example", "--list") => {
                set_once(&mut file, "--list".into(), "an example name")?;
            }
            ("example" | "convert", flag) if flag.starts_with('-') => {
                return Err(format!("unknown option {flag}"));
            }
            ("example", name) => set_once(&mut file, name.into(), "an example name")?,
            ("convert", path) => set_once(&mut file, path.into(), "a file")?,
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
            ("run" | "reload", "--reload-socket") => set_once(
                &mut reload_socket,
                value("--reload-socket")?.into(),
                "a reload socket",
            )?,
            ("reload", other) => return Err(format!("unexpected {other:?}")),
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
        "example" => Ok(Command::Example(
            file.map(|name| name.to_string_lossy().into_owned()),
        )),
        "convert" => Ok(Command::Convert(file.ok_or("convert needs a file")?)),
        "run" => Ok(Command::Run(RunOptions {
            config: file.ok_or("run needs a config file")?,
            workers,
            reload_socket,
        })),
        "reload" => Ok(Command::Reload(ReloadOptions {
            socket: reload_socket.ok_or("reload needs --reload-socket <path>")?,
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

#[cfg(test)]
mod tests {
    use super::*;
    use upstreamer::Costs;

    fn report(costs: Costs) -> CheckReport {
        CheckReport {
            sites: 3,
            steps: 14,
            warnings: Vec::new(),
            costs,
        }
    }

    #[test]
    fn reload_exits_with_what_came_of_the_reload() {
        let failed = || {
            Err(ReloadError::Failed(
                "still serving generation 2: broken".into(),
            ))
        };
        let unreachable = || Err(ReloadError::Unreachable("no process listens at /x".into()));
        let incompatible = || {
            Err(ReloadError::Incompatible {
                ours: vec![1],
                theirs: vec![2],
            })
        };
        for under_service_manager in [false, true] {
            assert_eq!(
                reloaded(Ok("serving generation 3".into()), under_service_manager),
                ("serving generation 3".to_owned(), 0)
            );
            assert_eq!(
                reloaded(failed(), under_service_manager),
                (
                    "reload failed, still serving generation 2: broken".to_owned(),
                    1
                )
            );
            assert_eq!(
                reloaded(unreachable(), under_service_manager),
                ("no process listens at /x".to_owned(), 3)
            );
        }
        assert_eq!(
            reloaded(incompatible(), true),
            (
                "the running process speaks reload protocol version 2, this program 1; leaving \
                 the reload to the service manager's signal, after which only the service's \
                 status says whether it failed"
                    .to_owned(),
                0
            ),
            "the manager's signal reloads a process this program cannot ask"
        );
        assert_eq!(
            reloaded(incompatible(), false),
            (
                "the running process speaks reload protocol version 2, this program 1; send it \
                 SIGHUP to reload it"
                    .to_owned(),
                3
            ),
            "and without a manager nothing would"
        );
    }

    #[test]
    fn the_summary_says_nothing_of_features_the_config_does_not_use() {
        assert_eq!(summary(&report(Costs::default())), "ok: 3 sites, 14 steps");
    }

    #[test]
    fn the_summary_counts_what_each_feature_costs() {
        let costs = Costs {
            pools: 3,
            origins: 7,
            probed: 2,
            limits: 2,
            limit_bytes: 265 * 1024,
            series: Some(212),
            sources: 1,
        };
        assert_eq!(
            summary(&report(costs)),
            "ok: 3 sites, 14 steps, 3 pools (7 origins, 2 probed), 1 discovery source, \
             2 limits (265 KiB), metrics on (212 series)"
        );
    }

    #[test]
    fn a_partial_kibibyte_of_buckets_counts_as_a_whole_one() {
        let costs = Costs {
            limits: 1,
            limit_bytes: 1025,
            ..Costs::default()
        };
        assert!(summary(&report(costs)).ends_with("1 limit (2 KiB)"));
    }
}
