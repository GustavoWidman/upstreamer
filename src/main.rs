use std::process::ExitCode;

fn main() -> ExitCode {
    eprintln!("upstreamer: no commands are available in this build");
    ExitCode::from(2)
}
