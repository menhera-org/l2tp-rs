// SPDX-License-Identifier: MIT

#[cfg(target_os = "linux")]
mod cli;
#[cfg(target_os = "linux")]
mod output;

#[cfg(target_os = "linux")]
fn main() -> std::process::ExitCode {
    cli::main()
}

#[cfg(not(target_os = "linux"))]
fn main() -> std::process::ExitCode {
    eprintln!("error: l2tp is only supported on Linux");
    std::process::ExitCode::FAILURE
}
