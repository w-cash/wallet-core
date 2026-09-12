#![forbid(unsafe_code)]

#[path = "main.rs"]
mod shared;

fn main() -> std::process::ExitCode {
    shared::main()
}
