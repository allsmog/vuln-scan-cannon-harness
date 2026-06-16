//! Tiny ANSI color helper, gated on TTY (so piped output stays clean).

use std::io::IsTerminal;

fn code(name: &str) -> &'static str {
    match name {
        "dim" => "2;90",
        "red" => "91",
        "bold" => "1",
        "recon" => "96",
        "find" => "94",
        "verify" => "93",
        "threat" => "95",
        "chain" => "35",
        "report" => "92",
        "cannon" => "38;5;208",
        _ => "0",
    }
}

pub fn color(text: &str, name: &str) -> String {
    if std::io::stdout().is_terminal() {
        format!("\x1b[{}m{}\x1b[0m", code(name), text)
    } else {
        text.to_string()
    }
}

pub fn ecolor(text: &str, name: &str) -> String {
    if std::io::stderr().is_terminal() {
        format!("\x1b[{}m{}\x1b[0m", code(name), text)
    } else {
        text.to_string()
    }
}
