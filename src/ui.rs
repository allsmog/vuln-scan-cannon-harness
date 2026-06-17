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

/// Open a file/URL in the OS default handler, cross-platform. Best-effort: a
/// missing opener is not fatal (the caller already wrote the file to disk).
pub fn open_path(path: &std::path::Path) -> std::io::Result<()> {
    #[cfg(target_os = "macos")]
    let mut cmd = std::process::Command::new("open");
    #[cfg(target_os = "windows")]
    let mut cmd = {
        let mut c = std::process::Command::new("cmd");
        c.args(["/C", "start", ""]);
        c
    };
    #[cfg(all(unix, not(target_os = "macos")))]
    let mut cmd = std::process::Command::new("xdg-open");

    cmd.arg(path);
    cmd.spawn().map(|_| ())
}
