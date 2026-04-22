//! Human-in-the-loop approval gate.
//!
//! Before executing any side-effectful proposal (write_file, …), the CLI
//! asks the user to confirm via stdin. To keep scripted use safe we:
//!
//! * Auto-reject when stdin is not a TTY (piped input, CI, etc.).
//! * Auto-reject when `--non-interactive` was passed.
//! * Apply a 60-second timeout so a stalled operator can't block a batch
//!   job forever — the proposal is rejected, not silently approved.
//!
//! All human-facing output goes to **stderr** so stdout stays clean for
//! scripts that parse reli's result.

use std::io::{self, BufRead, IsTerminal, Write};
use std::sync::mpsc;
use std::thread;
use std::time::Duration;

pub const APPROVAL_TIMEOUT: Duration = Duration::from_secs(60);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ApprovalMode {
    Interactive,
    NonInteractive,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ApprovalDecision {
    Approved,
    Rejected,
    /// User did not respond within `APPROVAL_TIMEOUT`.
    Timeout,
    /// Non-interactive mode or stdin is not a TTY — the proposal is
    /// auto-rejected. Distinguished from `Rejected` so the CLI can
    /// emit a clearer error message.
    AutoRejected,
}

impl ApprovalDecision {
    pub fn is_approved(self) -> bool {
        matches!(self, ApprovalDecision::Approved)
    }
}

pub fn request_approval(summary: &str, mode: ApprovalMode) -> ApprovalDecision {
    if mode == ApprovalMode::NonInteractive || !io::stdin().is_terminal() {
        eprintln!("{summary}");
        eprintln!("[reli] non-interactive: propuesta NO aprobada automáticamente");
        return ApprovalDecision::AutoRejected;
    }

    prompt_with_timeout(summary, APPROVAL_TIMEOUT)
}

fn prompt_with_timeout(summary: &str, timeout: Duration) -> ApprovalDecision {
    eprintln!("{summary}");
    eprint!(
        "[reli] ¿aprobar propuesta? [y/N] (timeout {}s): ",
        timeout.as_secs()
    );
    let _ = io::stderr().flush();

    let (tx, rx) = mpsc::channel::<String>();
    thread::spawn(move || {
        let mut line = String::new();
        if io::stdin().lock().read_line(&mut line).is_ok() {
            let _ = tx.send(line);
        }
    });

    match rx.recv_timeout(timeout) {
        Ok(line) => parse_response(&line),
        Err(mpsc::RecvTimeoutError::Timeout) => {
            eprintln!();
            eprintln!(
                "[reli] timeout ({}s) — propuesta NO aprobada",
                timeout.as_secs()
            );
            ApprovalDecision::Timeout
        }
        Err(mpsc::RecvTimeoutError::Disconnected) => {
            eprintln!("[reli] stdin cerrado — propuesta NO aprobada");
            ApprovalDecision::AutoRejected
        }
    }
}

/// Classify a single line of user input. Exposed for unit tests.
pub fn parse_response(line: &str) -> ApprovalDecision {
    let trimmed = line.trim();
    match trimmed.to_ascii_lowercase().as_str() {
        "y" | "yes" | "s" | "si" => ApprovalDecision::Approved,
        _ => ApprovalDecision::Rejected,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn yes_variants_are_approved() {
        for yes in [
            "y", "Y", "yes", "YES", "Yes\n", "  y  ", "s", "Si", "SI", "si\r\n",
        ] {
            assert_eq!(
                parse_response(yes),
                ApprovalDecision::Approved,
                "input {yes:?}"
            );
        }
    }

    #[test]
    fn anything_else_is_rejected() {
        for no in [
            "n", "no", "NO", "", "\n", "\r\n", "blah", "yeah", " 1 ", "true",
        ] {
            assert_eq!(
                parse_response(no),
                ApprovalDecision::Rejected,
                "input {no:?}"
            );
        }
    }

    #[test]
    fn is_approved_helper() {
        assert!(ApprovalDecision::Approved.is_approved());
        assert!(!ApprovalDecision::Rejected.is_approved());
        assert!(!ApprovalDecision::Timeout.is_approved());
        assert!(!ApprovalDecision::AutoRejected.is_approved());
    }
}
