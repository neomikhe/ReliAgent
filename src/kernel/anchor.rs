use std::fs::{File, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};

use super::audit::SignedEntry;
use super::{KernelError, KernelResult};

pub const DEFAULT_ANCHOR_ROTATE_LINES: u64 = 100;
const ANCHOR_FILENAME: &str = "anchor.log";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AnchorRow {
    pub sequence_no: u64,
    pub hmac: String,
    pub timestamp: String,
}

pub struct AnchorLog {
    dir: PathBuf,
    rotate_threshold: u64,
    lines_in_current: u64,
}

impl AnchorLog {
    pub fn open(dir: &Path, rotate_threshold: u64) -> KernelResult<Self> {
        if rotate_threshold == 0 {
            return Err(KernelError::Audit("rotate_threshold must be > 0".into()));
        }
        std::fs::create_dir_all(dir)?;
        let path = dir.join(ANCHOR_FILENAME);
        let lines = if path.exists() {
            count_lines(&path)?
        } else {
            0
        };
        Ok(Self {
            dir: dir.to_path_buf(),
            rotate_threshold,
            lines_in_current: lines,
        })
    }

    pub fn append_entry(&mut self, signed: &SignedEntry) -> KernelResult<()> {
        if self.lines_in_current >= self.rotate_threshold {
            self.rotate()?;
        }
        let path = self.dir.join(ANCHOR_FILENAME);
        let mut f = OpenOptions::new().create(true).append(true).open(&path)?;
        writeln!(
            f,
            "{}\t{}\t{}",
            signed.entry.sequence_no, signed.hmac, signed.entry.timestamp,
        )?;
        let _ = f.sync_data();
        self.lines_in_current += 1;
        Ok(())
    }

    fn rotate(&mut self) -> KernelResult<()> {
        let current = self.dir.join(ANCHOR_FILENAME);
        if !current.exists() {
            self.lines_in_current = 0;
            return Ok(());
        }
        let next = self.next_rotated_path();
        std::fs::rename(&current, &next)?;
        self.lines_in_current = 0;
        Ok(())
    }

    fn next_rotated_path(&self) -> PathBuf {
        let mut n: u64 = 1;
        loop {
            let p = self.dir.join(format!("{ANCHOR_FILENAME}.{n}"));
            if !p.exists() {
                return p;
            }
            n += 1;
        }
    }

    pub fn latest(&self) -> KernelResult<Option<AnchorRow>> {
        let current = self.dir.join(ANCHOR_FILENAME);
        if current.exists() {
            if let Some(row) = last_row_of(&current)? {
                return Ok(Some(row));
            }
        }
        let mut highest: u64 = 0;
        let mut highest_path: Option<PathBuf> = None;
        if let Ok(entries) = std::fs::read_dir(&self.dir) {
            let prefix = format!("{ANCHOR_FILENAME}.");
            for entry in entries.flatten() {
                let p = entry.path();
                if let Some(name) = p.file_name().and_then(|n| n.to_str()) {
                    if let Some(suffix) = name.strip_prefix(&prefix) {
                        if let Ok(n) = suffix.parse::<u64>() {
                            if n >= highest {
                                highest = n;
                                highest_path = Some(p);
                            }
                        }
                    }
                }
            }
        }
        if let Some(p) = highest_path {
            return last_row_of(&p);
        }
        Ok(None)
    }

    #[allow(dead_code)]
    pub fn rotated_count(&self) -> KernelResult<u64> {
        let mut count: u64 = 0;
        let prefix = format!("{ANCHOR_FILENAME}.");
        for entry in std::fs::read_dir(&self.dir)?.flatten() {
            if let Some(name) = entry.path().file_name().and_then(|n| n.to_str()) {
                if let Some(suffix) = name.strip_prefix(&prefix) {
                    if suffix.parse::<u64>().is_ok() {
                        count += 1;
                    }
                }
            }
        }
        Ok(count)
    }
}

fn count_lines(path: &Path) -> KernelResult<u64> {
    let f = File::open(path)?;
    let mut count: u64 = 0;
    for line in BufReader::new(f).lines() {
        let line = line?;
        if !line.trim().is_empty() {
            count += 1;
        }
    }
    Ok(count)
}

fn last_row_of(path: &Path) -> KernelResult<Option<AnchorRow>> {
    let f = File::open(path)?;
    let mut last_valid: Option<AnchorRow> = None;
    for line in BufReader::new(f).lines() {
        let line = line?;
        if line.trim().is_empty() {
            continue;
        }
        if let Some(row) = parse_anchor_line(&line) {
            last_valid = Some(row);
        }
    }
    Ok(last_valid)
}

fn parse_anchor_line(line: &str) -> Option<AnchorRow> {
    let mut parts = line.splitn(3, '\t');
    let seq = parts.next()?.parse::<u64>().ok()?;
    let hmac = parts.next()?.to_string();
    let timestamp = parts.next()?.to_string();
    if hmac.is_empty() || timestamp.is_empty() {
        return None;
    }
    Some(AnchorRow {
        sequence_no: seq,
        hmac,
        timestamp,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::kernel::audit::{AuditEntry, AuditStatus, HASH_FORMAT_VERSION};
    use tempfile::TempDir;

    fn sample_signed(seq: u64) -> SignedEntry {
        SignedEntry {
            entry: AuditEntry {
                sequence_no: seq,
                timestamp: format!("2026-04-20T12:00:{:02}Z", seq.min(59)),
                tool: "write_file".into(),
                args_hash: "deadbeef".into(),
                status: AuditStatus::Ok,
                prev_hmac: if seq == 0 {
                    "GENESIS".into()
                } else {
                    format!("prev_{}", seq - 1)
                },
                hash_format_version: HASH_FORMAT_VERSION,
            },
            hmac: format!("hmac_{seq}"),
        }
    }

    #[test]
    fn open_creates_dir_and_starts_empty() {
        let tmp = TempDir::new().unwrap();
        let sub = tmp.path().join("anchors");
        let anchor = AnchorLog::open(&sub, 10).unwrap();
        assert!(sub.exists());
        assert!(anchor.latest().unwrap().is_none());
    }

    #[test]
    fn open_rejects_zero_threshold() {
        let tmp = TempDir::new().unwrap();
        let res = AnchorLog::open(tmp.path(), 0);
        assert!(matches!(res, Err(KernelError::Audit(_))));
    }

    #[test]
    fn append_writes_and_latest_reads_last() {
        let tmp = TempDir::new().unwrap();
        let mut anchor = AnchorLog::open(tmp.path(), 10).unwrap();
        for i in 0..3 {
            anchor.append_entry(&sample_signed(i)).unwrap();
        }
        let row = anchor.latest().unwrap().expect("expected a row");
        assert_eq!(row.sequence_no, 2);
        assert_eq!(row.hmac, "hmac_2");
    }

    #[test]
    fn rotation_happens_at_threshold() {
        let tmp = TempDir::new().unwrap();
        let mut anchor = AnchorLog::open(tmp.path(), 3).unwrap();
        for i in 0..7 {
            anchor.append_entry(&sample_signed(i)).unwrap();
        }
        assert!(anchor.rotated_count().unwrap() >= 2);
        let row = anchor.latest().unwrap().expect("expected a row");
        assert_eq!(row.sequence_no, 6);
    }

    #[test]
    fn latest_falls_back_to_rotated_when_current_empty() {
        let tmp = TempDir::new().unwrap();
        let mut anchor = AnchorLog::open(tmp.path(), 2).unwrap();
        anchor.append_entry(&sample_signed(0)).unwrap();
        anchor.append_entry(&sample_signed(1)).unwrap();
        // Forzar rotación pero sin escribir nuevas entradas: el anchor.log
        // actual acaba vacío; latest() debe caer al rotado.
        anchor.append_entry(&sample_signed(2)).unwrap();
        std::fs::write(tmp.path().join("anchor.log"), b"").unwrap();
        let row = anchor.latest().unwrap().expect("expected fallback row");
        assert!(row.sequence_no == 1 || row.sequence_no == 2);
    }

    #[test]
    fn reopening_picks_up_existing_line_count() {
        let tmp = TempDir::new().unwrap();
        {
            let mut a = AnchorLog::open(tmp.path(), 10).unwrap();
            for i in 0..5 {
                a.append_entry(&sample_signed(i)).unwrap();
            }
        }
        let reopened = AnchorLog::open(tmp.path(), 10).unwrap();
        assert_eq!(reopened.lines_in_current, 5);
    }

    #[test]
    fn parse_anchor_line_rejects_malformed() {
        assert!(parse_anchor_line("no-tabs-here").is_none());
        assert!(parse_anchor_line("xx\thmac\ttime").is_none()); // seq no numérico
        assert!(parse_anchor_line("5\t\ttime").is_none()); // hmac vacío
        let ok = parse_anchor_line("42\tabc\t2026-01-01T00:00:00Z").unwrap();
        assert_eq!(ok.sequence_no, 42);
        assert_eq!(ok.hmac, "abc");
    }

    #[test]
    fn append_ignores_sync_data_errors() {
        // Smoke: append works even if sync_data best-effort fails (which it
        // shouldn't on tempdir, but this keeps the contract explicit).
        let tmp = TempDir::new().unwrap();
        let mut anchor = AnchorLog::open(tmp.path(), 10).unwrap();
        anchor.append_entry(&sample_signed(0)).unwrap();
        assert_eq!(anchor.lines_in_current, 1);
    }
}
