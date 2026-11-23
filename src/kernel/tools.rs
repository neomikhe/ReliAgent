use std::io::Read;
use std::path::PathBuf;

use super::policy::{MAX_FILE_SIZE, validate_write_path};
use super::sandbox::Sandbox;
use super::{KernelError, KernelResult};

pub fn write_file(sandbox: &Sandbox, path: &str, content: &[u8]) -> KernelResult<()> {
    if content.len() > MAX_FILE_SIZE {
        return Err(KernelError::FileTooLarge {
            actual: content.len(),
            max: MAX_FILE_SIZE,
        });
    }

    let safe_path = validate_write_path(path)?;

    if let Some(parent) = safe_path.parent()
        && !parent.as_os_str().is_empty()
    {
        sandbox.dir().create_dir_all(parent)?;
    }

    sandbox.dir().write(&safe_path, content)?;
    Ok(())
}

/// Read a file inside the sandbox. Refuses to load more than MAX_FILE_SIZE
/// bytes even if the file grows under us — we stat first, cap the reader
/// second.
pub fn read_file(sandbox: &Sandbox, path: &str) -> KernelResult<Vec<u8>> {
    let safe_path = validate_write_path(path)?;
    let metadata = sandbox.dir().metadata(&safe_path)?;
    if !metadata.is_file() {
        return Err(KernelError::InvalidPath {
            reason: "target is not a regular file".into(),
        });
    }
    if metadata.len() > MAX_FILE_SIZE as u64 {
        return Err(KernelError::FileTooLarge {
            actual: metadata.len() as usize,
            max: MAX_FILE_SIZE,
        });
    }

    let file = sandbox.dir().open(&safe_path)?;
    let mut buf = Vec::with_capacity(metadata.len() as usize);
    // take() guards against TOCTOU file growth between stat and read.
    file.take((MAX_FILE_SIZE as u64) + 1)
        .read_to_end(&mut buf)?;
    if buf.len() > MAX_FILE_SIZE {
        return Err(KernelError::FileTooLarge {
            actual: buf.len(),
            max: MAX_FILE_SIZE,
        });
    }
    Ok(buf)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DirEntryKind {
    File,
    Dir,
    Other,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DirEntry {
    pub name: String,
    pub kind: DirEntryKind,
}

/// List entries inside a sandbox directory. Empty path or "." lists the
/// sandbox root. Results are sorted lexicographically by name.
pub fn list_dir(sandbox: &Sandbox, path: &str) -> KernelResult<Vec<DirEntry>> {
    let safe_path = if path.is_empty() || path == "." {
        PathBuf::from(".")
    } else {
        validate_write_path(path)?
    };

    let metadata = sandbox.dir().metadata(&safe_path)?;
    if !metadata.is_dir() {
        return Err(KernelError::InvalidPath {
            reason: "target is not a directory".into(),
        });
    }

    let mut entries: Vec<DirEntry> = Vec::new();
    for entry in sandbox.dir().read_dir(&safe_path)? {
        let entry = entry?;
        let name = entry.file_name().to_string_lossy().into_owned();
        let kind = match entry.file_type() {
            Ok(ft) if ft.is_file() => DirEntryKind::File,
            Ok(ft) if ft.is_dir() => DirEntryKind::Dir,
            _ => DirEntryKind::Other,
        };
        entries.push(DirEntry { name, kind });
    }
    entries.sort_by(|a, b| a.name.cmp(&b.name));
    Ok(entries)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn new_sandbox() -> (TempDir, Sandbox) {
        let tmp = TempDir::new().unwrap();
        let sandbox = Sandbox::open(tmp.path()).unwrap();
        (tmp, sandbox)
    }

    #[test]
    fn write_inside_sandbox_succeeds() {
        let (tmp, sandbox) = new_sandbox();
        write_file(&sandbox, "hello.txt", b"hola").unwrap();

        let written = std::fs::read(tmp.path().join("hello.txt")).unwrap();
        assert_eq!(written, b"hola");
    }

    #[test]
    fn write_creates_parent_directories() {
        let (tmp, sandbox) = new_sandbox();
        write_file(&sandbox, "sub/nested/hello.txt", b"hola").unwrap();

        let written = std::fs::read(tmp.path().join("sub/nested/hello.txt")).unwrap();
        assert_eq!(written, b"hola");
    }

    #[test]
    fn write_with_parent_traversal_is_rejected() {
        let (_tmp, sandbox) = new_sandbox();
        let err = write_file(&sandbox, "../escape.txt", b"hola").unwrap_err();
        assert!(matches!(err, KernelError::PathOutsideSandbox { .. }));
    }

    #[test]
    fn write_unix_absolute_is_rejected() {
        let (_tmp, sandbox) = new_sandbox();
        let err = write_file(&sandbox, "/tmp/escape.txt", b"hola").unwrap_err();
        assert!(matches!(err, KernelError::PathOutsideSandbox { .. }));
    }

    #[test]
    fn write_empty_path_is_rejected() {
        let (_tmp, sandbox) = new_sandbox();
        let err = write_file(&sandbox, "", b"hola").unwrap_err();
        assert!(matches!(err, KernelError::InvalidPath { .. }));
    }

    #[test]
    fn write_rejects_oversize_content() {
        let (_tmp, sandbox) = new_sandbox();
        let huge = vec![0u8; MAX_FILE_SIZE + 1];
        let err = write_file(&sandbox, "huge.bin", &huge).unwrap_err();
        assert!(matches!(err, KernelError::FileTooLarge { .. }));
    }

    #[test]
    fn write_accepts_exact_max_size() {
        let (tmp, sandbox) = new_sandbox();
        let exact = vec![0u8; MAX_FILE_SIZE];
        write_file(&sandbox, "limit.bin", &exact).unwrap();

        let meta = std::fs::metadata(tmp.path().join("limit.bin")).unwrap();
        assert_eq!(meta.len() as usize, MAX_FILE_SIZE);
    }

    #[cfg(windows)]
    #[test]
    fn write_windows_drive_path_is_rejected() {
        let (_tmp, sandbox) = new_sandbox();
        let err = write_file(&sandbox, r"C:\Windows\evil.txt", b"hola").unwrap_err();
        assert!(matches!(err, KernelError::PathOutsideSandbox { .. }));
    }

    #[test]
    fn read_file_roundtrip() {
        let (_tmp, sandbox) = new_sandbox();
        write_file(&sandbox, "note.txt", b"hola mundo").unwrap();
        let got = read_file(&sandbox, "note.txt").unwrap();
        assert_eq!(got, b"hola mundo");
    }

    #[test]
    fn read_file_rejects_parent_traversal() {
        let (_tmp, sandbox) = new_sandbox();
        let err = read_file(&sandbox, "../escape.txt").unwrap_err();
        assert!(matches!(err, KernelError::PathOutsideSandbox { .. }));
    }

    #[test]
    fn read_file_rejects_unix_absolute() {
        let (_tmp, sandbox) = new_sandbox();
        let err = read_file(&sandbox, "/etc/passwd").unwrap_err();
        assert!(matches!(err, KernelError::PathOutsideSandbox { .. }));
    }

    #[test]
    fn read_file_missing_path_errors() {
        let (_tmp, sandbox) = new_sandbox();
        let err = read_file(&sandbox, "nope.txt").unwrap_err();
        assert!(matches!(err, KernelError::Io(_)), "unexpected: {err:?}");
    }

    #[test]
    fn read_file_rejects_directory_target() {
        let (tmp, sandbox) = new_sandbox();
        std::fs::create_dir_all(tmp.path().join("subdir")).unwrap();
        let err = read_file(&sandbox, "subdir").unwrap_err();
        assert!(matches!(err, KernelError::InvalidPath { .. }));
    }

    #[test]
    fn read_file_rejects_oversize() {
        let (tmp, sandbox) = new_sandbox();
        // Write directly via fs (bypassing write_file's own cap) to
        // simulate a pre-existing oversized file inside the sandbox.
        let huge = vec![0u8; MAX_FILE_SIZE + 1];
        std::fs::write(tmp.path().join("huge.bin"), &huge).unwrap();
        let err = read_file(&sandbox, "huge.bin").unwrap_err();
        assert!(matches!(err, KernelError::FileTooLarge { .. }));
    }

    #[test]
    fn read_file_accepts_exact_max_size() {
        let (tmp, sandbox) = new_sandbox();
        let exact = vec![7u8; MAX_FILE_SIZE];
        std::fs::write(tmp.path().join("exact.bin"), &exact).unwrap();
        let got = read_file(&sandbox, "exact.bin").unwrap();
        assert_eq!(got.len(), MAX_FILE_SIZE);
        assert!(got.iter().all(|&b| b == 7));
    }

    #[test]
    fn list_dir_root_with_dot() {
        let (_tmp, sandbox) = new_sandbox();
        write_file(&sandbox, "b.txt", b"b").unwrap();
        write_file(&sandbox, "a.txt", b"a").unwrap();
        write_file(&sandbox, "sub/c.txt", b"c").unwrap();

        let entries = list_dir(&sandbox, ".").unwrap();
        let names: Vec<&str> = entries.iter().map(|e| e.name.as_str()).collect();
        assert_eq!(names, vec!["a.txt", "b.txt", "sub"]);

        assert_eq!(entries[0].kind, DirEntryKind::File);
        assert_eq!(entries[1].kind, DirEntryKind::File);
        assert_eq!(entries[2].kind, DirEntryKind::Dir);
    }

    #[test]
    fn list_dir_empty_path_lists_root() {
        let (_tmp, sandbox) = new_sandbox();
        write_file(&sandbox, "x.txt", b"x").unwrap();
        let entries = list_dir(&sandbox, "").unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].name, "x.txt");
    }

    #[test]
    fn list_dir_nested() {
        let (_tmp, sandbox) = new_sandbox();
        write_file(&sandbox, "sub/a.txt", b"a").unwrap();
        write_file(&sandbox, "sub/b.txt", b"b").unwrap();

        let entries = list_dir(&sandbox, "sub").unwrap();
        let names: Vec<&str> = entries.iter().map(|e| e.name.as_str()).collect();
        assert_eq!(names, vec!["a.txt", "b.txt"]);
    }

    #[test]
    fn list_dir_empty_dir() {
        let (tmp, sandbox) = new_sandbox();
        std::fs::create_dir_all(tmp.path().join("empty")).unwrap();
        let entries = list_dir(&sandbox, "empty").unwrap();
        assert!(entries.is_empty());
    }

    #[test]
    fn list_dir_rejects_parent_traversal() {
        let (_tmp, sandbox) = new_sandbox();
        let err = list_dir(&sandbox, "../etc").unwrap_err();
        assert!(matches!(err, KernelError::PathOutsideSandbox { .. }));
    }

    #[test]
    fn list_dir_rejects_file_target() {
        let (_tmp, sandbox) = new_sandbox();
        write_file(&sandbox, "regular.txt", b"hi").unwrap();
        let err = list_dir(&sandbox, "regular.txt").unwrap_err();
        assert!(matches!(err, KernelError::InvalidPath { .. }));
    }

    #[test]
    fn list_dir_missing_path_errors() {
        let (_tmp, sandbox) = new_sandbox();
        let err = list_dir(&sandbox, "nope").unwrap_err();
        assert!(matches!(err, KernelError::Io(_)), "unexpected: {err:?}");
    }
}
