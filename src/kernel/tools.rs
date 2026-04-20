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

    if let Some(parent) = safe_path.parent() {
        if !parent.as_os_str().is_empty() {
            sandbox.dir().create_dir_all(parent)?;
        }
    }

    sandbox.dir().write(&safe_path, content)?;
    Ok(())
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
}
