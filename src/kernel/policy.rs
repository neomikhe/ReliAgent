use std::path::{Component, Path, PathBuf};

use super::{KernelError, KernelResult};

pub const MAX_FILE_SIZE: usize = 10 * 1024 * 1024;

pub fn validate_write_path(raw: &str) -> KernelResult<PathBuf> {
    if raw.is_empty() {
        return Err(KernelError::InvalidPath {
            reason: "path is empty".into(),
        });
    }

    if raw.contains('\0') {
        return Err(KernelError::InvalidPath {
            reason: "path contains a null byte".into(),
        });
    }

    #[cfg(windows)]
    {
        // Rechaza prefijos de ruta extendida y de dispositivo: pueden saltarse la normalización.
        if raw.starts_with(r"\\?\") || raw.starts_with(r"\\.\") {
            return Err(KernelError::InvalidPath {
                reason: "Windows extended-length or device path prefixes are not allowed".into(),
            });
        }
        // Rutas con unidad (p. ej. "C:foo" o "C:\foo") son absolutas respecto a un volumen:
        // fuera del sandbox por definición.
        let bytes = raw.as_bytes();
        if bytes.len() >= 2 && bytes[1] == b':' {
            return Err(KernelError::PathOutsideSandbox {
                path: raw.to_string(),
            });
        }
        // Bloquea alternate data streams del NTFS (p. ej. "file.txt:hidden").
        if let Some(name) = raw.rsplit(['/', '\\']).next() {
            if name.contains(':') {
                return Err(KernelError::InvalidPath {
                    reason: "NTFS alternate data streams are not allowed".into(),
                });
            }
        }
    }

    let path = Path::new(raw);
    if path.is_absolute() {
        return Err(KernelError::PathOutsideSandbox {
            path: raw.to_string(),
        });
    }

    let mut normalized = PathBuf::new();
    for component in path.components() {
        match component {
            Component::Normal(part) => normalized.push(part),
            Component::CurDir => {}
            Component::ParentDir | Component::RootDir | Component::Prefix(_) => {
                return Err(KernelError::PathOutsideSandbox {
                    path: raw.to_string(),
                });
            }
        }
    }

    if normalized.as_os_str().is_empty() {
        return Err(KernelError::InvalidPath {
            reason: "path resolves to empty after normalization".into(),
        });
    }

    Ok(normalized)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_simple_relative_path() {
        let p = validate_write_path("notes.txt").unwrap();
        assert_eq!(p, PathBuf::from("notes.txt"));
    }

    #[test]
    fn accepts_nested_relative_path() {
        let p = validate_write_path("sub/dir/file.txt").unwrap();
        assert_eq!(p, PathBuf::from("sub/dir/file.txt"));
    }

    #[test]
    fn strips_curdir_components() {
        let p = validate_write_path("./sub/./file.txt").unwrap();
        assert_eq!(p, PathBuf::from("sub/file.txt"));
    }

    #[test]
    fn rejects_parent_traversal() {
        let err = validate_write_path("../escape.txt").unwrap_err();
        assert!(matches!(err, KernelError::PathOutsideSandbox { .. }));
    }

    #[test]
    fn rejects_parent_traversal_nested() {
        let err = validate_write_path("sub/../../etc/passwd").unwrap_err();
        assert!(matches!(err, KernelError::PathOutsideSandbox { .. }));
    }

    #[test]
    fn rejects_unix_absolute_path() {
        let err = validate_write_path("/etc/passwd").unwrap_err();
        assert!(matches!(err, KernelError::PathOutsideSandbox { .. }));
    }

    #[test]
    fn rejects_empty_path() {
        let err = validate_write_path("").unwrap_err();
        assert!(matches!(err, KernelError::InvalidPath { .. }));
    }

    #[test]
    fn rejects_null_byte() {
        let err = validate_write_path("foo\0.txt").unwrap_err();
        assert!(matches!(err, KernelError::InvalidPath { .. }));
    }

    #[cfg(windows)]
    #[test]
    fn rejects_windows_drive_path() {
        let err = validate_write_path(r"C:\Windows\evil.txt").unwrap_err();
        assert!(matches!(err, KernelError::PathOutsideSandbox { .. }));
    }

    #[cfg(windows)]
    #[test]
    fn rejects_windows_drive_relative() {
        let err = validate_write_path(r"C:evil.txt").unwrap_err();
        assert!(matches!(err, KernelError::PathOutsideSandbox { .. }));
    }

    #[cfg(windows)]
    #[test]
    fn rejects_windows_extended_length_prefix() {
        let err = validate_write_path(r"\\?\C:\evil.txt").unwrap_err();
        assert!(matches!(err, KernelError::InvalidPath { .. }));
    }

    #[cfg(windows)]
    #[test]
    fn rejects_windows_device_prefix() {
        let err = validate_write_path(r"\\.\PhysicalDrive0").unwrap_err();
        assert!(matches!(err, KernelError::InvalidPath { .. }));
    }

    #[cfg(windows)]
    #[test]
    fn rejects_ntfs_alternate_data_stream() {
        let err = validate_write_path("notes.txt:hidden").unwrap_err();
        assert!(matches!(err, KernelError::InvalidPath { .. }));
    }
}
