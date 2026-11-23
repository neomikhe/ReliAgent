use std::path::{Component, Path, PathBuf};

use super::{KernelError, KernelResult};

pub const MAX_FILE_SIZE: usize = 10 * 1024 * 1024;

/// Caracteres que hacen que un texto se lea distinto de lo que es:
/// controles C0 y C1 y DEL (`char::is_control`), los Default_Ignorable de
/// Unicode (invisibles: anchura cero y unión U+200B–U+200F, marcas y
/// controles bidi, U+2060–U+206F, guion suave, fillers de Hangul, selectores
/// de variación, etiquetas U+E0000–U+E0FFF que el modelo lee y el humano no
/// ve), separadores U+2028/U+2029, anotaciones U+FFF9–U+FFFB, BOM y el
/// braille en blanco. Prohibidos en rutas del sandbox; la CLI los escapa al
/// mostrar texto. Coste aceptado: nombres que necesitan ZWJ/ZWNJ o un
/// selector de variación (algunos emoji, persa, escrituras índicas) se
/// rechazan.
pub fn is_unsafe_char(c: char) -> bool {
    c.is_control()
        || matches!(
            c,
            '\u{00AD}'
                | '\u{034F}'
                | '\u{061C}'
                | '\u{115F}'
                | '\u{1160}'
                | '\u{17B4}'
                | '\u{17B5}'
                | '\u{180B}'..='\u{180F}'
                | '\u{200B}'..='\u{200F}'
                | '\u{2028}'..='\u{202E}'
                | '\u{2060}'..='\u{206F}'
                | '\u{2800}'
                | '\u{3164}'
                | '\u{FE00}'..='\u{FE0F}'
                | '\u{FEFF}'
                | '\u{FFA0}'
                | '\u{FFF0}'..='\u{FFFB}'
                | '\u{1BCA0}'..='\u{1BCA3}'
                | '\u{1D173}'..='\u{1D17A}'
                | '\u{E0000}'..='\u{E0FFF}'
        )
}

/// Valida una ruta relativa al sandbox para cualquier herramienta
/// (`write_file`, `read_file`, `list_dir`) y la devuelve normalizada.
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
    // Antes que cualquier otra regla: un nombre así engañaría al humano que
    // aprueba y a cualquier herramienta que liste el sandbox después.
    if let Some(c) = raw.chars().find(|&c| is_unsafe_char(c)) {
        return Err(KernelError::InvalidPath {
            reason: format!(
                "path contains a control or invisible character (U+{:04X})",
                c as u32
            ),
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
        if let Some(name) = raw.rsplit(['/', '\\']).next()
            && name.contains(':')
        {
            return Err(KernelError::InvalidPath {
                reason: "NTFS alternate data streams are not allowed".into(),
            });
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

    #[test]
    fn rejects_control_and_invisible_chars_naming_the_code_point() {
        let err = validate_write_path("a\u{202e}b.txt").unwrap_err();
        assert!(format!("{err}").contains("U+202E"), "{err}");
        let err = validate_write_path("a\nb.txt").unwrap_err();
        assert!(format!("{err}").contains("U+000A"), "{err}");
    }

    #[test]
    fn unsafe_char_set_matches_the_documented_ranges() {
        for c in [
            '\0', '\t', '\n', '\r', '\u{1b}', '\u{7f}', '\u{80}', '\u{9f}', '\u{61c}', '\u{200b}',
            '\u{200f}', '\u{202a}', '\u{202e}', '\u{2028}', '\u{2029}', '\u{2066}', '\u{2069}',
            '\u{feff}',
        ] {
            assert!(is_unsafe_char(c), "U+{:04X}", c as u32);
        }
        for c in ['a', ' ', 'é', '\u{a0}', '\u{2010}', '日', '🦤'] {
            assert!(!is_unsafe_char(c), "U+{:04X}", c as u32);
        }
    }

    #[test]
    fn default_ignorable_characters_are_unsafe() {
        // Invisibles que el humano no ve en el prompt pero el modelo sí lee
        // (p. ej. etiquetas U+E0000: "ASCII smuggling").
        for c in [
            '\u{ad}',
            '\u{34f}',
            '\u{115f}',
            '\u{1160}',
            '\u{17b4}',
            '\u{17b5}',
            '\u{180b}',
            '\u{180e}',
            '\u{180f}',
            '\u{2060}',
            '\u{2064}',
            '\u{2065}',
            '\u{206a}',
            '\u{206f}',
            '\u{2800}',
            '\u{3164}',
            '\u{fe00}',
            '\u{fe0f}',
            '\u{ffa0}',
            '\u{fff0}',
            '\u{fff9}',
            '\u{fffb}',
            '\u{1bca0}',
            '\u{1bca3}',
            '\u{1d173}',
            '\u{1d17a}',
            '\u{e0000}',
            '\u{e0041}',
            '\u{e007f}',
            '\u{e0100}',
            '\u{e01ef}',
            '\u{e0fff}',
        ] {
            assert!(is_unsafe_char(c), "U+{:04X}", c as u32);
        }
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

#[cfg(test)]
mod proptests {
    use super::*;
    use proptest::prelude::*;

    // Segmentos "seguros": nunca contienen separadores, NUL, ni empiezan por ".".
    // Esto evita colisiones triviales con "." / "..".
    fn safe_segment() -> impl Strategy<Value = String> {
        "[a-zA-Z0-9_][a-zA-Z0-9_\\-]{0,15}".prop_map(|s| s)
    }

    fn safe_relative_path() -> impl Strategy<Value = String> {
        prop::collection::vec(safe_segment(), 1..6).prop_map(|parts| parts.join("/"))
    }

    proptest! {
        #![proptest_config(ProptestConfig { cases: 256, .. ProptestConfig::default() })]

        /// Propiedad: todo path "seguro" (segmentos alfanuméricos, sin separadores
        /// especiales) es aceptado y se normaliza a algo no vacío.
        #[test]
        fn safe_paths_are_accepted(raw in safe_relative_path()) {
            let normalized = validate_write_path(&raw).expect("safe path must validate");
            prop_assert!(!normalized.as_os_str().is_empty());
            // La normalización solo debe contener componentes Normal.
            for c in normalized.components() {
                prop_assert!(matches!(c, Component::Normal(_)));
            }
        }

        /// Propiedad: un path con un NUL en cualquier posición SIEMPRE se rechaza
        /// con InvalidPath (nunca se acepta, nunca es PathOutsideSandbox).
        #[test]
        fn null_bytes_always_rejected(
            prefix in "[a-zA-Z0-9_/]{0,20}",
            suffix in "[a-zA-Z0-9_/]{0,20}"
        ) {
            let raw = format!("{prefix}\0{suffix}");
            let res = validate_write_path(&raw);
            let is_invalid = matches!(res, Err(KernelError::InvalidPath { .. }));
            prop_assert!(is_invalid, "expected InvalidPath for raw containing NUL");
        }

        /// Propiedad: un carácter de control o invisible en cualquier posición
        /// se rechaza siempre con InvalidPath, antes que cualquier otra regla.
        #[test]
        fn unsafe_chars_always_rejected(
            prefix in "[a-zA-Z0-9_/.]{0,20}",
            bad in prop::sample::select(vec![
                '\u{1}', '\n', '\r', '\u{1b}', '\u{7f}', '\u{85}', '\u{9b}', '\u{61c}',
                '\u{200b}', '\u{200e}', '\u{202e}', '\u{2028}', '\u{2067}', '\u{feff}',
            ]),
            suffix in "[a-zA-Z0-9_/.]{0,20}"
        ) {
            let raw = format!("{prefix}{bad}{suffix}");
            let res = validate_write_path(&raw);
            let is_invalid = matches!(res, Err(KernelError::InvalidPath { .. }));
            prop_assert!(is_invalid, "expected InvalidPath for {:?}", raw);
        }

        /// Propiedad: cualquier path que empiece por "/" se rechaza como absoluto
        /// (PathOutsideSandbox). Excluye NULs para aislar la propiedad.
        #[test]
        fn unix_absolute_paths_always_rejected(tail in "[a-zA-Z0-9_/]{1,30}") {
            let raw = format!("/{tail}");
            let res = validate_write_path(&raw);
            let is_outside = matches!(res, Err(KernelError::PathOutsideSandbox { .. }));
            prop_assert!(is_outside, "expected PathOutsideSandbox for absolute path");
        }

        /// Propiedad: cualquier path que contenga ".." como componente, en
        /// cualquier posición, se rechaza como PathOutsideSandbox. Verifica que
        /// el traversal no se cuela mezclado con segmentos válidos.
        #[test]
        fn parent_traversal_always_rejected(
            before in prop::collection::vec(safe_segment(), 0..3),
            after in prop::collection::vec(safe_segment(), 0..3)
        ) {
            let mut parts: Vec<String> = before.clone();
            parts.push("..".to_string());
            parts.extend(after);
            let raw = parts.join("/");
            let res = validate_write_path(&raw);
            let is_outside = matches!(res, Err(KernelError::PathOutsideSandbox { .. }));
            prop_assert!(is_outside, "expected PathOutsideSandbox for traversal");
        }

        /// Propiedad (Windows): cualquier path que empiece por una letra de unidad
        /// seguida de ':' es rechazado (rutas con drive son absolutas respecto al
        /// volumen, o ADS de NTFS si el cuerpo contiene ':').
        #[cfg(windows)]
        #[test]
        fn windows_drive_letter_paths_always_rejected(
            drive in "[A-Za-z]",
            tail in "[a-zA-Z0-9_\\\\/]{0,20}"
        ) {
            let raw = format!("{drive}:{tail}");
            let res = validate_write_path(&raw);
            let is_rejected = matches!(
                res,
                Err(KernelError::PathOutsideSandbox { .. })
                    | Err(KernelError::InvalidPath { .. })
            );
            prop_assert!(is_rejected, "expected rejection for drive-prefixed path");
        }

        /// Propiedad de idempotencia-de-normalización: validar un path aceptado
        /// y luego reconstruirlo con '/' produce un path que sigue siendo aceptado
        /// y normaliza al mismo resultado.
        #[test]
        fn normalization_is_idempotent(raw in safe_relative_path()) {
            let first = validate_write_path(&raw).expect("safe path");
            let roundtrip = first
                .components()
                .filter_map(|c| match c {
                    Component::Normal(p) => p.to_str().map(|s| s.to_string()),
                    _ => None,
                })
                .collect::<Vec<_>>()
                .join("/");
            let second = validate_write_path(&roundtrip).expect("roundtrip must validate");
            prop_assert_eq!(first, second);
        }
    }
}
