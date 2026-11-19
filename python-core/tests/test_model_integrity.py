"""Pruebas de la verificación de integridad del modelo."""

from __future__ import annotations

import hashlib
import re
from pathlib import Path

import pytest

from reliagent_python.model_integrity import (
    CANONICAL_MODEL,
    ModelIntegrityError,
    ModelPin,
    blob_path_from_modelfile,
    verify_model,
)

REPO_ROOT = Path(__file__).resolve().parents[2]
HEX_A = "a" * 64
HEX_B = "b" * 64


def _pin_for(content: bytes, tag: str = "test:1b") -> ModelPin:
    return ModelPin(tag=tag, sha256=hashlib.sha256(content).hexdigest(), size=len(content))


def _blobs_dir(tmp_path: Path) -> Path:
    # Ollama guarda los pesos en <models>/blobs/sha256-<hex>.
    d = tmp_path / "blobs"
    d.mkdir(exist_ok=True)
    return d


def _blob(tmp_path: Path, content: bytes) -> Path:
    digest = hashlib.sha256(content).hexdigest()
    path = _blobs_dir(tmp_path) / f"sha256-{digest}"
    path.write_bytes(content)
    return path


def _show(blob: Path | str, extra: str = "") -> dict:
    return {"modelfile": f'# generated\n\nFROM {blob}\n{extra}TEMPLATE """x"""\n'}


class TestBlobPathFromModelfile:
    def test_parses_windows_path(self):
        mf = f"# c\nFROM C:\\Users\\u\\.ollama\\models\\blobs\\sha256-{HEX_A}\nTEMPLATE x\n"
        path, digest = blob_path_from_modelfile(mf)
        assert digest == HEX_A
        assert str(path).endswith(f"sha256-{HEX_A}")

    def test_parses_posix_path(self):
        mf = f"FROM /usr/share/ollama/.ollama/models/blobs/sha256-{HEX_B}\n"
        path, digest = blob_path_from_modelfile(mf)
        assert digest == HEX_B
        assert str(path).replace("\\", "/") == f"/usr/share/ollama/.ollama/models/blobs/sha256-{HEX_B}"

    def test_ignores_commented_from_line(self):
        mf = f"# FROM qwen2.5:7b\nFROM /b/sha256-{HEX_A}\n"
        assert blob_path_from_modelfile(mf)[1] == HEX_A

    @pytest.mark.parametrize(
        "modelfile",
        ["", "FROM qwen2.5:7b\n", "# FROM /b/sha256-" + HEX_A + "\n", None, 42],
    )
    def test_without_blob_reference_raises(self, modelfile):
        with pytest.raises(ModelIntegrityError):
            blob_path_from_modelfile(modelfile)


class TestVerifyModel:
    def test_accepts_blob_matching_pin(self, tmp_path):
        content = b"pesos de prueba"
        blob = _blob(tmp_path, content)
        assert verify_model(_show(blob), _pin_for(content)) == blob

    def test_rejects_when_ollama_uses_another_blob(self, tmp_path):
        blob = _blob(tmp_path, b"otro modelo")
        with pytest.raises(ModelIntegrityError, match="digest"):
            verify_model(_show(blob), _pin_for(b"modelo fijado"))

    def test_rejects_tampered_blob_contents(self, tmp_path):
        # El nombre del blob coincide con el pin, pero los bytes en disco no.
        content = b"modelo fijado"
        pin = _pin_for(content)
        blob = _blobs_dir(tmp_path) / f"sha256-{pin.sha256}"
        blob.write_bytes(b"modelo cambio")  # mismo tamaño, otro contenido
        assert blob.stat().st_size == pin.size
        with pytest.raises(ModelIntegrityError, match="SHA-256"):
            verify_model(_show(blob), pin)

    def test_rejects_size_mismatch(self, tmp_path):
        content = b"modelo fijado"
        pin = _pin_for(content)
        blob = _blobs_dir(tmp_path) / f"sha256-{pin.sha256}"
        blob.write_bytes(content + b"extra")
        with pytest.raises(ModelIntegrityError, match="size"):
            verify_model(_show(blob), pin)

    def test_rejects_missing_blob(self, tmp_path):
        pin = _pin_for(b"x")
        blob = _blobs_dir(tmp_path) / f"sha256-{pin.sha256}"
        with pytest.raises(ModelIntegrityError):
            verify_model(_show(blob), pin)

    def test_rejects_non_regular_file(self, tmp_path):
        pin = _pin_for(b"x")
        blob = _blobs_dir(tmp_path) / f"sha256-{pin.sha256}"
        blob.mkdir()
        with pytest.raises(ModelIntegrityError, match="regular file"):
            verify_model(_show(blob), pin)

    def test_rejects_show_without_modelfile(self):
        with pytest.raises(ModelIntegrityError):
            verify_model({}, _pin_for(b"x"))


PIN = _pin_for(b"modelo fijado")
BLOB_NAME = f"sha256-{PIN.sha256}"


class TestServerSuppliedPathIsNotTrusted:
    """La ruta del blob la dicta quien responda en 127.0.0.1:11434. Antes de
    tocar el sistema de archivos debe ser una ruta local absoluta a
    <...>/blobs/sha256-<pin>; si no, un servidor hostil podría hacer que el
    sidecar abra rutas de red (UNC -> SMB con NTLM en Windows)."""

    @pytest.mark.parametrize(
        "raw_path",
        [
            # 203.0.113.0/24 es TEST-NET-3: si el código llegara a abrirla,
            # la prueba se colgaría o fallaría con otro mensaje.
            f"\\\\203.0.113.7\\share\\blobs\\{BLOB_NAME}",
            f"//203.0.113.7/share/blobs/{BLOB_NAME}",
            f"\\\\?\\UNC\\203.0.113.7\\share\\blobs\\{BLOB_NAME}",
            f"\\\\.\\pipe\\blobs\\{BLOB_NAME}",
            f"blobs/{BLOB_NAME}",
            f"./blobs/{BLOB_NAME}",
        ],
    )
    def test_rejects_non_local_or_relative_paths(self, raw_path):
        with pytest.raises(ModelIntegrityError, match="local absolute path"):
            verify_model(_show(raw_path), PIN)

    def test_rejects_blob_outside_a_blobs_directory(self, tmp_path):
        other = tmp_path / "elsewhere"
        other.mkdir()
        path = other / BLOB_NAME
        path.write_bytes(b"modelo fijado")
        with pytest.raises(ModelIntegrityError, match="blobs"):
            verify_model(_show(path), PIN)

    def test_rejects_control_characters_in_path(self, tmp_path):
        evil = f"{_blobs_dir(tmp_path)}\x1b]52;c;aGk=\x07/{BLOB_NAME}"
        with pytest.raises(ModelIntegrityError, match="control character"):
            verify_model(_show(evil), PIN)

    def test_error_messages_never_echo_raw_control_characters(self, tmp_path):
        evil = f"{_blobs_dir(tmp_path)}\x1b[2J/{BLOB_NAME}"
        with pytest.raises(ModelIntegrityError) as exc:
            verify_model(_show(evil), PIN)
        assert "\x1b" not in str(exc.value)


class TestModelfileShape:
    def test_rejects_adapter_layers(self, tmp_path):
        content = b"modelo fijado"
        blob = _blob(tmp_path, content)
        show = _show(blob, extra=f"ADAPTER {blob.parent / ('sha256-' + 'c' * 64)}\n")
        with pytest.raises(ModelIntegrityError, match="ADAPTER"):
            verify_model(show, _pin_for(content))

    def test_rejects_more_than_one_from(self, tmp_path):
        content = b"modelo fijado"
        blob = _blob(tmp_path, content)
        show = _show(blob, extra=f"FROM {blob.parent / ('sha256-' + 'c' * 64)}\n")
        with pytest.raises(ModelIntegrityError, match="FROM"):
            verify_model(show, _pin_for(content))


class TestCanonicalPin:
    def test_canonical_pin_is_well_formed(self):
        assert re.fullmatch(r"[0-9a-f]{64}", CANONICAL_MODEL.sha256)
        assert CANONICAL_MODEL.size > 0
        assert CANONICAL_MODEL.tag

    def test_model_sha256_txt_matches_canonical_pin(self):
        # MODEL_SHA256.txt es la copia pública del pin; no puede divergir.
        lines = (REPO_ROOT / "MODEL_SHA256.txt").read_text(encoding="utf-8").splitlines()
        pins = [ln.split() for ln in lines if re.match(r"^[0-9a-f]{64}\s", ln)]
        assert len(pins) == 1, pins
        sha, tag, size = pins[0][:3]
        assert (sha, tag, int(size)) == (
            CANONICAL_MODEL.sha256,
            CANONICAL_MODEL.tag,
            CANONICAL_MODEL.size,
        )
