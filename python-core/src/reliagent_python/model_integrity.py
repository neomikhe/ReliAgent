"""Verificación de integridad del modelo canónico.

ReliAgent no descarga el modelo: lo hace Ollama (`ollama pull <tag>`). Antes
de cada inferencia se comprueba:

1. El Modelfile que devuelve `/api/show` tiene un único `FROM`, sin
   `ADAPTER`, y ese `FROM` apunta a `<...>/blobs/sha256-<hex>` con el `<hex>`
   fijado aquí.
2. La ruta es local y absoluta (nunca UNC ni de dispositivo) antes de tocar
   el sistema de archivos: quien responde en 127.0.0.1:11434 no es de
   confianza.
3. El SHA-256 de ese archivo en disco coincide con el fijado.

Límites: esto verifica el archivo que el servidor *dice* usar, no autentica
al proceso que escucha en el puerto; las capas de plantilla, system y
parámetros no están fijadas. Ver KNOWN_ISSUES.md y docs/THREAT_MODEL.md.

`MODEL_SHA256.txt` en la raíz del repo es la copia pública de este pin; una
prueba impide que diverjan.
"""

from __future__ import annotations

import hashlib
import os
import re
import stat
from dataclasses import dataclass
from pathlib import Path, PureWindowsPath
from typing import Any


@dataclass(frozen=True)
class ModelPin:
    tag: str
    sha256: str
    size: int


# Capa `application/vnd.ollama.image.model` del manifiesto oficial de
# registry.ollama.ai/library/qwen2.5:7b-instruct-q4_K_M.
CANONICAL_MODEL = ModelPin(
    tag="qwen2.5:7b-instruct-q4_K_M",
    sha256="2bada8a7450677000f678be90653b85d364de7db25eb5ea54136ada5f3933730",
    size=4683073952,
)

_FROM_LINE = re.compile(r"^FROM[ \t]+(?P<arg>.*?)[ \t]*$", re.MULTILINE)
_ADAPTER_LINE = re.compile(r"^ADAPTER\b", re.MULTILINE)
_BLOB_SUFFIX = re.compile(r"sha256-(?P<hex>[0-9a-f]{64})$")
# Controles C0/C1, DEL y caracteres de formato/bidi que alteran la terminal.
_UNSAFE_CHARS = re.compile(r"[\x00-\x1f\x7f-\x9f\u200b-\u200f\u202a-\u202e\u2066-\u2069]")
_HASH_CHUNK = 8 * 1024 * 1024


class ModelIntegrityError(Exception):
    """El modelo que usaría Ollama no es el fijado o no se pudo comprobar."""


def blob_path_from_modelfile(modelfile: Any) -> tuple[str, str]:
    """Devuelve la ruta (tal cual la envió el servidor) y el digest del único
    blob de pesos del Modelfile."""
    if not isinstance(modelfile, str):
        raise ModelIntegrityError("Ollama did not return a Modelfile")
    if _ADAPTER_LINE.search(modelfile):
        raise ModelIntegrityError("Modelfile has ADAPTER layers; only the pinned weights are allowed")
    froms = _FROM_LINE.findall(modelfile)
    if len(froms) != 1:
        raise ModelIntegrityError(f"Modelfile must have exactly one FROM line, found {len(froms)}")
    match = _BLOB_SUFFIX.search(froms[0])
    if match is None:
        raise ModelIntegrityError("Modelfile FROM line does not point to a weights blob")
    return froms[0], match.group("hex")


def verify_model(show_response: dict[str, Any], pin: ModelPin) -> Path:
    """Comprueba que Ollama usa el blob fijado y que sus bytes no cambiaron.

    Devuelve la ruta del blob verificado.
    """
    raw_path, digest = blob_path_from_modelfile(show_response.get("modelfile"))
    if digest != pin.sha256:
        raise ModelIntegrityError(
            f"Ollama serves {pin.tag} from blob digest {digest}, expected {pin.sha256}"
        )
    path = _local_blob_path(raw_path)
    _verify_blob_file(path, pin)
    return path


def _local_blob_path(raw: str) -> Path:
    """Valida la ruta enviada por el servidor sin tocar el sistema de archivos."""
    if _UNSAFE_CHARS.search(raw):
        # No se repite la ruta: podría contener secuencias de escape.
        raise ModelIntegrityError("model blob path contains control characters")
    if not _is_local_absolute(raw):
        raise ModelIntegrityError(f"model blob path is not a local absolute path: {raw}")
    path = Path(raw)
    if path.parent.name != "blobs":
        raise ModelIntegrityError(f"model blob is not inside a 'blobs' directory: {raw}")
    return path


def _is_local_absolute(raw: str) -> bool:
    if os.name == "nt":
        # Solo "X:\..."; rechaza UNC (\\host\share), \\?\ y \\.\ (dispositivos).
        win = PureWindowsPath(raw)
        return re.fullmatch(r"[A-Za-z]:", win.drive) is not None and win.is_absolute()
    return raw.startswith("/") and not raw.startswith("//")


def _verify_blob_file(path: Path, pin: ModelPin) -> None:
    try:
        # stat antes de abrir: abrir un FIFO o un dispositivo podría bloquear.
        if not stat.S_ISREG(os.stat(path).st_mode):
            raise ModelIntegrityError(f"model blob is not a regular file: {path}")
        # O_NONBLOCK: si lo cambian por un FIFO entre stat y open, open no se
        # queda esperando a un escritor; fstat lo rechaza a continuación.
        flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NONBLOCK", 0)
        fd = os.open(path, flags)
        with os.fdopen(fd, "rb", buffering=0) as f:
            info = os.fstat(f.fileno())
            if not stat.S_ISREG(info.st_mode):
                raise ModelIntegrityError(f"model blob is not a regular file: {path}")
            if info.st_size != pin.size:
                raise ModelIntegrityError(
                    f"model blob size {info.st_size} != expected {pin.size}"
                )
            actual = _sha256_of_first_bytes(f, pin.size)
    except (OSError, ValueError) as e:
        reason = e.strerror if isinstance(e, OSError) and e.strerror else type(e).__name__
        raise ModelIntegrityError(f"cannot read model blob {path}: {reason}") from e
    if actual != pin.sha256:
        raise ModelIntegrityError(
            f"model blob SHA-256 {actual} != expected {pin.sha256} (modified on disk?)"
        )


def _sha256_of_first_bytes(f: Any, size: int) -> str:
    """Hashea exactamente `size` bytes, aunque el archivo crezca mientras tanto."""
    digest = hashlib.sha256()
    remaining = size
    while remaining:
        chunk = f.read(min(_HASH_CHUNK, remaining))
        if not chunk:
            raise ModelIntegrityError("model blob shrank while hashing")
        digest.update(chunk)
        remaining -= len(chunk)
    return digest.hexdigest()
