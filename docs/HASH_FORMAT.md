# Hash Format — v1 (ReliAgent v0.1.0)

> **Scope.** This document is the byte-level, reproducible specification of
> a single audit entry and its HMAC. It is the contract an external
> verifier has to implement to validate a `reli` audit log without any
> ReliAgent code.
>
> **Version.** `hash_format_version = 1`. This number is persisted on every
> row of `audit_entries`. Any change to the serialisation, the field set,
> the ordering, or the HMAC algorithm requires a new version number and a
> migration plan. See [§6 Compatibility](#6-compatibility-and-future-versions).

---

## 1. Where things live

| What | Path |
|---|---|
| Audit database | `~/.reliagent/audit.db` (SQLite) |
| Rolling anchor log | `~/.reliagent/anchors/` (one JSON-lines file per rotation) |
| HMAC key | OS keyring entry (`service = "reliagent"`, `account = "hmac-v1"`) |

Audit entries are stored in the `audit_entries` table defined in
[`src/kernel/migrations/v1.sql`](../src/kernel/migrations/v1.sql). The
database uses WAL journaling (`journal_mode = WAL`) and
`synchronous = NORMAL`.

---

## 2. Logical entry

Each entry is a tuple of nine fields:

| # | Field | Type | Notes |
|---|---|---|---|
| 1 | `sequence_no` | `u64` | Strictly monotonic, starts at `0`, contiguous, never reused. Primary key. |
| 2 | `timestamp` | `String` | RFC 3339 with offset (`YYYY-MM-DDTHH:MM:SS±HH:MM` or `...Z`). Set at `record()` time using `OffsetDateTime::now_utc()`. |
| 3 | `tool` | `String` | The logical operation name, e.g. `write_file`, `read_file`, `list_dir`. UTF-8. |
| 4 | `args_hash` | `String` | Lowercase hex of `SHA-256(serde_json::to_vec(args))`. 64 characters. |
| 5 | `status` | tagged enum | `{"kind": "ok"}` or `{"kind": "rejected", "reason": "<text>"}`. |
| 6 | `prev_hmac` | `String` | Lowercase hex of the previous entry's `hmac`. For `sequence_no = 0` this is the literal ASCII string `"GENESIS"`. |
| 7 | `hash_format_version` | `u32` | `1` for this document. Stored per row to allow future verifier dispatch. |
| 8 | `hmac` | `String` | Lowercase hex of HMAC-SHA-256 over the JSON-serialised entry above. 64 characters. |

Fields 1–7 together form the **signed payload**. Field 8 is the signature
over that payload.

---

## 3. Canonicalisation of `args`

`args` is any user-defined serialisable value (`impl Serialize`). Before
hashing:

```rust
let bytes = serde_json::to_vec(args)?;
let args_hash = hex::encode(Sha256::digest(&bytes));
```

**Caveat (v1).** `serde_json::to_vec` is not strict JCS (RFC 8785): field
order in nested structs depends on the source type's field order, and maps
are emitted in insertion order. This means two *logically equivalent* JSON
inputs with different key orders will produce **different** `args_hash`
values today.

For ReliAgent's own tool calls this is deterministic because the argument
types are fixed Rust structs, but third-party integrations should not
assume JCS semantics yet. Full JCS canonicalisation is tracked for v0.2 —
see the `v15_jcs_canonicalization` test in `tests/red_team.rs`.

---

## 4. HMAC input

The HMAC input is the UTF-8 encoding of a JSON object containing the
signed payload (fields 1–7) in **source declaration order** of the
`AuditEntry` struct in [`src/kernel/audit.rs`](../src/kernel/audit.rs):

```json
{
  "sequence_no":       <u64>,
  "timestamp":         "<rfc3339>",
  "tool":              "<tool>",
  "args_hash":         "<hex-sha256>",
  "status":            {"kind":"ok"}  |  {"kind":"rejected","reason":"..."},
  "prev_hmac":         "<hex or \"GENESIS\">",
  "hash_format_version": 1
}
```

The serialiser is `serde_json::to_vec` with default options (no extra
whitespace, UTF-8, ASCII-preserving numeric encoding).

The HMAC is then:

```
hmac = HMAC-SHA256(key = keyring[reliagent/hmac-v1], message = utf8(above))
```

and is stored as lowercase hex. The key is exactly 32 bytes; attempting to
open the store with a key of a different length fails immediately with
`Audit("HMAC key length N != expected 32")`.

---

## 5. The chain

### 5.1 Genesis

The first entry in any log has `sequence_no = 0` and
`prev_hmac = "GENESIS"`. The literal ASCII string `GENESIS` is part of the
HMAC input — an attacker cannot omit the genesis marker without breaking
the HMAC.

### 5.2 Linking

For every `n > 0`:

```
entry[n].prev_hmac == entry[n-1].hmac
```

Verification walks entries in ascending `sequence_no` and checks that each
`prev_hmac` matches the prior row's `hmac`, and that each row's `hmac`
recomputes from the signed payload using the keyring key.

### 5.3 Anchor log

Because the in-DB chain alone cannot detect **tail truncation** (removing
the newest entry leaves a consistent prefix), ReliAgent additionally
writes a lightweight witness outside the DB:

- Directory: `~/.reliagent/anchors/`
- Format: one JSON object per line, `{"sequence_no": N, "hmac": "<hex>"}`
- Rotation: after `DEFAULT_ANCHOR_ROTATE_LINES` entries, the current file
  is closed and a new one opens. Old files stay on disk.

On `open`, the store verifies that the most recent anchor entry references
a `sequence_no` present in the DB **and** that the DB's HMAC for that row
matches the anchor's HMAC. A mismatch or a missing row is
`AuditCorrupted`.

### 5.4 Verification outcomes

`AuditStore::verify` returns:

- `Ok(())` — every row's HMAC recomputes, every `prev_hmac` matches, and
  the latest anchor agrees with the DB.
- `Err(KernelError::AuditCorrupted { sequence_no, reason })` — the point
  of the first detected inconsistency.

On failure, `reli` enters **read-only** mode: the log is inspectable and
exportable, but no new entries may be recorded. Recovery is manual
(forensics, or `reli reset --wipe-everything`).

---

## 6. Compatibility and future versions

- Every row stores its `hash_format_version`. On load, any row with a
  version other than the running code's supported set is rejected.
- Bumping this version number requires:
  1. A new migration in `src/kernel/migrations/`.
  2. A new section in this file describing the v2 payload.
  3. Dispatching in the verifier so mixed logs (v1 rows followed by v2
     rows) can still be walked end-to-end.
- Fields that are **not** in the HMAC input today — and therefore can be
  changed without a version bump — are limited to: nothing. Every field
  of `AuditEntry` (except the `hmac` itself) is covered.

---

## 7. External verifier pseudocode

```python
import hmac, hashlib, json, sqlite3

def verify(db_path, key: bytes) -> None:
    conn = sqlite3.connect(db_path)
    rows = conn.execute("""
        SELECT sequence_no, timestamp, tool, args_hash,
               status_kind, status_reason, prev_hmac, hmac,
               hash_format_version
          FROM audit_entries
         ORDER BY sequence_no ASC
    """).fetchall()

    expected_prev = "GENESIS"
    for (seq, ts, tool, args_hash, status_kind, status_reason,
         prev_hmac, stored_hmac, hfv) in rows:

        assert hfv == 1, f"unsupported hash_format_version {hfv}"
        assert prev_hmac == expected_prev, f"chain break at {seq}"

        if status_kind == "ok":
            status = {"kind": "ok"}
        else:
            status = {"kind": "rejected", "reason": status_reason or ""}

        payload = json.dumps({
            "sequence_no": seq,
            "timestamp": ts,
            "tool": tool,
            "args_hash": args_hash,
            "status": status,
            "prev_hmac": prev_hmac,
            "hash_format_version": hfv,
        }, separators=(",", ":"))  # serde_json default is compact

        recomputed = hmac.new(key, payload.encode("utf-8"),
                              hashlib.sha256).hexdigest()
        assert recomputed == stored_hmac, f"hmac mismatch at {seq}"
        expected_prev = stored_hmac
```

> **Note.** `serde_json`'s default output uses no separators (`,` and `:`
> with no surrounding whitespace), which matches `json.dumps(...,
> separators=(",", ":"))`. If you ever see extra whitespace in the canonical
> payload, the byte stream changed and that is a bug in the recorder, not
> the verifier.

---

## 8. Change log

- **v1 — 2026-04-21.** Initial format. Fields as above. HMAC-SHA-256,
  32-byte key from OS keyring, genesis marker `"GENESIS"`.
