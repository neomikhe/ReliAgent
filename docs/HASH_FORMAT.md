# Hash Format — v2 (ReliAgent v0.1.0)

> **Scope.** This document is the byte-level, reproducible specification of
> a single audit entry and its HMAC. It is the contract an external
> verifier has to implement to validate a `reli` audit log without any
> ReliAgent code.
>
> **Version.** New rows are written with `hash_format_version = 2`. Rows
> written by earlier builds carry `hash_format_version = 1` and remain
> verifiable (§6). The number is persisted on every row of
> `audit_entries`. Any change to the serialisation, the field set, the
> ordering, or the HMAC algorithm requires a new version number and a
> migration plan.

---

## 1. Where things live

| What | Where |
|---|---|
| Audit database | `~/.reliagent/audit.db` (SQLite). On Linux/macOS `reli` creates the directory `0700` |
| Backup taken before the v1→v2 migration | `~/.reliagent/audit.db.schema1.bak` |
| Rolling anchor log | `~/.reliagent/anchors/anchor.log`, rotated to `anchor.log.1`, `anchor.log.2`, … |
| HMAC key | OS keyring, `service = "reliagent"`, `account = "audit-hmac-v1"` |
| Head witness | OS keyring, `service = "reliagent"`, `account = "audit-head-v1:<16 hex>"` — one per log, derived from the SHA-256 of the canonical path of `audit.db` (§5.5) |

Audit entries live in the `audit_entries` table. The schema is created by
[`v1.sql`](../src/kernel/migrations/v1.sql) and upgraded by
[`v2.sql`](../src/kernel/migrations/v2.sql) (`schema_meta.schema_version =
"2"`). The database uses:

- `journal_mode = WAL` and `synchronous = FULL` (plus `fullfsync` on
  macOS): a committed row survives power loss, which is what makes "log
  before act" meaningful (§5.3).
- `locking_mode = EXCLUSIVE`: one process uses the log at a time. Another
  `reli` waits about 2 s and exits with code `6`; other tools are blocked
  too. Run external verifiers while `reli` is not running.
- Only `reli`'s own schema: the tables `audit_entries` (exactly the v1
  or v2 columns) and `schema_meta`, and indexes on them. `reli` refuses
  a database with anything else — triggers, views, other tables, extra
  columns, values over 1 MiB (§5.6).

---

## 2. Logical entry

| # | Field | Type | Notes |
|---|---|---|---|
| 1 | `sequence_no` | `u64` | Strictly monotonic, starts at `0`, contiguous, never reused. Primary key. |
| 2 | `timestamp` | `String` | RFC 3339 in UTC (`...Z`), set when the row is recorded. Informational: ordering is `sequence_no`. |
| 3 | `tool` | `String` | `write_file`, `read_file` or `list_dir`. UTF-8. |
| 4 | `args_hash` | `String` | Lowercase hex of `SHA-256(serde_json::to_vec(args))`. 64 characters. See §3. |
| 5 | `status` | tagged enum | `{"kind":"pending"}`, `{"kind":"ok"}`, `{"kind":"error","reason":"<text>"}` or `{"kind":"rejected","reason":"<text>"}`. |
| 6 | `resolves` | `u64`, optional | v2 resolution rows only: the `sequence_no` of the `pending` row they close. Absent otherwise. |
| 7 | `prev_hmac` | `String` | Lowercase hex of the previous entry's `hmac`. For `sequence_no = 0` this is the literal ASCII string `"GENESIS"`. |
| 8 | `hash_format_version` | `u32` | `2` for rows written now, `1` for legacy rows. |
| 9 | `hmac` | `String` | Lowercase hex of HMAC-SHA-256 over fields 1–8 (§4). 64 characters. |

In SQLite, `status` is split into `status_kind` + `status_reason`, and
`resolves` is the column `resolves_seq` (`NULL` when absent).
`status_reason` is `NULL` for `pending` and `ok` and non-`NULL` for
`error` and `rejected` — it is only signed as part of `status`, so any
other combination is treated as tampering.

### 2.1 One action, two rows (v2)

Every action that reaches the kernel — a direct `reli write/read/ls`, or a
proposal from the agent that the critic approved — produces:

1. A **`pending`** row, committed **before** the action is checked
   against the policy, shown to the human, or executed. It names the tool
   and the `args_hash`.
2. A **resolution** row with `resolves = <pending seq>`, the same `tool`
   and the same `args_hash`, and one of:

| `status` | Meaning | `reason` |
|---|---|---|
| `ok` | The action ran and succeeded. | — |
| `rejected` | The action did **not** run. | `policy: path_outside_sandbox`, `policy: invalid_path (<fixed kernel text>)`, `policy: file_too_large (<n> > <max> bytes)`; or, from the approval gate, `user_denied`, `timeout`, `non_interactive` |
| `error` | The action was attempted and failed, or its outcome is unknown. | `io: <ErrorKind>` (e.g. `io: NotFound`); `abandoned: …` (below) |

Reasons are fixed codes: they never contain the path (which the model may
choose) or text from the operating system.

Actions are strictly sequential: a new `pending` row is only written when
every earlier one has a resolution. A `pending` row with no resolution
means the process ended between the two rows (crash, power loss, Ctrl+C).
The next `reli` command that records an action first closes it with
`status = error` and a reason starting with `abandoned:`. It is `error`,
not `rejected`, because the action **may or may not have run**.

Proposals the critic rejects, malformed proposals and `--dry-run` never
reach the kernel and are not logged.

### 2.2 Legacy v1 rows

v1 rows are one row per action: `status` is only `ok` or `rejected`, and
`resolves` is always absent.

---

## 3. Canonicalisation of `args`

`args` is a fixed Rust struct per tool, serialised with `serde_json`
before hashing:

| Tool | `args` (exact bytes) |
|---|---|
| `write_file` | `{"path":"<path>","bytes":<content length>}` (the content itself is not logged) |
| `read_file` | `{"path":"<path>"}` |
| `list_dir` | `{"path":"<path>"}` (`"."` for the sandbox root) |

```rust
let bytes = serde_json::to_vec(args)?;
let args_hash = hex::encode(Sha256::digest(&bytes));
```

**Canonical form.** The bytes above are the canonical form. They do not
depend on how the proposal was spelled: the sidecar's JSON is parsed
into a typed action and these structs are generated from it, so key
order, whitespace, escapes (`\u0061` vs `a`) and unknown fields in the
proposal make no difference
(`cli::tests::different_spellings_of_a_proposal_are_audited_with_the_same_bytes`).
String escaping is the same as RFC 8785 (JCS); the only difference from
byte-exact JCS is member order (`write_file` writes `path` before
`bytes`). Switching to strict JCS would change the signed bytes and is
reserved for a future hash format version (red-team vector 15).

---

## 4. HMAC input

The HMAC input is the UTF-8 encoding of a compact JSON object with fields
1–8 in this order. `resolves` is **omitted** (not `null`) when absent, so a
v1 row's bytes are exactly what v1 code signed:

```json
{"sequence_no":0,"timestamp":"…","tool":"write_file","args_hash":"…","status":{"kind":"pending"},"prev_hmac":"GENESIS","hash_format_version":2}
{"sequence_no":1,"timestamp":"…","tool":"write_file","args_hash":"…","status":{"kind":"ok"},"resolves":0,"prev_hmac":"<hmac of row 0>","hash_format_version":2}
{"sequence_no":3,"timestamp":"…","tool":"write_file","args_hash":"…","status":{"kind":"rejected","reason":"user_denied"},"resolves":2,"prev_hmac":"…","hash_format_version":2}
```

The serialiser is `serde_json::to_vec` with default options: no
whitespace, UTF-8, keys in the order above, `status` fields in the order
`kind`, `reason`.

```
hmac = HMAC-SHA256(key = keyring[reliagent/audit-hmac-v1], message = utf8(above))
```

stored as lowercase hex. The key is exactly 32 bytes; opening the store
with a key of a different length fails immediately.

---

## 5. The chain

### 5.1 Genesis

The first entry has `sequence_no = 0` and `prev_hmac = "GENESIS"`. The
literal string is part of the HMAC input.

### 5.2 Linking

For every `n > 0`: `entry[n].prev_hmac == entry[n-1].hmac`. The chain is
strictly linear by `sequence_no`; `resolves` is a semantic link, not part
of the linking rule.

### 5.3 Log before act

Before the policy check, the approval prompt or any file-system access,
the kernel:

1. commits the `pending` row (`synchronous = FULL`), checking that SQLite
   reports exactly one written row;
2. appends its anchor line (§5.4) and updates the head witness (§5.5).

If any of that fails, the action does not run. If recording the
resolution fails after the action ran, the error names the outcome that
was lost, the `pending` row is still in the log, and the next session
closes it as `abandoned`. So every side effect has at least a `pending`
row describing it.

### 5.4 Anchor log

Each committed row is also appended to `anchors/anchor.log` as one line:

```
<sequence_no>\t<hmac>\t<timestamp>
```

After 100 lines the file is renamed to `anchor.log.N` and a new one is
started. On open, the store checks that the most recent anchor line
references a `sequence_no` present in the DB **and** that the DB's HMAC
for that row matches. A mismatch or a missing row is `AuditCorrupted`.

Writing the anchor is mandatory for `pending` rows and best-effort (a
warning) for resolutions. If there is no anchor file at all, the check is
skipped. The anchor has no key and lives on the same disk: it catches a
truncation of the DB alone, not one of the DB and the anchor together —
that is what §5.5 is for.

### 5.5 Head witness

After every committed row, `reli` stores `<sequence_no>:<hmac>` of that
row in the OS keyring (§1), out of reach of an attacker who can only
modify files. On open:

- the row at the witness's `sequence_no` must exist and have that `hmac`
  — otherwise `AuditCorrupted` (tail truncated, or `audit.db` deleted or
  replaced);
- rows **after** the witness are accepted (a crash between the SQLite
  commit and the keyring write);
- a log without a witness (created before this feature) adopts its
  current last row.

Like the anchor, the witness is mandatory for `pending` rows and
best-effort for resolutions. `reli reset --wipe-everything` deletes it.

### 5.6 Verification rules

A log verifies when its schema is exactly `reli`'s (§1; `type`, `name`
and `sql` of `sqlite_master` compared byte for byte, so a disguised
trigger such as `type = 'TRIGGER'` is refused too), and walking rows by
ascending `sequence_no`:

1. `sequence_no` equals the row's position.
2. `hash_format_version` is `1` or `2`.
3. `prev_hmac` matches the previous row's `hmac` (or `"GENESIS"`).
4. The HMAC recomputes from fields 1–8 with the keyring key.
5. `status_reason` is `NULL` exactly for `pending` and `ok` (§2).
6. **v1 rows:** `status` is `ok` or `rejected`, no `resolves`, and no v1
   row appears after a v2 row.
7. **v2 rows:** a `pending` row has no `resolves` and is only allowed
   when no other `pending` row is open; any other row has `resolves = p`
   where `p` is the open v2 `pending` row, with the same `tool` and
   `args_hash`.
8. The latest anchor line agrees with the DB (§5.4) and the log is not
   shorter than its head witness (§5.5).

An unresolved `pending` row is allowed only as the last open action
(§2.1). Rules 6–7 can only fail for rows that are correctly signed, i.e.
a bug or someone holding the key.

### 5.7 Verification outcomes

`AuditStore::verify` returns `Ok(())` or
`Err(KernelError::AuditCorrupted { sequence_no, reason })` at the first
inconsistency. In v0.1.0 `reli` then enters **read-only mode**: every
command that would act refuses (exit code `3`) and names that entry, and
`reli log` still prints every row exactly as stored — one JSON object per
line whose keys are always the ten v2 column names (`resolves_seq` is
`null` for a v1 log) — followed by the verification result on stderr.
Values that `reli` never writes are tagged instead of looking like normal
ones: `{"blob_hex": …}`, `{"text_hex": …}` for text that is not UTF-8,
`{"real": …}` for a non-finite number. Control and invisible characters
are written as JSON escapes. `reli log` opens the database
`query_only` and never migrates, repairs or extends it. Recovery is
manual (forensics on the export or on a copy of the files, then
`reli reset --wipe-everything`). Exit code `6` only means the log is in
use by another process; it never indicates tampering.

---

## 6. Compatibility and future versions

- Opening a schema-1 database first copies it to `audit.db.schema1.bak`
  (`VACUUM INTO`, never overwriting an existing backup), then migrates it
  to schema 2 (`v2.sql`): the table is rebuilt to allow the new statuses
  and the `resolves_seq` column; existing rows are copied unchanged and
  still verify as v1.
- If `schema_version` says `1` but the table already has v2 columns, the
  migration is refused (it would erase `resolves_seq`).
- A unique index on `resolves_seq` makes SQLite refuse a second
  resolution of the same `pending` row.
- A new hash format requires: a new migration, a new section here, and
  verifier dispatch on `hash_format_version` so mixed logs still verify.
- No field of the entry is outside the HMAC (except `hmac` itself);
  `status_reason` is covered as part of `status`, with the rule in §2.

---

## 7. External verifier pseudocode

```python
import hmac, hashlib, json, sqlite3

class Corrupted(Exception):
    pass

def check(condition, message):
    if not condition:  # not `assert`: it disappears under `python -O`
        raise Corrupted(message)

def verify(db_path, key: bytes) -> None:
    # Read-only, and only while reli is not running (it holds an
    # exclusive lock). Compare the head witness and anchors/ separately.
    conn = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)
    foreign = conn.execute(
        "SELECT type, name FROM sqlite_master WHERE type IN ('trigger','view')"
    ).fetchall()
    check(not foreign, f"unexpected schema objects: {foreign}")
    rows = conn.execute("""
        SELECT sequence_no, timestamp, tool, args_hash, status_kind,
               status_reason, resolves_seq, prev_hmac, hmac, hash_format_version
          FROM audit_entries ORDER BY sequence_no ASC
    """).fetchall()

    expected_prev, seen_v2, open_pending = "GENESIS", False, {}
    for i, (seq, ts, tool, args_hash, kind, reason, resolves,
            prev_hmac, stored_hmac, hfv) in enumerate(rows):
        check(seq == i, f"gap or reorder at {seq}")
        check(hfv in (1, 2), f"unsupported hash_format_version {hfv} at {seq}")
        check(prev_hmac == expected_prev, f"chain break at {seq}")
        check((reason is None) == (kind in ("pending", "ok")),
              f"status_reason does not match status at {seq}")

        status = {"kind": kind}
        if kind in ("error", "rejected"):
            status["reason"] = reason
        payload = {"sequence_no": seq, "timestamp": ts, "tool": tool,
                   "args_hash": args_hash, "status": status}
        if resolves is not None:
            payload["resolves"] = resolves
        payload["prev_hmac"] = prev_hmac
        payload["hash_format_version"] = hfv
        message = json.dumps(payload, separators=(",", ":"), ensure_ascii=False)
        recomputed = hmac.new(key, message.encode("utf-8"), hashlib.sha256).hexdigest()
        check(recomputed == stored_hmac, f"hmac mismatch at {seq}")

        if hfv == 1:
            check(not seen_v2 and kind in ("ok", "rejected") and resolves is None,
                  f"invalid v1 row at {seq}")
        elif kind == "pending":
            seen_v2 = True
            check(resolves is None and not open_pending,
                  f"pending at {seq} while another action is open")
            open_pending[seq] = (tool, args_hash)
        else:
            seen_v2 = True
            check(open_pending.pop(resolves, None) == (tool, args_hash),
                  f"row {seq} does not resolve the open pending action")
        expected_prev = stored_hmac
```

> **Note.** `serde_json` emits no whitespace and keeps non-ASCII characters
> as UTF-8, which matches `json.dumps(..., separators=(",", ":"),
> ensure_ascii=False)`. If you see a mismatch only on rows with non-ASCII
> paths or reasons, check `ensure_ascii`.

---

## 8. Change log

- **Documentation — 2026-11-23** (format unchanged, still v2). `reli log`
  and read-only mode (§5.7); canonical form of `args` stated precisely
  (§3); private audit directory on Unix (§1).
- **v2 — 2026-11-18.** Two rows per action (`pending` before acting, then
  `ok` / `error` / `rejected` with `resolves`). New statuses `pending` and
  `error`; `abandoned` closes orphaned `pending` rows; refusal reasons are
  fixed codes. `synchronous = FULL`, an exclusive lock on the database, a
  head witness in the OS keyring, and rejection of triggers, views and
  unsigned `status_reason` values. v1 rows remain valid.
- **v1 — 2026-04-21.** Initial format: one row per action, `ok` /
  `rejected`. HMAC-SHA-256, 32-byte key from the OS keyring, genesis
  marker `"GENESIS"`.
