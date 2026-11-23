# Releasing ReliAgent

Checklist for maintainers. Pushing a `vX.Y.Z` tag runs
[`.github/workflows/release.yml`](../.github/workflows/release.yml), which
builds, signs and uploads the archives to a **draft** release.

The draft itself stays hidden until a maintainer publishes it, but
pushing the tag already makes public: the tag and GitHub's source
archives for it, the workflow logs, the build artifacts (downloadable by
any signed-in user for 3 days), and the cosign signatures and build
attestations, which go to the public Sigstore transparency log for good.
**Treat a pushed tag as released.**

## Before tagging

1. `main` is green in [`test.yml`](../.github/workflows/test.yml) on all
   three platforms (runs on `main` are never cancelled, so every commit
   there has a full result).
2. The version is the same in `Cargo.toml`, `python-core/pyproject.toml`,
   `python-core/src/reliagent_python/__init__.py` (`__version__`), the
   `about` text in `src/cli.rs`, the titles of `KNOWN_ISSUES.md`,
   `docs/THREAT_MODEL.md` and `docs/HASH_FORMAT.md`, and the tag you are
   about to push.
3. [`CHANGELOG.md`](../CHANGELOG.md) has a dated entry for it (replace
   "unreleased" with the date), and the supported-versions table in
   [`SECURITY.md`](../SECURITY.md) is current.
4. Pins that Dependabot does not update are where you want them:
   - `rust-toolchain.toml` (Rust toolchain);
   - `UV_VERSION` and `PYTHON_VERSION` in `test.yml` (uv: a release at
     least two weeks old whose checksum the pinned `setup-uv` knows;
     Python: the one in `scripts/pbs.lock`);
   - `scripts/pbs.lock` (bundled Python runtime; after a bump, run
     `scripts/package_release.sh` on at least one platform, see
     [`scripts/README.md`](../scripts/README.md));
   - the `uv_build` range in `python-core/pyproject.toml` (must include
     the uv versions in use, so uv builds the sidecar with its built-in
     backend);
   - the runner images in `release.yml` (`ubuntu-24.04` sets the glibc
     the Linux binary needs);
   - `AUDITED_OLLAMA_VERSIONS` in
     `python-core/src/reliagent_python/main.py`: if the release targets a
     new Ollama version, audit it first
     ([`audits/README.md`](../audits/README.md)).

## Tag and build

```bash
git switch main && git pull --ff-only
git tag vX.Y.Z
git push origin vX.Y.Z
```

The tag must match `v<major>.<minor>.<patch>` (optionally `-suffix`);
anything else is refused by the workflow.

## Check the draft, then publish

For at least one archive per platform:

```bash
cosign verify-blob --certificate <archive>.cert --signature <archive>.sig \
    --certificate-identity "https://github.com/neomikhe/ReliAgent/.github/workflows/release.yml@refs/tags/vX.Y.Z" \
    --certificate-oidc-issuer https://token.actions.githubusercontent.com <archive>
gh attestation verify <archive> --repo neomikhe/ReliAgent \
    --signer-workflow neomikhe/ReliAgent/.github/workflows/release.yml
```

Then extract it on that platform and run `./reli ping` and
`./reli --non-interactive run --mock-llm --dry-run "write 'x' to a.txt"`.
Publish the draft only when all three platforms pass.

## If something is wrong

**Never reuse a version number once its tag has been pushed**: the
withdrawn build stays signed, attested and verifiable under that name
forever (see above), so a second, different `vX.Y.Z` would let anyone
pass the old one off as genuine. Delete the draft, keep or delete the tag,
fix the problem on `main`, and release `vX.Y.(Z+1)`. Never move a tag.
