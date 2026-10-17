# SPDX-License-Identifier: AGPL-3.0-only

# OS secret-store integration tier

The only tests in this repository that reach a real OS secret store: the Windows Credential Manager and Linux Secret Service
adapters of `ArcForges.Security.Secrets` (ArcForges-Design `docs/architecture/16-testing-strategy.md` section 1; AD-0016 amendment of
2026-10-17; L-26). Every routine test uses an isolated backend instead, and the test tripwire (`OsSecretStoreGuard`, the AppContext
switch `ArcForges.Security.Secrets.DenyOsStores` that every test project sets) refuses the real stores everywhere else.

## Rules (enforced by `OsSecretStoreTier`, the collection fixture)

- **One opt-in.** Nothing runs without `ARCFORGES_OS_SECRET_STORE_TESTS=1`; the tests are then reported as skipped with that reason.
  Only the hosted tier job (on its test step) and `eng/os_secret_store_tier.py` (with the user's explicit opt-in) run them.
- **Separate.** Every test class carries `[Trait("env", "os-secret-store")]`. No default suite, no pre-push step and no other
  workflow selects this project; `tests/ArchitectureTests` (`OsSecretStoreTierPolicyTests`) fails if one does.
- **Minimal and sequential.** One test at a time in one process (parallelization off, one collection). Each test does only what its
  contract needs: write and overwrite a uniquely named entry, read it, delete it; a missing entry; the backend unavailable (Linux).
- **Limits per run.** At most 4 test entries at once, 32 secret-store calls, 10 s per call, 5 minutes for the tier. Reaching one
  fails the run and every later call.
- **Unique names.** `ArcForges.Secrets.v1.` plus the uppercase SHA-256 hex of `arcforges.os-secret-store-test.v1|<run id>|<n>`,
  with a fresh random run id. By name alone they cannot be told apart from production keys; the run's name list tells them apart. It
  is written and flushed before each entry is created, to `artifacts/evidence/os-secret-store-tier/os-secret-store-tier-<run id>.log`
  (or `ARCFORGES_OS_SECRET_STORE_TESTS_EVIDENCE`), and is kept with the run's evidence.
- **Safe cleanup.** Only listed names are deleted, by exact name, and each is read back once: it must be absent. A remaining entry
  fails the test and is reported by name; a failed absence check is evidence (L-26) and is never retried. Nothing is enumerated or
  deleted by pattern. The read-backs and absence checks are test verification, not production behaviour (04-execution section 2).
- **Never stress or load.** No stress, load, soak or concurrency test runs here, hosted runners included.

## Where it runs

- **Windows Credential Manager:** `.github/workflows/os-secret-store-tier.yml` on a disposable `windows-latest` runner for external
  pull requests, `merge_group`, manual dispatch and weekly (Wednesday 04:41 UTC); skipped for the owner's pull requests and never on
  a push. That hosted run is the tier's evidence. On the workstation only on explicit opt-in (weaker evidence: the store is shared
  with the user's applications):

  ```powershell
  $env:ARCFORGES_OS_SECRET_STORE_TESTS = '1'; python eng/os_secret_store_tier.py; Remove-Item Env:ARCFORGES_OS_SECRET_STORE_TESTS
  ```

- **Linux Secret Service:** only in the isolated `ArcForgesTest` WSL distribution (never the development distribution `Debian` or a
  user's session keyring), on explicit opt-in. Each test starts its own `dbus-daemon` and unlocked `gnome-keyring-daemon` in a new
  temporary directory, so even there no session bus or keyring of the user is contacted. The provider and tools are user installs in
  `ArcForgesTest` (`gnome-keyring`, `dbus-daemon`, `libsecret-tools` for `secret-tool`, `dbus-send`; acceptance register H-11);
  without them the tests are skipped with the reason, never reported as passed. With the .NET SDK of `global.json` installed there:

  ```sh
  wsl -d ArcForgesTest --cd <checkout> -- env ARCFORGES_OS_SECRET_STORE_TESTS=1 python3 eng/os_secret_store_tier.py
  ```

The runner refuses to run without the opt-in (exit code 3, "NOT RUN") and, on Linux, outside `ArcForgesTest`.
