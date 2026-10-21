# Per-application secrets (PLT.40)

Packaged as `ArcForges.Security.Secrets` (package admission: PLT.46).

This first-party building block stores opaque `SecretRef` values in the
owning app installation's credential namespace. The namespace includes realm,
account, product, device, installation, partition and secret identity. Composition
maps its trusted `AppIdentity` into the closed local `SecretApplicationDimension`
storage dimension (not a second product-identity authority); arbitrary product strings
are rejected, and the secrets package does not depend on the application-composition layer.
A reference has no readable identifier or plaintext representation; session sign-out
revokes use (`RevokeAllConnectorGrants`) without deleting the local vault.

The broker exposes store/delete and a short-lived connector-use grant, not a
secret-returning method. A grant is issued by the foreground direct-human host,
bound to the full planned actor chain and connector definition, and revalidated
against the live signed-in foreground session and recovery generation at use.
Credential-bearing work runs in the trusted app host executor; connector IPC must
never carry the secret bytes.

## What the isolation does and does not prove

Two different things are called isolation, and this package keeps them apart.

- **Broker namespace (proved offline).** Cross-product, cross-realm, cross-account,
  cross-device and cross-installation references, a delegated agent or extension acting as
  the human owner, a revoked or expired grant, a changed recovery generation and an ended
  foreground session all fail inside the owning host. Own sign-out leaves other
  applications' vaults and local data intact. This constrains only code that goes through
  the owning host's broker.
- **OS-enforced sibling denial (store property, declared not assumed).** Each
  `ISecretBackingStore` declares a `SecretStoreIsolation`. A broker is constructed with an
  explicit `SecretIsolationPolicy`: `RequireOsEnforcedPerApplication` fails closed unless the
  store declares `OsEnforcedPerApplication`; `AllowSameUserSharedStore` records that the host
  accepts the weaker assurance. `SecretBroker.IsolationAssurance` reports the declared class
  so release gates can refuse to claim more.

`WindowsCredentialManagerSecretStore` is the current-user Windows adapter and declares
`SameUserShared`. Credential Manager is addressable by name from every process of the same
Windows user, so it is **not** an OS-enforced sibling boundary: a hostile same-user
application that bypasses the broker can read an entry whose target it can compute. A test
of the OS secret-store tier records this observation with a second, ArcForges-free process.
An OS-enforced Windows adapter needs package identity (MSIX/AppContainer) and is not provided
here. No macOS keychain (code-signature access group), Linux secret-portal or Android keystore
adapter exists. `OsSecretStore.CreateForCurrentPlatform` returns Credential Manager on Windows and the
Secret Service on Linux when one is reachable; otherwise it fails closed with
`PlatformNotSupportedException` and never falls back to files, preferences or memory. Only
`OsSecretStore.SelectForCurrentPlatform` (below) selects the reported file fallback.

The real Windows round trip, a missing entry and the same-user sibling observation (`cmdkey`) are tests of the
OS secret-store integration tier (below), not of the routine suite.

## Test tripwire and the OS secret-store tier

Routine tests never reach a real OS secret store (ArcForges-Design `docs/architecture/16-testing-strategy.md`
section 1, AD-0016 amendment of 2026-10-17). `OsSecretStoreGuard` is the runtime tripwire:

- Every test project sets the AppContext switch `ArcForges.Security.Secrets.DenyOsStores=true` in its runtime
  configuration (this repository's `Directory.Build.targets`; consumers set it in their own test projects, for
  example `<RuntimeHostConfigurationOption Include="ArcForges.Security.Secrets.DenyOsStores" Value="true" />`).
- While it is set, the Windows Credential Manager adapter (construction and every operation) and the Secret Service
  adapter on the user's session bus check it before any OS call and throw `OsSecretStoreDeniedException`, unless
  `ARCFORGES_OS_SECRET_STORE_TESTS=1` (the tier's single opt-in) is set. The Secret Service scope is the user's
  session bus: no explicit `BusAddress`, or one equal to `DBUS_SESSION_BUS_ADDRESS`, `/run/user/<uid>/bus` or
  `$XDG_RUNTIME_DIR/bus`, and any address that cannot be shown to be test-owned. Only a `unix:path=` socket that does
  not exist, or that lies in a directory of its own under the temporary directory (a private daemon), is outside it.
- `OsSecretStore.SelectForCurrentPlatform` and `CreateForCurrentPlatform` propagate the refusal; it is never an
  unavailable backend, so selection never falls back to the file store on refusal.
- `OsSecretStoreGuard.ThrowIfDenied(store)` lets a consumer guard another user store (for example a CNG user key) the
  same way. Release builds never set the switch, so production behaviour is unchanged.

The tier is `tests/OsSecretStoreTests` (trait `env=os-secret-store`), which no routine suite, pre-push step or other
workflow selects. It runs minimal and sequential tests through a fixture that names each entry `ArcForges.Secrets.v1.`
plus the uppercase SHA-256 hex of `arcforges.os-secret-store-test.v1|<run id>|<n>` (fresh random run id), writes that
name to the run's name list before creating it, deletes only listed names and verifies their absence (a failed check is
evidence, never retried), and fails the run at 4 entries at once, 32 store calls, 10 s per call or 5 minutes. The
Windows Credential Manager tests run on disposable hosted Windows runners (`.github/workflows/os-secret-store-tier.yml`:
external pull requests, `merge_group`, manual dispatch and weekly); locally only through `eng/os_secret_store_tier.py`
with the explicit opt-in. The Linux Secret Service tests run only on the isolated Linux secret-store test host, reached through the Linux MCP server (ArcForges-Design AD-0019 §6).

## Linux backends and the node's credential store (AF-DP-02)

`OsSecretStore.SelectForCurrentPlatform(dataRoot, options)` selects the store for node credentials and
the node data key and returns a `SecretStoreSelection`: the store, the `Backend`, the `Protection` and,
when the OS store was not chosen, a `FallbackReason` without secret material. The node keeps this record
and shows `CredentialInOsStore` as `AccountStatus.credential_in_os_store` (R-AUTH-003, AD-0011 §4).

| Platform | Selected backend | `Protection` | `CredentialInOsStore` |
|---|---|---|---|
| Windows | `WindowsCredentialManager` (unchanged adapter) | `OsSecretStore` | true |
| Linux, Secret Service available | `SecretService` | `OsSecretStore` | true |
| Linux, no session bus or no `org.freedesktop.secrets` | `OwnerOnlyFile` | `FileOwnerOnly` (weaker) | false |

- **Secret Service.** `org.freedesktop.secrets` over the session D-Bus with `Tmds.DBus.Protocol`
  (Native AOT compatible). Items live in the default collection with the attributes
  `{application: arcforges, name: <key>}`; a write replaces the item with the same attributes. A locked
  collection is unlocked through the desktop keyring's prompt; a dismissed prompt, or one unanswered within
  `SecretServiceOptions.PromptTimeout`, fails the operation (it is never redirected to a file). Values cross
  the bus encrypted (`dh-ietf1024-sha256-aes128-cbc-pkcs7`) unless the service supports only `plain`. Each
  operation opens and closes its own connection and session; every call is bounded by `CallTimeout`.
  The backend is available when a session bus is configured (`SecretServiceOptions.BusAddress`, or
  `DBUS_SESSION_BUS_ADDRESS` / `$XDG_RUNTIME_DIR/bus`), accepts a connection, opens a session and has a
  default collection. A keyring without one (for example gnome-keyring started headless in a fresh home,
  without a login keyring) is unavailable, so selection reports the file fallback; the store never creates
  a collection, because that prompts for a new keyring password.
- **File fallback.** One secret per file under `<data root>/run/secrets/`, mode 0600 in a 0700
  directory, written unbuffered to a temporary file in that directory, flushed and renamed over the name,
  and the directory flushed. The data root and `run/` must be real directories (not symbolic links) of the
  current user that no other user can write (missing ones are created 0700);
  `run/secrets/` must be a real directory of the current user, and a wider mode is repaired to 0700. A
  secret file that is not a regular file of the current user, or that grants any group or other access, is
  refused on read (it may have been exposed or planted); storing the key again replaces it and deleting it
  removes it. The value is not encrypted: anyone acting as the user, or reading the disk outside the OS,
  can read it, which is why it is reported as weaker storage.
- **Keys and values.** Both Linux backends take keys of 1–128 characters `[A-Za-z0-9._-]` starting with a
  letter or digit (a safe single file name; the broker's canonical opaque targets qualify) and values of
  1–2560 bytes, the Credential Manager bound. Both declare `SecretStoreIsolation.SameUserShared`.

Obligations of the consumer (the node):

- **Locked keyring without a prompter.** A locked default collection is unlocked only through the
  desktop keyring's prompt. Without a desktop session the prompt is dismissed and the operation fails
  closed; the store never redirects that value to the file fallback. Whether to retry, ask the user to
  unlock, or select the file fallback deliberately (and report `credential_in_os_store = false`) is the
  node's decision.
- **Backend persistence across runs.** Selection is made at each start and can differ between runs (a
  session bus or keyring that appears or disappears). The store does not remember where a credential was
  written; the node records the backend that holds each credential and reads it from there, migrates it,
  or re-enrolls when the backend changed.

Tests run on a real Linux file system and, for the Secret Service, against a private `dbus-daemon` and an
unlocked private `gnome-keyring-daemon` that the test starts in a new temporary directory and stops
afterwards; they never reach the user's session bus or keyring. The Secret Service tests belong to the OS
secret-store tier: they run only with `ARCFORGES_OS_SECRET_STORE_TESTS=1` on the isolated Linux secret-store test host
and skip, with the reason, when `dbus-daemon`, `gnome-keyring-daemon`, `secret-tool` or `dbus-send` is not
installed there (user installs, H-11). The file fallback tests and the selection over a bus address that does
not exist run on every Linux test run. `tests/SecretStoreSelectionAotTests` is the Native AOT probe of the selection.

## Known limits

- Grant expiry uses the monotonic clock (`TimeProvider.GetTimestamp`), so a wall-clock change cannot extend
  or shorten a grant; `ConnectorSecretGrant.ExpiresAt` is informational.
- Revocation is immediate for every use that has not started. The host executor runs while its grant is locked,
  so revoking that one grant (sign-out) waits for an operation already in flight, which then completes; the
  executor contract therefore requires bounded runtime.
- Expired grants are evicted when the next grant is minted or on `RevokeAllConnectorGrants`; only the foreground
  human host can mint grants, so the table is host-bounded.
- Native AOT: `tests/SecretStoreSelectionAotTests` publishes the selection, both Linux backends and the Windows adapter with
  Native AOT (compile only in CI); its local runs are the AOT execution evidence. Its runtime configuration sets the
  tripwire switch like every test project, so a Windows run shows the refusal in Native AOT instead of the selection.
- The Secret Service is reached only on the session bus of the same user, so its transport encryption protects
  the value from bus monitors, not from the service itself; whoever owns `org.freedesktop.secrets` is trusted.
- A desktop prompt (unlocking a locked collection) needs a desktop session; without one the prompt is dismissed
  and the operation fails. Selecting the file fallback instead is the caller's decision.
- There is no cross-process or concurrent-use test of the broker.
