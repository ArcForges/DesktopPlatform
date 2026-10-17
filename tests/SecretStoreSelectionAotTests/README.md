# SPDX-License-Identifier: AGPL-3.0-only

# Secrets Native AOT probe

This executable is the Native AOT proof of the `ArcForges.Security.Secrets` platform selection (AF-DP-02). It references the library
project, so publishing it with Native AOT (`eng/build/desktop-aot.props`: `PublishAot`, full trimming, `IL2026`/`IL3050` and every other
warning as an error) compiles and trims `OsSecretStore.SelectForCurrentPlatform` with every backend: the Windows Credential Manager
adapter, the Linux Secret Service client over `Tmds.DBus.Protocol` (including the `dh-ietf1024-sha256-aes128-cbc-pkcs7` transport) and
the owner-only file fallback with its `statx`/`fsync` bindings. It is not a product host and claims nothing about the node.

CI publishes it on `win-x64` and `linux-x64` (compile only) and never runs it. Local runs:

- **Linux, no argument.** Selects the store with a bus address that does not exist, checks the reported `OwnerOnlyFile` /
  `FileOwnerOnly` choice, and writes, reads, replaces and deletes secrets in a new temporary data root (0700 directory, 0600 files).
- **Linux, `--private-keyring`.** Additionally starts a private `dbus-daemon` and an unlocked private `gnome-keyring-daemon` (random
  test-only password) in a new temporary directory, with an environment that names only that directory, checks the reported
  `SecretService` / `OsSecretStore` choice and round-trips a value through the default collection, then stops both and deletes the
  directory. It never reaches the user's session bus or keyring. Without the two daemons it prints `SKIP:` with the reason (H-11).
- **Windows.** Like every test project, the probe's runtime configuration sets the OS secret-store test tripwire
  (`ArcForges.Security.Secrets.DenyOsStores`), so the selection is refused with `OsSecretStoreDeniedException` before any OS call: the
  probe never reads or writes the user's Credential Manager, and the run shows that the switch and the refusal survive Native AOT. The
  `WindowsCredentialManager` / `OsSecretStore` selection itself is asserted by the OS secret-store tier (`tests/OsSecretStoreTests`).
- **Linux.** Both modes name only buses the probe owns (a path that does not exist, or a private daemon in its own temporary
  directory), which are outside the tripwire's scope.

Windows (Native AOT needs the Visual Studio C++ developer environment for the linker):

```bat
call "C:\Program Files\Microsoft Visual Studio\18\Community\Common7\Tools\VsDevCmd.bat" -arch=amd64 -host_arch=amd64
dotnet publish tests/SecretStoreSelectionAotTests/SecretStoreSelectionAotTests.csproj -c Release -r win-x64 -p:IlcUseEnvironmentalTools=true -o artifacts/af-dp-02/win-x64
artifacts\af-dp-02\win-x64\SecretStoreSelectionAotTests.exe
```

Linux (WSL2 Debian):

```sh
dotnet publish tests/SecretStoreSelectionAotTests/SecretStoreSelectionAotTests.csproj -c Release -r linux-x64 -o artifacts/af-dp-02/linux-x64
./artifacts/af-dp-02/linux-x64/SecretStoreSelectionAotTests --private-keyring
```

Each check prints one `PASS:` (or `SKIP:`) line and the probe exits `0`, or it reports the failed check on standard error and exits
`1`. Run as the JIT-compiled assembly it refuses to run. macOS is not supported and never claimed (P2-023).
