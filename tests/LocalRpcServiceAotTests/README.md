# SPDX-License-Identifier: AGPL-3.0-only

# Local RPC service-mode Native AOT probe

This executable is the Native AOT proof of the `ArcForges.LocalRpc` service-endpoint mode (AF-DP-01). It references the library project, so
publishing it with Native AOT (`eng/build/desktop-aot.props`: `PublishAot`, full trimming, `IL2026`/`IL3050` and every other warning as an
error) compiles and trims every service-mode path: the Windows bindings (`CreateNamedPipeW` with the same-user access list and
`PIPE_REJECT_REMOTE_CLIENTS`, `GetNamedPipeClientProcessId`, `OpenProcess`, `OpenProcessToken`, `GetProcessTimes`,
`QueryFullProcessImageNameW`), the Linux `SO_PEERCRED` and `/proc` reads, the stream lane and the per-method deadline profiles. It is not a
product host and claims nothing about the node.

CI publishes it on `win-x64` and `linux-x64` (compile only) and never runs it. A local run serves one service-mode endpoint of the platform
(a Named Pipe on Windows, a Unix socket in a new `0700` directory on Linux) and calls it from the same process: the connection's peer is this
process and its user, a profiled method gets its 60 s deadline above the 30 s data cap, a stream with owner heartbeats runs beside 16 data
calls, a second stream on the connection is refused `stream-lane-full`, and on Linux the directory and socket modes are `0700` and `0600`.

Windows (Native AOT needs the Visual Studio C++ developer environment for the linker):

```bat
call "C:\Program Files\Microsoft Visual Studio\18\Community\Common7\Tools\VsDevCmd.bat" -arch=amd64 -host_arch=amd64
dotnet publish tests/LocalRpcServiceAotTests/LocalRpcServiceAotTests.csproj -c Release -r win-x64 -o artifacts/af-dp-01/win-x64
artifacts\af-dp-01\win-x64\LocalRpcServiceAotTests.exe
```

Linux:

```sh
dotnet publish tests/LocalRpcServiceAotTests/LocalRpcServiceAotTests.csproj -c Release -r linux-x64 -o artifacts/af-dp-01/linux-x64
./artifacts/af-dp-01/linux-x64/LocalRpcServiceAotTests
```

A run prints one `PASS:` line and exits `0`, or reports the failed check on standard error and exits `1`. Run as the JIT-compiled
assembly it refuses to run. macOS is not supported and never claimed (P2-023).

## Second-account modes (acceptance register AR-02)

These modes let a second operating-system account attempt a service-mode endpoint. Under one account they are controls of the mechanics
only; a refusal expected by the account that owns the endpoint prints `INVALID|same-account` and exits `2`, and root prints `INVALID|root`.

| Mode | Run as | Result |
|---|---|---|
| `--ar02-serve [--expose-socket]` | the owning account | Serves one service-mode endpoint (a new pipe `af-svc-ar02-<32 hex>` on Windows; `node.sock` in a new owner-only `/tmp/afar02-*/arcforges/` on Linux) and prints `AR02-ENDPOINT\|<transport>\|<address>\|<owner SID or uid>\|<pid>`. Standard input: `COUNT` prints `AR02-PEERS\|admitted=<n>\|other-user=<n>\|unresolved=<n>\|exited=<n>\|refused=<n>`; `STOP` ends it (also end of input or 30 minutes). On Linux, `--expose-socket` opens the directories to traversal (0711) and the socket to everyone (0666) after binding, so a second uid reaches the socket and meets the `SO_PEERCRED` uid check instead of the directory permission. |
| `--ar02-connect <address> <owner> refused\|admitted-control` | the second account (`refused`) or the owner (`admitted-control`) | A raw connect without any library check; prints `AR02-IDENTITY\|<SID or uid>` and then `REFUSED\|access-denied` (Windows access list), `REFUSED\|eacces` (Linux directory permission), `REFUSED\|closed-by-peer-check` (the server dropped the connection before any byte: its peer check), `ADMITTED`, or `INCONCLUSIVE\|<error>`. Exit `0` when the outcome is the expected one, `1` when it contradicts it, `3` when inconclusive. |
