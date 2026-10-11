# SPDX-License-Identifier: AGPL-3.0-only

# Local RPC Native AOT probe

This executable is a dedicated process-to-process proof for the generated
`ArcForges.Contracts.LocalRpc.Platform` contract. It is not a product host and
does not claim the restricted launcher, inherited descriptor, or production
lease guarantees owned by later platform work.

Publish and run locally on each available OS (the run is intentionally opt-in;
CI only restores and publishes the binary and never executes it):

```powershell
C:\Users\J7Rdm\.dotnet\dotnet.exe publish tests/LocalRpcAotTests/LocalRpcAotTests.csproj -c Release -r win-x64 -o artifacts/prf-04/win-x64
artifacts/prf-04/win-x64/LocalRpcAotTests.exe
```

```sh
dotnet publish tests/LocalRpcAotTests/LocalRpcAotTests.csproj -c Release -r linux-x64 -o artifacts/prf-04/linux-x64
./artifacts/prf-04/linux-x64/LocalRpcAotTests
```

The runtime peer-PID proof supports Windows Named Pipes and Linux Unix-domain
sockets (`SO_PEERCRED`). macOS is not supported and never claimed (P2-023).
The source still contains a Darwin `SOL_LOCAL` / `LOCAL_PEERPID` selector
branch (Apple XNU `<sys/un.h>`: `SOL_LOCAL=0`, `LOCAL_PEERPID=0x002`,
[Apple XNU header](https://raw.githubusercontent.com/apple-oss-distributions/xnu/main/bsd/sys/un.h#L81-L89));
it is unexercised code, not a supported platform and not evidence.
The parent starts owner A and peer B, authenticates them in both directions,
then stops B while A's process, owner-session ID, and server remain alive. It
restarts B at the same endpoint with the same installation ID but a fresh
instance ID and parent-issued one-use launch nonce. The OS PID may be reused;
A must reject the old channel/lease, then reconnect and authenticate B's fresh
instance/launch identity without restarting or replacing A's owner session.

Each peer's accepted connection checks the OS-observed process ID against the
parent-provisioned PID, the caller manifest's process/installation/instance
tuple, and a one-use launch nonce supplied only over redirected private stdin.
The same-user spoof child is given the actual test bootstrap secret and expected
tuple but runs under a different OS PID; it must be refused before confirmation.
The executable also checks bidirectional challenge/confirm, eight overlapping
same-epoch renewals (one linearized success, stale fences refused), an
expiry-boundary race held behind a server barrier (all post-expiry renewals
refused), cancellation, sanitized malformed-protobuf refusal followed on the
same authorized HTTP/2 channel by a generated challenge/confirm that succeeds,
and the 4 MiB receive bound. The malformed request must not reach service
dispatch; the successful generated challenge must reach it exactly once. A
reattached peer may reuse its OS PID, but must preserve its installation while
rotating its instance ID and one-use launch nonce. The lease epoch/fence headers
are private test-fixture state;
they do not change the generated Contracts wire DTOs or claim production lease
semantics.

The runtime checks use the published Native AOT executable itself as the
parent, client, server, and worker. The test does not substitute an in-memory
transport or TCP. CI's Windows/Linux matrix proves locked restore and AOT
compilation only; local runtime evidence must identify the actual OS and RID.
The `--verify-unix-peer-pid-backends` mode checks the pure backend selector
(the Linux `SO_PEERCRED` route, the retained Darwin selector branch and the
unsupported-platform fail-closed case) without opening sockets. It is not a
runtime proof for any platform. macOS is not supported and never claimed
(P2-023): no macOS run is required, recorded or claimed.

## Second-Linux-uid modes

These Linux-only modes let a second, non-root uid attempt the probe's own
Unix-domain endpoint. On any other OS they print `INVALID: ... is Linux-only`
and exit `2`; the two-process probe and its Windows named-pipe path are
unchanged. The current uid is read from `/proc/self/status` (the effective uid);
no native binding is added. The runnable procedure is
[eng/verification/prf-04-second-linux-uid.md](../../eng/verification/prf-04-second-linux-uid.md).

| Mode | Run as | Result |
|---|---|---|
| `--wrong-uid-serve` | the owning uid (not root) | Creates a new owner-only `0700` directory `/tmp/afprf04-wu-<32 hex>` and serves the probe's own Kestrel endpoint `endpoint.sock` in it, with the real generated LocalBootstrap service and no expected peer, so every Challenge is refused in-band. Prints `WRONG-UID-ENDPOINT\|<socket>\|<uid>\|<pid>`. Reads `COUNT` (prints `CHALLENGE-DISPATCHES\|<n>`) and `STOP` from standard input; ends on `STOP`, end of input or after 30 minutes, printing `STOPPED\|<stop\|eof\|bound>\|challenge-dispatches=<n>`, and removes the directory. |
| `--wrong-uid-control <socket>` | the owning uid | The owner's connect must succeed, `SO_PEERCRED` must name the same uid, and the generated Challenge must be refused in-band (authentication). `PASS` exit `0`; otherwise `FAIL` exit `1` (`INVALID` exit `2` for root or a server of another uid). |
| `--wrong-uid-connect <socket> <owner-uid>` | a second, non-root uid | A raw connect. `EACCES` prints `PASS: wrong-uid peer refused at connect (EACCES)`, exit `0`. A connection prints `FAIL: wrong-uid peer connected (...)`, exit `1`, with the in-band result of one generated Challenge. Any other error (a missing socket, a dead listener, a timeout) is `INCONCLUSIVE`, exit `3`. Running as root or as the owner uid is `INVALID`, exit `2`, before any connect. |
| `--verify-wrong-uid-mode` | any non-root uid | An offline self-check, like `--verify-unix-peer-pid-backends`: the connect classification, the exit codes, the in-band descriptions, argument and uid validation, `/proc/self/status` parsing, the root and same-uid guards and the Linux-only refusal. On Linux it adds one real kernel `EACCES` exercise: a raw listener in a `chmod 000` directory is refused and classified as the refusal, a missing socket is inconclusive, and the owner's connection is observed through `SO_PEERCRED`. |

The control and connect modes print a `WRONG-UID-IDENTITY|<uid>` line first.
The barrier under test is the endpoint's owner-only `0700` directory, the same
protection as the two-process probe's directory. The socket file's own mode
follows the process umask and is not a probe guarantee. A same-uid run of these
modes is a control of the mechanics only. It is never wrong-uid evidence.
