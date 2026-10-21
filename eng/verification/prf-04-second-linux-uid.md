# PRF.04 second-Linux-uid Unix-socket denial procedure

Status: blocked on a second Linux uid, not proven. The user deferred the
second-account checks on 2026-10-10. No second uid has run this procedure, and
no result of it is recorded here or claimed anywhere. macOS is not supported and
never claimed (P2-023).

This procedure checks one property of the PRF.04 Native AOT probe on Linux. A
second, non-root uid that tries to connect to the probe's Unix-domain endpoint
is refused by the kernel (`EACCES`) before any byte reaches the server. The
barrier is the endpoint's owner-only `0700` directory, the same protection that
the two-process probe gives its own sockets. The socket file's own mode follows
the process umask and is not a probe guarantee, so it is not checked here.

The probe modes it uses are documented in
[tests/LocalRpcAotTests/README.md](../../tests/LocalRpcAotTests/README.md#second-linux-uid-modes).
The LocalRpc library's own second-uid procedure is separate: section U1 of
[src/BuildingBlocks/ArcForges.LocalRpc/Tests/wrong-user-procedure.md](../../src/BuildingBlocks/ArcForges.LocalRpc/Tests/wrong-user-procedure.md).
Both procedures can share the same second uid.

## 1. Host and uids

Run on a native Linux host (local WSL is not a development dependency; ArcForges-Design
AD-0018). Work on the Linux-native file system, never
under `/mnt/c`.

- The owning uid (A) is the distribution's normal user, and it is not root.
- The second uid (B) is a non-root user that is not in the `sudo` group. If the
  LocalRpc procedure has already created `afwrong`, reuse it. Otherwise A creates
  it once:

  ```bash
  sudo useradd --create-home --shell /bin/bash --user-group afwrong
  id -u; id afwrong
  ```

  `id -u` (A) and the uid in `id afwrong` (B) must differ, and neither may be
  `0`. `id afwrong` must not list the `sudo` group. Root is never acceptable as
  B: it bypasses discretionary access control, and the probe reports `INVALID`.

## 2. Staging

Build the linux-x64 Native AOT probe from a clean Linux-native clone of the
commit under test. Use the SDK that `global.json` pins (10.0.400), with clang and
lld on `PATH`:

```bash
git status --porcelain
git rev-parse HEAD
dotnet --version
dotnet restore tests/LocalRpcAotTests/LocalRpcAotTests.csproj --locked-mode
dotnet publish tests/LocalRpcAotTests/LocalRpcAotTests.csproj -c Release -r linux-x64 -o artifacts/prf-04/linux-x64 --no-restore
```

`git status --porcelain` must print nothing. Record the 40-hex commit. Home is
mode 0700, so B cannot run the binary from A's clone. A installs the
self-contained executable into a world-readable directory:

```bash
PRF=/opt/arcforges-prf04-wrong-uid
sudo install -d -o "$(id -un)" -g "$(id -gn)" -m 0755 "$PRF"
install -m 0755 artifacts/prf-04/linux-x64/LocalRpcAotTests "$PRF/LocalRpcAotTests"
sha256sum "$PRF/LocalRpcAotTests"
```

Record the SHA-256 digest.

## 3. Terminals

Open two terminals as A, T1 and T2. Paste this into each:

```bash
PRF=/opt/arcforges-prf04-wrong-uid
UIDA=$(id -u)
prf()   { "$PRF/LocalRpcAotTests" "$@"; echo "EXIT|$?"; }
prf_b() { sudo -u afwrong "$PRF/LocalRpcAotTests" "$@"; echo "EXIT|$?"; }
```

`prf` runs as A and `prf_b` runs as B. The probe needs no environment
variables, so the environment reset by `sudo -u` does not matter. The serving
probe keeps T1. Type `COUNT` or `STOP` and Enter there.

## 4. Steps

1. Self-checks. T2: `prf --verify-wrong-uid-mode`, then `prf_b --verify-wrong-uid-mode`.
   Each prints `PASS: wrong-uid mode self-check: ...; real kernel EACCES from a chmod-000 directory classified as a refusal, a missing socket as inconclusive, and the owner connection (uid <uid>, own pid) observed through SO_PEERCRED.`
   and then `EXIT|0`. The uid is A's in the first run and B's in the second. This
   shows that B can run the staged binary and that the kernel's `EACCES` is
   classified as a refusal for each uid.
2. Serve. T1: `"$PRF/LocalRpcAotTests" --wrong-uid-serve`. Expected:
   `WRONG-UID-ENDPOINT|/tmp/afprf04-wu-<32 hex>/endpoint.sock|<uid A>|<pid>`.
   In T2, set `SOCK=<socket>` from that line and `HDIR=$(dirname "$SOCK")`.
3. Mode. T2: `stat -c '%a %U %n' "$HDIR"`. Expected: `700 <A's name> /tmp/afprf04-wu-<32 hex>`.
4. Control before. T2: `prf --wrong-uid-control "$SOCK"`. Expected:
   `WRONG-UID-IDENTITY|<uid A>`,
   `PASS: owner uid <uid A> connected to server pid <pid>; generated Challenge refused in-band (authentication), as the endpoint has no expected peer.`,
   `EXIT|0`. The `<pid>` is the serving probe's pid from step 2.
5. Wrong-uid attempt. T2: `prf_b --wrong-uid-connect "$SOCK" "$UIDA"`. Expected:
   `WRONG-UID-IDENTITY|<uid B>`, `PASS: wrong-uid peer refused at connect (EACCES)`, `EXIT|0`.
6. Guard controls. These show that the probe cannot be made to pass from the wrong
   uid. T2:
   - `prf --wrong-uid-connect "$SOCK" "$UIDA"`. Expected: `WRONG-UID-IDENTITY|<uid A>`,
     `INVALID: this process runs as the owner uid <uid A>; a same-uid connect proves nothing about a second uid.`,
     `EXIT|2`.
   - `sudo "$PRF/LocalRpcAotTests" --wrong-uid-connect "$SOCK" "$UIDA"; echo "EXIT|$?"`.
     Expected: `WRONG-UID-IDENTITY|0`, `INVALID: this process runs as root (uid 0), ...`, `EXIT|2`.

   Neither run connects.
7. Control after. Repeat step 4. Expected: the same `PASS` line and `EXIT|0`.
8. Dispatch count. T1: `COUNT`. Expected: `CHALLENGE-DISPATCHES|2`. Only the two
   owner controls reached the generated service. B's attempt did not.
9. Stop. T1: `STOP`. Expected: `STOPPED|stop|challenge-dispatches=2`, and the
   probe exits `0` (`echo "EXIT|$?"` in T1 prints `EXIT|0`). T2:
   `test -e "$HDIR" || echo gone` prints `gone`.
10. Gone controls. T2:
    - `prf --wrong-uid-control "$SOCK"`. Expected: `FAIL: the owner connect failed (AddressNotAvailable); the endpoint is not live for its owner.`, `EXIT|1`.
    - `prf_b --wrong-uid-connect "$SOCK" "$UIDA"`. Expected: `INCONCLUSIVE: connect failed with AddressNotAvailable, not EACCES; ...`, `EXIT|3`.

    This shows that a missing endpoint is never counted as a refusal.

## 5. Verdict

The property is proven only when all of these hold in one session:

- Step 1 printed `PASS` and `EXIT|0` for both uids.
- Steps 2 and 3 showed a socket of uid A inside a `700` directory owned by A.
- Steps 4 and 7 (the controls before and after) printed `PASS` and `EXIT|0`.
- Step 5 printed `WRONG-UID-IDENTITY|<uid B>` with a uid other than A's and not
  `0`, then `PASS: wrong-uid peer refused at connect (EACCES)` and `EXIT|0`.
- Step 6 printed `INVALID` and `EXIT|2` twice.
- Step 8 printed `CHALLENGE-DISPATCHES|2`, and step 9 printed
  `STOPPED|stop|challenge-dispatches=2` with exit `0` and `gone`.

Outcomes that do not prove the property:

- `INCONCLUSIVE: ...` (exit `3`) in step 5 is never a refusal. A missing socket, a
  dead listener or a timeout says nothing about B. Record it. The property is not
  proven.
- `INVALID: ...` (exit `2`) in step 5 means the set-up is wrong: B is root, or B is
  the same uid as A. Record it. The property is not proven.
- If the probe prints nothing, crashes or hangs, record it. The property is not
  proven.
- A repeat after any of these is a new attempt. Record it in its own block and
  report every attempt.

`FAIL: wrong-uid peer connected (...)` with `EXIT|1` in step 5 is a failed
denial. The line also reports the in-band result of the generated Challenge.
Stop, record every line verbatim and report it as a defect. Do not retry for a
pass.

## 6. Recording

Record this block verbatim for each attempt. The coordinator copies it into the
PRF.04 ledger. Nothing is recorded as proven from memory or from a partial run.

```text
procedure: eng/verification/prf-04-second-linux-uid.md
date (UTC):
commit: <40-hex>, clean
binary: /opt/arcforges-prf04-wrong-uid/LocalRpcAotTests sha256 <digest>, linux-x64 Native AOT
host: <. /etc/os-release; echo "$PRETTY_NAME">, <uname -r>, <dotnet --version>, <clang --version | head -1>
owning uid: <name> <uid>, not root
second uid: <name> <uid>, not root, not in sudo
lines: every printed line of steps 1 to 10, in order, with the EXIT lines and the terminal that printed each
verdict: proven | not proven (<rule that failed>)
```

## 7. Cleanup

```bash
ls -d /tmp/afprf04-wu-* 2>/dev/null
sudo rm -rf /opt/arcforges-prf04-wrong-uid
```

`ls` must print nothing. If it prints a directory that a crashed probe left
behind, A removes it with `rm -rf`. If no other procedure still needs B, remove
it with `sudo userdel --remove afwrong`.
