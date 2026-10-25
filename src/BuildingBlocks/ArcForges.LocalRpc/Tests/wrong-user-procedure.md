# Wrong-user denial procedure (PLT.09, PLT.10, PLT.11)

This procedure checks that a second operating-system account is refused by the endpoints and launch roots of
`ArcForges.LocalRpc`. One account cannot show this, so the procedure needs a person who can create a second local
account (Windows) or a second uid (Linux). Hosted CI never runs it.

Status at the time of writing: not run. Wrong-user denial is blocked on a second Windows account, not proven, and
blocked on a second Linux uid, not proven. A section counts as proven only when every rule in "Verdict" below holds.

| Section | Task | What the second account must observe |
|---|---|---|
| W1 | PLT.09 | The plain Named Pipe endpoint refuses its raw connect. |
| W2 | PLT.09 | The library client refuses a pipe that the second account owns (the foreign-pipe client check). |
| W3 | PLT.10 | The launch authority refuses a launch root that the second account owns. |
| W4 | PLT.10 | The launch endpoint refuses its raw connect, over a Named Pipe and over a Unix socket. |
| W5 | PLT.11 | The registration endpoint refuses its raw connect, over a Named Pipe and over a Unix socket. |
| U1 | PLT.09, PLT.10, PLT.11 | On Linux, the plain, launch and registration Unix sockets refuse a second uid. |

The checks cover the operating-system boundary only. The in-band launch proof and the registration gate are covered by
the offline tests and are not part of this procedure.

## The helper modes

The test assembly `ArcForges.LocalRpc.Tests.dll` doubles as the helper. A mode runs only when two environment variables
are set: `DOTNET_STARTUP_HOOKS` names the assembly, and `ARCFORGES_LOCALRPC_HELPER` names the mode with `|`-separated
arguments. The code is `WrongUserHelperProcess.cs`. Its parsing, classification, guards and exit codes are tested
offline (`LocalRpcWrongUserProcedureTests`). `LocalRpcWrongUserProcedureChecks` runs every mode under one account
(`ARCFORGES_LOCALRPC_OS_STREAMS=1`); those runs are controls and never wrong-user evidence.

| Mode | Run by | Prints |
|---|---|---|
| `wrong-user-serve\|<plain\|launch\|registration>\|<named-pipe\|unix-socket>` | owning account | `SERVING\|<transport>\|<address>\|<owner SID or uid>\|<pid>`, then `STOPPED\|<reason>` after a `STOP` line, the end of input or 30 minutes |
| `wrong-user-connect\|<transport>\|<address>\|<owner>\|<refused\|admitted-control>` | either | `IDENTITY\|<SID or uid>`, then one outcome line |
| `wrong-user-squat-pipe\|<name>` | either (Windows) | `SQUATTING\|<name>\|<owner SID>`; the pipe grants Authenticated Users read and write |
| `wrong-user-client\|<name>\|<squatter SID>\|<refused\|admitted-control>` | either (Windows) | `IDENTITY\|<SID>`, then one outcome line |
| `wrong-user-foreign-root-make\|<path>\|<grantee SID>` | root owner (Windows) | `FOREIGN-ROOT\|<path>\|<owner SID>\|<grantee SID>` |
| `wrong-user-root-check\|<path>\|<refused\|admitted-control>` | either (Windows) | `IDENTITY\|<SID>`, then one outcome line |

`wrong-user-connect` is a raw operating-system connect. On Windows it is a `NamedPipeClientStream` without
`CurrentUserOnly`. On Linux it is a plain `AF_UNIX` socket. So a refusal comes from the endpoint's own protection and
not from a check in the library client.

The outcome lines and exit codes are:

| Line | Meaning | Exit code with `refused` | Exit code with `admitted-control` |
|---|---|---|---|
| `REFUSED\|access-denied` | The OS refused the raw connect (`UnauthorizedAccessException` or `EACCES`). | 0 | 1 |
| `REFUSED\|not-owned-by-current-user` | The library client refused a pipe owned by another account. | 0 | 1 |
| `REFUSED\|owner-not-current-user` | The launch authority refused the root with exactly "A launch directory must be owned by the current user." | 0 | 1 |
| `ADMITTED` | The connection opened or the root was accepted. | 1 | 0 |
| `PASSED-OWNERSHIP` | The library client's pipe-ownership check passed. | 1 | 0 |
| `INCONCLUSIVE\|<detail>` | Not found, refused by a dead listener, busy, timed out, another refusal reason. | 3 | 3 |
| `INVALID\|<detail>` | `same-account`, `root`, `administrators-owned`, `unsupported-platform`, `root-path` or `owner-not-creator`. | 2 | 2 |

A malformed mode prints `USAGE|<message>` on standard error and exits with 64. The serving, squatting and root-making
modes exit with 0 when they finish normally.

## Common set-up

### S1. Accounts

Windows:

- The owning account (A) is the account that builds the output. All of A's steps run in a non-elevated console.
- The second account (B) is a standard local account. It is not a member of Administrators and it is never elevated.
  An administrator creates it once. The `*` makes `net user` ask for the password, so the password is never on the command
  line:

  ```powershell
  net user afwrong * /add
  net localgroup Administrators
  ```

  The second command's list must not contain `afwrong`. An elevated or administrator account is not acceptable as B: its
  token's default owner is Administrators, and the launch authority accepts an Administrators-owned root by design. W3
  then reports `INVALID|administrators-owned`.
- Every console, for A and for B, runs this identity check. The first line is the account SID. The second must print
  `False`:

  ```powershell
  [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
  ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
  ```

Linux (a native Linux host; work on the Linux-native file system, never under a Windows mount such as `/mnt/c`):

- The owning uid (A) is the distribution's normal user.
- The second uid (B) is a non-root user that is not in the `sudo` group. Create it once:

  ```bash
  sudo useradd --create-home --shell /bin/bash --user-group afwrong
  id afwrong
  ```

  `id afwrong` must show a uid other than 0 and no `sudo` group. Root is never acceptable as B: it bypasses
  discretionary access control, and the helper reports `INVALID|root`.

### S2. Staging

Build from a clean checkout of the commit under test, with the SDK that `global.json` pins on `PATH` (the same commands
run in bash on Linux, in a Linux-native clone):

```powershell
git status --porcelain
git rev-parse HEAD
dotnet restore src/BuildingBlocks/ArcForges.LocalRpc/Tests/ArcForges.LocalRpc.Tests.csproj --locked-mode
dotnet build src/BuildingBlocks/ArcForges.LocalRpc/Tests/ArcForges.LocalRpc.Tests.csproj -c Release --no-restore
```

`git status --porcelain` must print nothing. Record the 40-hex commit. The output is in
`artifacts/bin/dotnet/<windows|linux>/ArcForges.LocalRpc.Tests/Release/net10.0/`.

Windows. B cannot read A's profile, so the output is copied to `C:\ArcForgesWrongUser`. It runs on the machine-wide
runtime in `C:\Program Files\dotnet`; this workstation has Microsoft.NETCore.App and Microsoft.AspNetCore.App 10.0.12.
A runs the following, in the repository root, in a non-elevated console. If A may not create a folder in `C:\`, an
administrator creates `C:\ArcForgesWrongUser` and makes A its owner, and A runs the rest.

```powershell
$SidA = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
$SidB = ([Security.Principal.NTAccount]"$env:COMPUTERNAME\afwrong").Translate([Security.Principal.SecurityIdentifier]).Value
New-Item -ItemType Directory C:\ArcForgesWrongUser | Out-Null
icacls C:\ArcForgesWrongUser /inheritance:r /grant:r "*S-1-5-18:(OI)(CI)F" "*S-1-5-32-544:(OI)(CI)F" "*${SidA}:(OI)(CI)F" "*S-1-5-11:(OI)(CI)RX"
New-Item -ItemType Directory C:\ArcForgesWrongUser\tests, C:\ArcForgesWrongUser\tmp, C:\ArcForgesWrongUser\roots | Out-Null
icacls C:\ArcForgesWrongUser\roots /grant "*${SidB}:(OI)(CI)M"
Copy-Item -Recurse artifacts\bin\dotnet\windows\ArcForges.LocalRpc.Tests\Release\net10.0\* C:\ArcForgesWrongUser\tests
& 'C:\Program Files\dotnet\dotnet.exe' --list-runtimes
```

The access list gives SYSTEM, Administrators and A full control and Authenticated Users read and execute; nothing is
inherited from `C:\`. B may also create folders in `roots` (W3). `tmp` is the temporary folder of A's serving console.
Its afwu-* folders inherit Authenticated Users read and execute, so B can reach the library's own owner-only directory
under it. On a Unix-socket route the library's protection is then the only barrier, not A's profile.

Linux. Home is mode 0700, so B cannot read A's clone or A's `~/.dotnet`. A copies the output, and the host and runtimes
of the SDK install, to a world-readable directory:

```bash
AFWU=/opt/arcforges-wrong-user
sudo install -d -o "$(id -un)" -g "$(id -gn)" -m 0755 "$AFWU"
mkdir -p "$AFWU/tests" "$AFWU/dotnet"
cp -a artifacts/bin/dotnet/linux/ArcForges.LocalRpc.Tests/Release/net10.0/. "$AFWU/tests/"
cp -a ~/.dotnet/dotnet ~/.dotnet/host ~/.dotnet/shared "$AFWU/dotnet/"
chmod -R a+rX "$AFWU"
"$AFWU/dotnet/dotnet" --list-runtimes
```

### S3. Consoles and the helper function

Windows. Open the consoles that a section names:

- A: a new, non-elevated Windows PowerShell console.
- B: started from any console of A with the following command. `runas` asks for B's password:

  ```powershell
  runas /user:$env:COMPUTERNAME\afwrong "powershell.exe -NoProfile -NoExit"
  ```

Paste this into every console, then run the S1 identity check:

```powershell
Remove-Item Env:\DOTNET_ROOT -ErrorAction SilentlyContinue
$AfwuDll = 'C:\ArcForgesWrongUser\tests\ArcForges.LocalRpc.Tests.dll'
$AfwuDotnet = 'C:\Program Files\dotnet\dotnet.exe'
function afwu([Parameter(Mandatory = $true)][string] $Mode) {
    $env:DOTNET_STARTUP_HOOKS = $AfwuDll
    $env:ARCFORGES_LOCALRPC_HELPER = $Mode
    try { & $AfwuDotnet $AfwuDll; "EXIT|$LASTEXITCODE" }
    finally { Remove-Item Env:\DOTNET_STARTUP_HOOKS, Env:\ARCFORGES_LOCALRPC_HELPER -ErrorAction SilentlyContinue }
}
```

In each console that serves as A, also set the temporary folder:

```powershell
$env:TMP = 'C:\ArcForgesWrongUser\tmp'; $env:TEMP = $env:TMP
```

Linux. Open each terminal on the Linux host and paste:

```bash
AFWU=/opt/arcforges-wrong-user
afwu()   { env -u TMPDIR DOTNET_STARTUP_HOOKS="$AFWU/tests/ArcForges.LocalRpc.Tests.dll" ARCFORGES_LOCALRPC_HELPER="$1" "$AFWU/dotnet/dotnet" "$AFWU/tests/ArcForges.LocalRpc.Tests.dll"; echo "EXIT|$?"; }
afwu_b() { sudo -H -u afwrong env -u TMPDIR DOTNET_STARTUP_HOOKS="$AFWU/tests/ArcForges.LocalRpc.Tests.dll" ARCFORGES_LOCALRPC_HELPER="$1" "$AFWU/dotnet/dotnet" "$AFWU/tests/ArcForges.LocalRpc.Tests.dll"; echo "EXIT|$?"; }
```

`afwu` runs as A and `afwu_b` runs as B. `sudo -u` resets the environment, so `env` passes the two variables. Without
`TMPDIR`, the serving helper's temporary folder is a mode-0700 `/tmp/afwu-*` directory.

Always quote the mode in single quotes, because it contains `|` (U1 uses double quotes where the shell must expand
`$ADDR`). Replace each placeholder in angle brackets with the value that an earlier line printed: `<SidA>` and `<SidB>`
are the SIDs from the S1 identity check, and `<uid A>` and `<uid B>` are the uids that `id -u` and `id -u afwrong` print.

A serving or squatting helper keeps its console. Type `STOP` and Enter to end it. It prints `STOPPED|stop` (the
squatter adds `|accepted=<n>`), then `EXIT|0`.

### S4. Reachability control R0 (Windows)

This control shows that B's staged runtime and helper start and can open a pipe that grants B access. It runs once
before W1 and once after W5.

1. A, in console A2: `afwu 'wrong-user-squat-pipe|af-wu-reach-1'`. It prints `SQUATTING|af-wu-reach-1|<SidA>`.
2. B, in console B1: `afwu 'wrong-user-connect|named-pipe|af-wu-reach-1|<SidA>|admitted-control'`. Expected:
   `IDENTITY|<SidB>`, `ADMITTED`, `EXIT|0`.
3. A2: `STOP`.

If B gets anything else, the B console cannot prove a refusal, and every Windows section of the session is not proven.

### S5. Recording

For each section run, record this block verbatim. The coordinator copies it into the task ledger, and the repository's
README Validation section summarises it. Nothing is recorded as proven from memory or from a partial run.

```text
procedure: src/BuildingBlocks/ArcForges.LocalRpc/Tests/wrong-user-procedure.md section <W1..W5|U1> [<route>/<transport>]
date (UTC):
commit: <40-hex>, clean
host: <Windows edition and build (cmd /c ver)> | <Linux PRETTY_NAME, uname -r>
runtime: Microsoft.NETCore.App <version>, Microsoft.AspNetCore.App <version> (<dotnet path>)
owning account: <name> <SID or uid>, administrator check False | uid not 0
second account: <name> <SID or uid>, not an administrator, not elevated | not root, not in sudo
lines: every printed line, in order, with the EXIT lines and the console or terminal that printed it
verdict: proven | not proven (<rule that failed>)
```

### Verdict

A section, or a route and transport within it, is proven only when all of the following hold:

- R0 passed in the same session (Windows), or B's start-up control passed (Linux, U1 step 1).
- The `IDENTITY` lines show A and B as different accounts.
- Each control before B's attempt printed its expected line with `EXIT|0`.
- B's attempt printed the expected `REFUSED|...` line with `EXIT|0`.
- Each control after B's attempt printed its expected line with `EXIT|0`.

Inconclusive results, and what to do with them:

- `INCONCLUSIVE|...` is never a refusal. A missing endpoint, a dead listener, a busy pipe or a timeout says nothing
  about B. Record it. The section is not proven.
- `INVALID|...` means the run was set up wrongly: the same account, root, an Administrators-owned root, or the wrong
  platform. Record it. The section is not proven.
- If a helper prints nothing, crashes or hangs, record it. The section is not proven.
- A repeat after any of these is a new attempt. Record it with its own block, and report every attempt.

`ADMITTED` or `PASSED-OWNERSHIP` for B's attempt, with `EXIT|1`, is a failed denial. Stop the procedure, record the
lines verbatim, and report it as a defect. Do not retry for a pass.

## W1. PLT.09 Named Pipe denial

Set-up and staging: S1 to S3 (Windows). Consoles A1, A2 and B1. R0 has passed.

1. A1: `afwu 'wrong-user-serve|plain|named-pipe'`. Expected: `SERVING|named-pipe|<pipe>|<SidA>|<pid>`. Note `<pipe>`
   (af-wu-<32 hex>).
2. Control before. A2: `afwu 'wrong-user-connect|named-pipe|<pipe>|<SidA>|admitted-control'`. Expected:
   `IDENTITY|<SidA>`, `ADMITTED`, `EXIT|0`.
3. Check. B1: `afwu 'wrong-user-connect|named-pipe|<pipe>|<SidA>|refused'`. Expected: `IDENTITY|<SidB>`,
   `REFUSED|access-denied`, `EXIT|0`.
4. Control after. Repeat step 2. Expected: `ADMITTED`, `EXIT|0`.
5. A1: `STOP`. Expected: `STOPPED|stop`, `EXIT|0`.
6. Gone control. Repeat step 2. Expected: `INCONCLUSIVE|...` (a missing pipe times out: `INCONCLUSIVE|timeout`),
   `EXIT|3`.

Inconclusive: any `INCONCLUSIVE` or `INVALID` in step 3. Step 3 gives `INVALID|same-account` when B1 is really A.
Cleanup: step 5 removes the pipe. Record: S5, section W1.

## W2. PLT.09 foreign-pipe client ownership

The library client checks the connected server end's owner against the current token's user SID before sending bytes. It does not
use `CurrentUserOnly`, whose runtime check compares the token's default owner (potentially BUILTIN\Administrators when elevated).
A different user or group owner is refused. Here B owns a pipe that grants A access. The raw connect is admitted, so only the
ownership check can refuse the client.

Set-up and staging: S1 to S3 (Windows). Consoles A1, B1 and B2.

1. B2: `afwu 'wrong-user-squat-pipe|af-wu-foreign-1'`. Expected: `SQUATTING|af-wu-foreign-1|<SidB>`.
2. Control (B owns it). B1: `afwu 'wrong-user-client|af-wu-foreign-1|<SidB>|admitted-control'`. Expected:
   `IDENTITY|<SidB>`, `PASSED-OWNERSHIP`, `EXIT|0`.
3. Access control before. A1: `afwu 'wrong-user-connect|named-pipe|af-wu-foreign-1|<SidB>|admitted-control'`.
   Expected: `IDENTITY|<SidA>`, `ADMITTED`, `EXIT|0`.
4. Check. A1: `afwu 'wrong-user-client|af-wu-foreign-1|<SidB>|refused'`. Expected: `IDENTITY|<SidA>`,
   `REFUSED|not-owned-by-current-user`, `EXIT|0`.
5. Access control after. Repeat step 3. Expected: `ADMITTED`, `EXIT|0`.
6. B2: `STOP`. Expected: `STOPPED|stop|accepted=<n>` (record n), `EXIT|0`.

Inconclusive:

- `INCONCLUSIVE|connect-...` in step 4: the client failed to connect for a reason other than ownership.
- `SQUATTING` with an owner other than `<SidB>`: B is elevated.
- `INVALID|same-account` in step 4: A1 is really B.

Cleanup: step 6 removes the pipe. Record: S5, section W2.

## W3. PLT.10 launch-root ownership

B creates a launch root that B owns. Its protected access list grants full control only to A, SYSTEM and
Administrators, and every one of those rules is accepted for A. So when A opens it, only the owner rule can refuse.

Set-up and staging: S1 to S3 (Windows; `roots` grants B Modify). Consoles A1 and B1.

1. Control root before. A1:
   - `afwu 'wrong-user-foreign-root-make|C:\ArcForgesWrongUser\roots\rt-w3-control|<SidA>'`. Expected:
     `FOREIGN-ROOT|C:\ArcForgesWrongUser\roots\rt-w3-control|<SidA>|<SidA>`, `EXIT|0`.
   - `afwu 'wrong-user-root-check|C:\ArcForgesWrongUser\roots\rt-w3-control|admitted-control'`. Expected:
     `IDENTITY|<SidA>`, `ADMITTED`, `EXIT|0`.

   The same access-list shape is accepted when A owns the root.
2. Foreign root. B1: `afwu 'wrong-user-foreign-root-make|C:\ArcForgesWrongUser\roots\rt-w3|<SidA>'`. Expected:
   `FOREIGN-ROOT|C:\ArcForgesWrongUser\roots\rt-w3|<SidB>|<SidA>`, `EXIT|0`. Then, in A1,
   `icacls C:\ArcForgesWrongUser\roots\rt-w3` shows A, SYSTEM and Administrators with full control and no inherited
   entry, and `(Get-Acl C:\ArcForgesWrongUser\roots\rt-w3).Owner` names B.
3. Check. A1: `afwu 'wrong-user-root-check|C:\ArcForgesWrongUser\roots\rt-w3|refused'`. Expected: `IDENTITY|<SidA>`,
   `REFUSED|owner-not-current-user`, `EXIT|0`.
4. Control after. Repeat the second command of step 1. Expected: `ADMITTED`, `EXIT|0`.

B cannot use `rt-w3` as a control, because it grants A, and B's own check reports `INCONCLUSIVE|other-refusal`. That is
expected and is not part of the verdict.

Inconclusive:

- `INVALID|administrators-owned` in step 3: B is elevated or an administrator.
- `INCONCLUSIVE|other-refusal` in step 3: a rule other than the owner rule refused.
- `INCONCLUSIVE|owner-unreadable` or `INCONCLUSIVE|not-found` in step 3.
- `INVALID|root-path` in step 1 or 2: the path already exists.

Cleanup: B1 runs `Remove-Item -Recurse C:\ArcForgesWrongUser\roots\rt-w3`, and A1 runs
`Remove-Item -Recurse C:\ArcForgesWrongUser\roots\rt-w3-control`. Record: S5, section W3.

## W4. PLT.10 launch endpoint denial (Named Pipe; Unix socket)

The serving helper creates a launch authority with a root under A's temporary folder, issues one launch, and serves its
endpoint with a launch-authorized server. On Windows, the Named Pipe is `afl-<32 hex>`, created with an explicit user-SID owner and protected user-only DACL.
The Unix socket is `<tmp>\afwu-*\rt\<12 hex>\s`, inside the library's protected owner-only launch directories. Run the
steps once with `<transport>` = `named-pipe` and once with `unix-socket`.

Set-up and staging: S1 to S3 (Windows). Console A1 has the S3 temporary folder set. Consoles A2 and B1.

1. A1: `afwu 'wrong-user-serve|launch|<transport>'`. Expected: `SERVING|<transport>|<address>|<SidA>|<pid>`.
2. Unix socket only. A2: `$Address = '<address>'`, then `icacls (Split-Path $Address)` and
   `icacls (Split-Path (Split-Path $Address))`. Both show only A, with no inherited entry.
   `icacls (Split-Path (Split-Path (Split-Path $Address)))` (the afwu-* folder) shows Authenticated Users read and execute.
3. Control before. A2: `afwu 'wrong-user-connect|<transport>|<address>|<SidA>|admitted-control'`. Expected:
   `IDENTITY|<SidA>`, `ADMITTED`, `EXIT|0`.
4. Check. B1: `afwu 'wrong-user-connect|<transport>|<address>|<SidA>|refused'`. Expected: `IDENTITY|<SidB>`,
   `REFUSED|access-denied`, `EXIT|0`.
5. Control after. Repeat step 3. Expected: `ADMITTED`, `EXIT|0`.
6. A1: `STOP`. Expected: `STOPPED|stop`, `EXIT|0`. On the Unix-socket run, `Test-Path <address>` is then `False`.
7. Gone control. Repeat step 3. Expected: `INCONCLUSIVE|...`, `EXIT|3`.

Inconclusive: any `INCONCLUSIVE` in step 4. On the Unix-socket run, `INCONCLUSIVE|socket-<code>` means that Windows
`AF_UNIX` answered with something other than access denied. Record the code; it is not a refusal.

The AF_UNIX residual: a Windows `AF_UNIX` serving helper may fail to close after `STOP`. This is the disclosed
non-close residual. If `STOPPED` and `EXIT|0` do not follow within 60 seconds:

- Record it.
- End the helper with `Stop-Process -Id <pid>`.
- Remove its afwu-* folder from `C:\ArcForgesWrongUser\tmp`.
- Treat step 7 as not observed.

Steps 3 to 5 still decide the verdict.

Cleanup: step 6. `C:\ArcForgesWrongUser\tmp` must then be empty. Record: S5, section W4, one block per transport.

## W5. PLT.11 registration endpoint denial (Named Pipe; Unix socket)

This is the same as W4 with the route `registration`. The served endpoint is the launch endpoint behind the
registration gate (`RequireRegistration`), with the generated LocalBootstrap service.

Set-up and staging: S1 to S3 (Windows). Console A1 has the S3 temporary folder set. Consoles A2 and B1. For each
`<transport>` in `named-pipe` and `unix-socket`:

1. A1: `afwu 'wrong-user-serve|registration|<transport>'`. Expected: `SERVING|<transport>|<address>|<SidA>|<pid>`.
2. Unix socket only: the `icacls` readback of W4 step 2.
3. Control before. A2: `afwu 'wrong-user-connect|<transport>|<address>|<SidA>|admitted-control'`. Expected:
   `ADMITTED`, `EXIT|0`.
4. Check. B1: `afwu 'wrong-user-connect|<transport>|<address>|<SidA>|refused'`. Expected: `IDENTITY|<SidB>`,
   `REFUSED|access-denied`, `EXIT|0`.
5. Control after. Repeat step 3. Expected: `ADMITTED`, `EXIT|0`.
6. A1: `STOP`. Expected: `STOPPED|stop`, `EXIT|0`.
7. Gone control. Repeat step 3. Expected: `INCONCLUSIVE|...`, `EXIT|3`.

Inconclusive: as in W4, and the same AF_UNIX residual handling applies. Cleanup: step 6. Then run R0 once more, and
then the Windows cleanup below. Record: S5, section W5, one block per transport.

## U1. Linux second-uid Unix-socket denial (plain, launch, registration)

On Linux, the library binds a socket only inside a directory with no group or other bits, and sets the socket to mode
0600. The launch route's root and launch directories are 0700. The serving helper's own `/tmp/afwu-*` directory is also
0700, so this section checks B twice for each route:

- Layered: as served.
- Isolated: after A opens the helper directory to 0711. Then only the library's own modes stand between B and the
  socket: the socket's 0600 on the plain route, and the 0700 `rt` and launch directories on the launch and registration
  routes. The library checks the directory modes only at bind, so the server keeps serving.

Set-up and staging: S1 to S3 (Linux). Terminals T1 and T2 as A.

1. B's start-up control, once per session:
   - T1: `afwu_b 'wrong-user-serve|plain|unix-socket'`. Expected: `SERVING|unix-socket|<b-address>|<uid B>|<pid>`.
   - T2: `afwu_b 'wrong-user-connect|unix-socket|<b-address>|<uid B>|admitted-control'`. Expected:
     `IDENTITY|<uid B>`, `ADMITTED`, `EXIT|0`.
   - T1: `STOP`.

   This shows that B's runtime and helper work.

Then, for each `<route>` in `plain`, `launch` and `registration`:

2. T1: `afwu 'wrong-user-serve|<route>|unix-socket'`. Expected: `SERVING|unix-socket|<address>|<uid A>|<pid>`. Set
   `ADDR=<address>` and `HDIR=$(echo "$ADDR" | cut -d/ -f1-3)` (the `/tmp/afwu-*` directory) in T2.
3. Modes. T2: `stat -c '%a %U %n' "$ADDR"; d=$(dirname "$ADDR"); while [ "$d" != /tmp ]; do stat -c '%a %U %n' "$d"; d=$(dirname "$d"); done`.
   Expected: the socket is `600`, and every directory up to and including `$HDIR` is `700`, owned by A.
4. Control before. T2: `afwu "wrong-user-connect|unix-socket|$ADDR|$(id -u)|admitted-control"`. Expected:
   `IDENTITY|<uid A>`, `ADMITTED`, `EXIT|0`.
5. Layered check. T2: `afwu_b "wrong-user-connect|unix-socket|$ADDR|$(id -u)|refused"`. Expected: `IDENTITY|<uid B>`,
   `REFUSED|access-denied`, `EXIT|0`.
6. Isolate. T2: `chmod 0711 "$HDIR"; stat -c '%a %n' "$HDIR"`. Expected: `711 <HDIR>`.
7. Isolated check. Repeat step 5. Expected: `REFUSED|access-denied`, `EXIT|0`.
8. Control after. Repeat step 4. Expected: `ADMITTED`, `EXIT|0`.
9. T1: `STOP`. Expected: `STOPPED|stop`, `EXIT|0`. T2: `test -e "$ADDR" || echo gone` prints `gone`.
10. Gone control. Repeat step 4. Expected: `INCONCLUSIVE|...`, `EXIT|3`.

Inconclusive:

- `INVALID|root` in step 5 or 7: `afwu_b` ran as root, because `afwrong` is uid 0.
- `INVALID|same-account`: the B uid equals A's.
- `INCONCLUSIVE|not-found` in step 7: the server removed its socket.
- Any other `INCONCLUSIVE|...`.

The layered check alone does not prove the library's protection. A route is proven only when both steps 5 and 7 are
refused.

Cleanup: step 9 removes the helper directory. `ls -d /tmp/afwu-* 2>/dev/null` must print nothing; remove any directory
it prints. Record: S5, section U1, one block per route. Add `. /etc/os-release; echo "$PRETTY_NAME"; uname -r` and the
`--list-runtimes` output.

## Cleanup after a session

Windows:

- A removes `C:\ArcForgesWrongUser`: `Remove-Item -Recurse C:\ArcForgesWrongUser`. Any `rt-w3` that B still owns is
  removed by B first.
- An administrator deletes the account with `net user afwrong /delete`, and removes its profile, for example
  `Get-CimInstance Win32_UserProfile | Where-Object LocalPath -like '*\afwrong' | Remove-CimInstance`.

Linux:

```bash
sudo rm -rf /opt/arcforges-wrong-user
sudo userdel --remove afwrong
```
