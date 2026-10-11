# ArcForges.ContentSandbox

The first-party Native AOT content helper host (WP-11.09, PLT.45). A product never parses hostile image bytes in its own process:
it launches this helper in a restricted operating-system profile through `ArcForges.ContentSandbox.Broker` and talks to it over the
generated `ContentSandboxService` contract. This project is non-packable. Helper and broker packaging (this helper as a per-RID runtime
package, and the `ArcForges.ContentSandbox.Contracts` and `.Broker` packages) is out of scope, not completed: PLT.46 was narrowed to the four
Security packages (coordinator ruling S52(1); P2-026 item 20), so no helper or broker package exists or is claimed.

## What it is

- **Entry (`Host/HelperEntry`).** Reads one launch frame from its inherited standard input (never argv, environment or a file), wraps exactly
  the resources the frame lists, brings the operating-system profile into force, verifies it by attempting what it must deny, and only then runs
  the host. A malformed frame (exit 64), an inventory that is not the closed set (65) or a profile that cannot be enforced and verified (70)
  ends the process before any parser exists. A helper never falls back to full trust.
- **Host (`Host/ContentSandboxHost`).** Serves the sandbox contract to the parent on the supplied service stream and proves the one-use launch
  secret to the parent on the supplied control stream (the generated LocalBootstrap challenge, confirm and renew from `ArcForges.LocalRpc`),
  keeps its registration lease, and leaves the process when the parent is lost, the session lease passes or the session is closed. Renewal and
  cancellation are declared reserved control methods, so they pass a full data lane. It listens on no network endpoint.
- **Service (`Host/ContentSandboxServiceImpl`).** Holds exactly one invocation-scoped session whose identity, input and budget the launch fixed.
  It chooses parsers only from the composition named by the launch (the production helper composes `ProductionParserProfile`, which composes no parser: the local PDF path is retired by P2-022 and the still-image composition, NAT.31, is out of scope in V1 under P2-026), fills only the slot grants the parent made, seals exactly the bytes written, and checks every
  result with the same shape rules the parent applies again. A parser that fails, overruns its deadline or is cancelled ends the invocation.
- **Profiles.** Windows: the parent creates the process in an AppContainer and Job Object; the helper checks it cannot reach the parent process
  or the user profile. Linux (`Native/LinuxEnforcement`): the helper applies no_new_privs, resource limits, Landlock and a seccomp
  filter to itself and checks them. Seccomp is synchronised to every thread (TSYNC). Landlock restricts only the calling thread unless its own
  TSYNC flag is given, so the helper passes that flag, refuses to run if the kernel rejects it (a kernel without multithread Landlock, which
  is recent), and its self-check observes the denial from the applying thread, from several thread-pool threads and from a new thread. Each
  refusing step writes one bounded diagnostic line to its standard error before exit 70 (`isolation: <step> refused (<errno>)` when a step that
  puts the profile in force fails, `isolation: <step> was not denied (<errno>)` when a self-check attempt is not denied), so the parent's
  `security.isolation_unavailable` detail names the step. Parent loss is detected by the helper polling its parent id (no parent-death signal: the kernel ties it to the spawning thread, which may retire while the parent lives) and the supervising parent kills the helper on every path. A wedged helper whose parent was killed is not ended by the kernel. No offline test observes the Landlock TSYNC flag or the shrink seal (a mutant that drops either survives offline); the Linux opt-in checks below observe both on a Linux kernel. Not covered on Linux: tgkill to another same-user process (the runtime needs it), no PID/user/mount namespaces. macOS is not supported: there is no launcher, no profile and no entitlements file; the
  reserved `MacOsAppSandboxXpc` value is never selected, and a launch or a frame carrying it is refused (security.isolation_unavailable).
- **Fixture (`Fixture/`).** TEST ONLY: the same host with one deliberately hostile first-party test composition (the registered
  `SUB-hostile-test-parser`). It parses no real format. Its script attacks the boundary (reads a product file, connects to a real listener,
  sends datagrams, opens other processes, spawns, maps the read-only input writable) or crashes, hangs, exhausts memory or overruns its
  output; its Linux variants also signal another process, open `/proc/<pid>/mem`, resize an output slot and open files from new and pool
  threads. It is never packaged or composed into a release.

## Tests

`Tests/` (`ArcForges.ContentSandbox.Tests`) runs offline in CI: the launch frame, the record mapping, the budget, the retired PDF calls answering their closed refusals without a parser, the parent
and the real helper host end to end over in-memory streams (grant, seal, private copy and digest on the copy, acknowledgement, cancellation through
the control slot while the data lane is full, deadlines, a helper that dies mid-call), a helper that lies, the pure parts of the Linux profile (a classic-BPF interpreter runs
the seccomp program, and the closed diagnostic step names), and the macOS refusal. **The in-process helper is not operating-system containment.**

The OS checks are explicit local opt-in, skipped by default and always skipped in hosted CI (P2-017). On Windows (`OsIsolationTests`), once:

```powershell
dotnet publish src/DesktopHelpers/ArcForges.ContentSandbox/Fixture/ArcForges.ContentSandbox.HostileFixture.csproj -c Release -r win-x64
$env:ARCFORGES_CONTENTSANDBOX_OS = '1'
$env:ARCFORGES_CONTENTSANDBOX_FIXTURE = '<the publish directory>'
dotnet test --project src/DesktopHelpers/ArcForges.ContentSandbox/Tests/ArcForges.ContentSandbox.Tests.csproj -c Release
```

Publishing needs the Visual Studio C++ tools on the path of the shell; on a machine where `findvcvarsall.bat` cannot find `vswhere.exe`, put
`%ProgramFiles(x86)%\Microsoft Visual Studio\Installer` on `PATH` for that shell. The results are evidence for that machine, that Windows build and that fixture only.

On Linux (`LinuxOsIsolationTests`), once, on a Linux-native file system (ext4; never a Windows mount such as `/mnt/c`). Locally this is
WSL2 Debian (P2-024), with the pinned .NET SDK in `~/.dotnet` and clang and lld for the Native AOT link. From PowerShell, clone the branch
being recorded into the Debian home directory and open a Debian shell:

```powershell
wsl.exe -d Debian -- git clone --no-local --branch <branch> /mnt/c/<path of the DesktopPlatform clone> ~/arcforges/DesktopPlatform
wsl.exe -d Debian
```

Then, in that shell:

```bash
cd ~/arcforges/DesktopPlatform
export DOTNET_ROOT="$HOME/.dotnet" PATH="$HOME/.dotnet:$PATH" NUGET_PACKAGES="$HOME/arcforges/nuget"
T=src/DesktopHelpers/ArcForges.ContentSandbox/Tests/ArcForges.ContentSandbox.Tests.csproj
F=src/DesktopHelpers/ArcForges.ContentSandbox/Fixture/ArcForges.ContentSandbox.HostileFixture.csproj
uname -r; cat /etc/os-release; dotnet --version; clang --version | head -1; git rev-parse HEAD
dotnet restore "$T" --locked-mode && dotnet restore "$F" --locked-mode
git diff --exit-code -- '*packages.lock.json'
dotnet build "$T" -c Release --no-restore
dotnet publish "$F" -c Release -r linux-x64 --no-restore
export ARCFORGES_CONTENTSANDBOX_LINUX_OS=1
export ARCFORGES_CONTENTSANDBOX_FIXTURE="$PWD/<the publish directory printed by dotnet publish, under artifacts/bin>"
dotnet test --project "$T" -c Release --no-build
```

Every check prints `[os-evidence]` lines; record them with the commit, `uname -r`, the distribution and the SDK. The first check records the
kernel facts (`/sys/kernel/security/lsm` or its absence, `CONFIG_LSM` and the Landlock, seccomp and user-namespace options from
`/proc/config.gz`, the Landlock ABI, `landlock_restrict_self` with and without the TSYNC flag, seccomp TSYNC and `close_range`); each
restricting probe runs in a child copy of the test host. On a kernel that refuses the TSYNC flag the helper must refuse fail-closed
(`security.isolation_unavailable`, `exit=70`, `isolation: landlock-tsync refused (<errno>)`), that refusal is checked, and the containment set
is skipped as "blocked on a Linux kernel with multithread Landlock (TSYNC), not proven". The pinned-build integrity refusal, the production
output-slot seals and unconfined control runs of the attacks (each must report ALLOWED, so a denial inside the helper is not a vacuous probe)
run on any kernel. The results are evidence for that machine, that kernel and that fixture only.

## Status by RID (2026-10-11)

- **win-x64.** The nine `OsIsolationTests` are the only evidence of AppContainer and Job Object denial and parent-death cleanup; see the Plan
  ledger record of PLT.45 for the runs and the commit each ran at.
- **linux-x64: blocked on a Linux kernel with multithread Landlock (TSYNC), not proven.** The Linux opt-in checks ran on 2026-10-11 in WSL2
  Debian 13 (kernel `6.18.40.1-microsoft-standard-WSL2`, x86_64, glibc 2.41, .NET SDK 10.0.400, clang 19.1.7, ext4 clone) with a freshly
  published Native AOT linux-x64 fixture: 14 checks, 5 passed, 9 skipped (the containment set), 0 failed. Kernel facts observed:
  `/sys/kernel/security/lsm` absent (securityfs not mounted); `CONFIG_LSM="landlock,lockdown,yama,loadpin,safesetid,integrity,selinux,apparmor,tomoyo"`,
  `CONFIG_SECURITY_LANDLOCK=y`, `CONFIG_SECCOMP_FILTER=y`, `CONFIG_USER_NS=y`; Landlock ABI 7; `landlock_restrict_self` without flags
  accepted, with the TSYNC flag answered -1 errno 22 (EINVAL); seccomp `SET_MODE_FILTER` with TSYNC accepted; `close_range` accepted;
  memfd sealing available; user namespaces available (`max_user_namespaces` 63939); Yama `ptrace_scope` 1; the WSL shell itself already
  carries one seccomp filter. Observed on that kernel: the real Linux launcher started the helper, which refused before any parser ran
  (`security.isolation_unavailable`, `exit=70`, `isolation: landlock-tsync refused (22)`) and was reaped; a helper that is not the pinned
  build was never started (`resource.integrity_failed`); the production output slots carry SHRINK, GROW and SEAL seals and refuse shrinking
  and growing with EPERM and a writable mapping of a read-only reopen; the unconfined controls reported ALLOWED. **No Linux containment
  pass is claimed**: file, network, process, spawn, mapping, thread, crash, hang, memory-exhaustion, cancellation, oversized-output and
  parent-death containment on Linux were not observed. Owner: the PLT.45 completion follow-up; trigger: a local Linux kernel that accepts the
  TSYNC flag, on which the same commands run the containment set.
- **win-arm64: blocked on a Windows ARM64 host, not proven.** No Tier 2 waiver is granted.
- **macOS: not supported and never claimed** (P2-023).

## What is not proven

See the Plan ledger record of PLT.45. In addition to the RID status above, two residuals are disclosed and are not PLT.45 acceptance:

- **Authenticode.** Windows signature verification of the helper is not implemented: the launcher pins the SHA-256 of the installed helper
  from the signed inventory.
- **AppContainer storage reuse.** The pooled AppContainer identities are reused one after another and keep their per-container storage between
  invocations; nothing cleans it on release and no test covers it (see the broker README).

The opt-in results on each platform are one machine, one OS build or kernel and one fixture; they are not generalised.

## Production composition

`ProductionParserProfile` (`arcforges-parsers-v1`) is the one composition the production helper contains. It composes no parser:
the local PDF parser path (its native `arc_pdf_*` engine and `ArcForges.Native.Pdf` binding) is retired by P2-022 and removed by NAT.32, and
the production parser tasks are out of scope, not completed, under P2-026: NAT.14 (PDF and image parsers), NAT.31 (the still-image parser
composition) and PLT.54 (the production parsers and their containment evidence). The five ContentSandbox PDF RPCs stay in the published
`arcforges.local.sandbox.v1` schema unchanged. The service answers them without reaching any parser: `OpenPdf` answers
`resource.parser_failed`, a malformed call answers `validation.invalid_request`, the other read calls answer `state.not_found`, and
`ClosePdf` returns its idempotent receipt. The hostile test composition is never registered in production.

**What is not proven.** The PDF path is retired, not completed: no PDF parsing, rendering, preview or AI PDF reading is claimed. No
still-image parser is composed and no containment against a production parser or a hostile real-format input is claimed; PLT.45 completes on
its first-party hostile-test-parser proof (P2-026).
