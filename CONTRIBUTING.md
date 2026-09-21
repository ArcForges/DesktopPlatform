# Contributing to DesktopPlatform

Use an isolated `.worktree/` branch and the [README verification commands](README.md#build-and-verify).
Shared mechanism changes belong here; product rules and business RPC schemas belong to their owners.
Keep C# 14, C++20, explicit source provenance, committed dependency locks and warnings-as-errors.

PR CI compiles/stages Windows native outputs, builds/packages the managed solution on Linux,
and runs targeted offline architecture/policy tests, formatting, dependency review and secret scanning.
Weekly/manual Deep check retains C# CodeQL only. No macOS, native runtime, installed-consumer,
GUI/device/browser or live-service CI is permitted under [AGENTS.md](AGENTS.md).

Run relevant format/static checks once. The independent IDE build and runtime diagnostics are explicit
local opt-in when affected, never automatic pre-push work. Reuse installed tools and dependencies.
Include actual results and untested coverage in the PR description. Publication completion uses
provider status, without public package re-downloads or repeated hash/consumer checks.
The [packaging guide](eng/packaging/README.md) explains the reduced candidate and release flows.
