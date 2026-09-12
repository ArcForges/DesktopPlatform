# Contributing to DesktopPlatform

Use an isolated `.worktree/` branch and the [README verification commands](README.md#build-and-verify).
Shared mechanism changes belong here; product rules and business RPC schemas belong to their owners.
Keep C# 14, C++20, explicit source provenance, committed dependency locks and warnings-as-errors.

PR CI validates the managed solution, package metadata and a clean package consumer on Windows and Linux,
Windows native CMake/ABI probes, formatting, dependency review and secret scanning. Weekly/manual deep
checks retain C# CodeQL and Linux native clang-tidy, sanitizers and fuzzers. Native publication is a later
capability admission with per-RID AOT, licence and dependency evidence, not a consequence of passing probes.

Run `pre-commit run --all-files`; the Windows `win-slnx-release-x64` pre-push hook checks the independent
IDE build. Include the actual commands/results and any unverified boundary in the PR description.
The [packaging guide](eng/packaging/README.md) explains candidate and release flows.
