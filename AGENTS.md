# DesktopPlatform contributor instructions

This repository owns shared desktop mechanisms, C# interop, CMake/vcpkg and capability NuGet production.
The product applications, Cloud, AI, Web, Mobile and business RPC schemas have separate repositories.
The design authority for active development is [ArcForges-Design](https://github.com/ArcForges/ArcForges-Design) ([AD-0001](https://github.com/ArcForges/ArcForges-Design/blob/main/docs/decisions/AD-0001-flagship-pivot.md)).

- Work on a focused branch in `.worktree/`. Preserve the primary checkout and unrelated repositories.
- Use C# 14 / .NET 10 from `global.json`, C++20 and C17-compatible public C ABI headers.
- Keep native toolchains here. Consumers use exact published package versions and committed lock files;
  never add Git submodules or sibling source dependencies. Business proto generation belongs to Contracts.
- Put dependency versions in `Directory.Packages.props`, restore locked, retain warnings-as-errors and
  AOT/trim diagnostics. Native interop uses owned C ABI / LibraryImport, never a C++ ABI.
- Add SPDX headers to source/configuration; preserve third-party notices and source provenance.
- New projects are non-packable by default. Admit a package explicitly in `eng/packaging/packages.json`
  only when its behavior and dependency closure are verified. Never publish placeholders as capabilities.
- Keep build inputs declarative; executable packaging verification is the portable Python tool under `eng/`.
  Do not add tracked PowerShell or shell helper scripts.
- Record what actually ran. A successful package-policy smoke does not prove native capability AOT,
  product behavior, release signing or NuGet publication. Run the checks documented in the README.

## Flagship role

DesktopPlatform is an **active** repository of the ArcForges flagship ([AD-0001](https://github.com/ArcForges/ArcForges-Design/blob/main/docs/decisions/AD-0001-flagship-pivot.md)). Per [architecture 01 §5](https://github.com/ArcForges/ArcForges-Design/blob/main/docs/architecture/01-system-overview.md#5-repository-and-project-map) and the [reuse classification](https://github.com/ArcForges/ArcForges-Design/blob/main/docs/reuse/inventory-and-classification.md#2-desktopplatform), it adapts `ArcForges.LocalRpc` (service-endpoint mode, stream lane, per-method limit profiles and a peer identity provider; [refactor](https://github.com/ArcForges/ArcForges-Design/blob/main/docs/reuse/desktopplatform-refactor.md)) and `ArcForges.Security.Secrets` (Linux backends). The flagship reuses `ArcForges.Observability`, `ArcForges.DesignSystem`, `ArcForges.Desktop.Shell` and `ArcForges.Build.Policy`, and reuses `ArcForges.Persistence.Sqlite`, `ArcForges.NativeInterop`, `ArcForges.Foundation`, `ArcForges.Security` and `ArcForges.Security.Audit` where they fit. The other application-family packages, ContentSandbox and the native image packages are retained for future products and are not scheduled. The unfinished items the classification lists (Linux TSYNC, the in-repository Shell Avalonia adapter, the PLT.66 Contracts move, wrong-user procedures) are retained too and are not flagship prerequisites.

## Delivery (serial, ArcForges/Plan)

Tasks for this repository come from the [Plan delivery graph](https://github.com/ArcForges/Plan/blob/main/delivery-graph.json) and are delivered under the Plan [execution policy](https://github.com/ArcForges/Plan/blob/main/execution-policy.md) and [delivery procedure](https://github.com/ArcForges/Plan/blob/main/delivery-procedure.md) ([AD-0014](https://github.com/ArcForges/ArcForges-Design/blob/main/docs/decisions/AD-0014-delivery-method.md)). They are binding. The historical P2-018 model (delivery lanes, adoption slices, `delivery.py` claims and handoffs, parallel workers, integration-owner roles, Plan leases, the build slot and the launcher) is retired and never resumed.

- One task is active at a time. Work only inside its write scope, in a worktree `.worktree/<task-id-lower>` on branch `task/<task-id-lower>`, never in the primary checkout.
- Delegated workers and reviewers work locally. Only the coordinator pushes, opens pull requests, merges (at the reviewed head, after hosted CI passes) and publishes.
- Title pull requests `[<TASK-ID>] <summary>`.
- Shared files: the task that adds a project, dependency or job appends it to the solution and project lists, `Directory.Packages.props` and the CI job lists; lock files are regenerated after rebase, never hand-merged. `eng/packaging/packages.json` gains one entry per admitted package, and every merge to main publishes all packages at one version. The vcpkg baseline and overlay ports change only through a dependency-admission change; generated policy data is regenerated from its pinned source; the reason-code registry is append-only.
- The design-policy, reference-baseline, runtime-ownership and reconciliation checks (`eng/design_policy.py`, `eng/reference_baselines.py`, `eng/runtime_ownership.py`, `eng/reconciliation.py`) validate against exact pinned commits of the historical design corpus, which is now the read-only `ArcForges/ArcForges-Design-Parallel` (AD-0001). The recorded identities stay `ArcForges/ArcForges-Design`; the checks fetch those commits from `ArcForges/ArcForges-Design-Parallel` through the single mapping in `eng/historical_sources.py` (ArcForges/DesktopPlatform#180). Never work around a failing check by changing pins, exports or records. Change `eng/policy/design-source.json` and both generated exports only together, through a reviewed change; see [design policy](docs/design-policy.md). Its "Reviewed refresh" procedure (repinning from a newly merged Design PR) no longer applies, because the historical corpus is frozen; the current design is `ArcForges/ArcForges-Design`, which these checks do not read.
- Earlier `docs/` records named after work packages or substeps describe their original scope; they are evidence, not execution instructions. Where older documents prefix a command with `delivery.py build-slot run … --` or assign a step to an integration owner, that is historical: run the wrapped command directly, and leave pushing and merging to the coordinator.

## Validation policy (P2-017)

The historical [CI and local validation policy](https://github.com/ArcForges/ArcForges-Design-Parallel/blob/64173614f2c41543bfff8f6df8d5a9e41207eb0a/docs/assurance/ci-and-local-validation-policy.md) (ArcForges-Design-Parallel at `64173614`) stays in force for this repository, except its rule 9 (parallel delivery), which AD-0014 supersedes. Where it differs from the Plan execution policy, the Plan governs.

- Never add or execute macOS CI, native/runtime/package-consumer execution, GUI, browser, device, live-service or published-package installation tests in any CI trigger or nested build script.
- Keep necessary Windows/Linux compilation, packaging, targeted offline unit/static checks and non-duplicated security checks. Runtime diagnostics are explicit local opt-in only for affected behavior using existing tools. Do not silently build/test from commit or push hooks.
- Preserve locks, required signatures, licence/provenance and one identity/integrity check at each real trust handoff. Do not routinely download public artifacts or repeat archive/hash/consumer verification after publication. Narrow FFmpeg licence/configuration and Windows signature inspection remain legal admission checks.
- Do not reinstall vcpkg, SDKs or toolchains to expand validation. Do not create tags or republish solely for verification. Use the normal network and never change proxy or network configuration (no port 7890). Diagnose a failure before any rerun, retry transient failures with bounded backoff, inspect remote state before retrying a write, and report the exact operation when a failure persists. Linux opt-in checks run in the local WSL2 Debian distribution (P2-024); installs inside it are the user's, and there is no SSH.
- Record removed coverage honestly. Every pull request gets an independent review of its complete latest head; the coordinator merges only at the reviewed head after applicable checks succeed. Post-merge work stops after commit/job/publication status and a clean primary fast-forward; retain branches/worktrees.

## Dependency admission (WP02.05)

- Keep `eng/policy/dependency-policy.json` bound to the complete actual dependency inputs. A dependency or framework change requires a reviewed replacement receipt, closure/licence and maintenance review and every upgrade checklist item. Hash refresh alone is insufficient.
- Preserve existing source/native provenance and public/internal import gates. Stable closures cannot import prerelease dependencies; only recorded exact foundation candidates are permitted in development.
- Framework major upgrades require explicit runtime/AOT/trim and affected Android Kotlin/JVM/ART/R8 assessment under VG-08. Record conditional local coverage honestly without adding forbidden CI or provisioning tools.
