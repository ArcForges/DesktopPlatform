# DesktopPlatform dependency register

The authoritative managed versions and hashes are the central manifest and per-project package locks.
The present runtime scaffolds have no external runtime package references. Build/test-only dependencies
are Microsoft.CodeAnalysis.NetAnalyzers (MIT), Microsoft.NET.Test.Sdk and its platform dependencies (MIT),
xunit.v3 and xunit.runner.visualstudio (Apache-2.0), and coverlet.collector (MIT).
`ArcForges.Build.Policy` includes none of those dependencies in its NuGet closure.

Native upstream sources/versions are listed in [NOTICE](../../NOTICE.md), the classic vcpkg pin in
[deploy](../../deploy/README.md), and the OTIO overlay's source digest/patch. Preserve all upstream
licences, static dependencies and corresponding source when a runtime capability is admitted.
The old monorepo's planned product-source adoption register remains in Git at base commit
`99bfe7d695ed0d65a0d035af7d219fc9b86100f5`; those product imports are not DesktopPlatform imports.
No reference-repository code was copied by this extraction.
