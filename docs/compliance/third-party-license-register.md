# DesktopPlatform dependency register

The authoritative managed versions and hashes are the central manifest and per-project package locks.
The present runtime scaffolds have no external runtime package references. Build/test-only dependencies
are Microsoft.CodeAnalysis.NetAnalyzers (MIT), Microsoft.NET.Test.Sdk and its platform dependencies (MIT),
xunit.v3 and xunit.runner.visualstudio (Apache-2.0), and coverlet.collector (MIT).
`ArcForges.Build.Policy` includes none of those dependencies in its NuGet closure.

Native upstream sources/versions are listed in [NOTICE](../../NOTICE.md), the classic vcpkg pin in
[deploy](../../deploy/README.md), and the OTIO overlay's source digest/patch. Preserve all upstream
licences, static dependencies and corresponding source in the admitted runtime packages.
`native.py stage` validates the installed upstream versions, recipe hashes and release library hashes,
then copies each dependency's copyright and SPDX record. The artifact records every DLL's PE imports,
exports and SHA256, and supplies the complete non-system DLL closure. Microsoft CRT files come from
the installed Visual Studio redistributable directory; its version and redistribution terms are
recorded in `sbom.json`. The actual DLL product/file version is recorded separately
from the enclosing redistributable-directory version. The reviewed vendor record
requires unchanged bytes, valid Microsoft Authenticode signatures and separate full
vendor terms. Windows system libraries remain OS prerequisites.

The [provenance profile](../provenance.md) binds every selected component to exact
source commits, release archives, feature selections, recipes and original notices.
Full referenced legal companions supplement the installed copyright files. Root or
port SPDX summaries do not override subordinate headers or licence alternatives.
The sealed native receipt and actual NuGet inspector reject changed or unclassified
legal, recipe, source and runtime members.

Media includes SHA512-verified FFmpeg/libusb source archives, selected build configuration and every
vcpkg recipe/patch in its closure. The actual FFmpeg binary must report the admitted LGPL configuration;
GPL/nonfree configurations fail staging. Package verification cross-checks these files against the
immutable native producer artifact before both consumer validation and public upload. See the
[native release evidence](../native-package-release.md) for what actually ran and remaining scope.

The old monorepo's planned product-source adoption register remains in Git at base commit
`99bfe7d695ed0d65a0d035af7d219fc9b86100f5`; those product imports are not DesktopPlatform imports.
No reference-repository code was copied by this extraction.
