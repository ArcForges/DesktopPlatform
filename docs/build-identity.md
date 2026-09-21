# Independent versions and build identity

WP02.04 follows the accepted [nine-owner profile](https://github.com/ArcForges/ArcForges-Design/blob/main/docs/assurance/wp02-04-version-identity-profile.md).
`eng/version-sources.json` declares all nine axes. NativeAbiVersion reads the actual C header constants;
PackageVersion reads committed NuGet locks and the audited native SBOM dependency closure. AppVersion
and business contracts are not applicable to these library foundations. Future capability descriptors,
portable formats, migrations, product policy and extensions remain explicitly not produced, with their
future producer named. Neither a package release nor the ABI probes imply those features exist.

Each NuGet contains `build-identity.json` (`arcforges.build-identity.v1`): artifact coordinates, all nine
axes with source digests, and source/run identity. Verification independently resolves the axes from
the verifier checkout and sealed native SBOMs, compares the original candidate build record, and rejects
modified inner reports even after an archive's outer checksum is updated. Publication checks the real
GitHub source/run; consumer reruns may read the original producer attempt and never relabel its bytes.

Build.Policy stamps every owned managed assembly, including tools. Packing passes the allocated version
to both Version and PackageVersion. The ArchitectureTests read actual PE metadata for every solution
assembly, comparing source and timestamp against Git and run identity against the CI execution.
CMake and the independent Visual Studio native path generate the same build-info suffix before compiling
owned code. The existing native exports, ABI1.0, exact buffer sizing and error behavior remain unchanged.
No third-party library is rewritten or rebuilt to add ArcForges identity.

The source timestamp is commit time, not wall-clock compilation time. Native and managed jobs have
their own preserved build/run records; a later consumer retry does not manufacture a new identity.
Optional local ordinary/Native AOT consumers can retrieve managed assembly and native export
metadata, and the local C17 diagnostic can inspect the suffix. CI does not execute these consumers
or load owned DLLs during staging. The FFmpeg legal configuration probe remains a narrow licence check.

Run `python -m unittest discover -s eng -p test_build_identity.py -v` for synthetic nine-source mutation,
invalid/absent axes, duplicate subjects, aliases and real Git identity rejection tests. These mechanism
fixtures do not assert production implementations for absent axes. Run the README build/architecture
suite and the packaging guide for actual binary and package evidence. Build-local results and CI/public
package evidence remain distinct.

Current validation follows [AGENTS.md](../AGENTS.md) and P2-017: no macOS/runtime-consumer CI or
post-publication download/hash cycle. Historical WP02.04 runtime receipts do not require repetition.
