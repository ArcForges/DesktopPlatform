# Source and native package provenance

WP00.03 implements the [reviewed Design profile](https://github.com/ArcForges/ArcForges-Design/blob/0efe24e454c62450ee5739384031c24cc3242f97/docs/assurance/reference-coverage-and-provenance.md).
The audit subject is the current DesktopPlatform repository. The retired initialization
repository is not a producer or source input. The existing package identities, ABI and
runtime tests remain independent release gates.

## Before introducing material

Use `eng/provenance/template.json` to create a record under `eng/provenance/records`.
The ten fields identify the exact source repository/commit/paths, file-level licence,
attribution, target, disposition, independent oracle, NOTICE and lifetime. The
Licensing and Provenance Owner reviews the actual files and compatibility; a maintainer
may exercise that role through an authorized implementation review. Architecture decides
boundary questions. Register conflicts under `eng/provenance/conflicts`; unresolved
conflicts block acceptance. A word such as `approved` does not replace review evidence.

Record an explicit removal owner/trigger for temporary material. Generated material
records each generator and input separately. A tool's implementation is not automatically
included in its output. Preserve original legal text and subordinate licence overrides;
the source notice summary does not replace them. The five-row decision table is closed,
and source copyleft remains prohibited at the Apache interoperability boundary.

Bind each identified reused file in `eng/provenance/files.json`; every other tracked or
non-ignored new file has an explicit first-party classification. Review also detects
newly copied content within previously authored files. The initial records reconcile
existing material honestly; they do not assert that a record existed before its historic
copy. Used records are immutable, including retired records. Create a revision and
`supersedes` link for any changed input, intent or content, retain history and update the
active binding. CI compares with the event's trusted base, not a contributor-selected
empty baseline.

```text
python -m unittest discover -s tests/tooling -p "test_*.py" -v
python eng/check_provenance.py --owner DesktopPlatform
python eng/native_provenance.py
```

After a reviewed inventory change, `--write-notice` updates the deterministic source
summary. Checks fail for incomplete records, unknown classifications, prohibited
boundaries, changed bytes, escaped/linked paths, missing notices and altered history.
The Python checker and its original tests are reused under Apache-2.0 from Contracts
18a970c67c463f1971ca05773b80f31a1b1ba1a7; the local extension records the exact native
expressions already audited here. This does not import AGPL tooling into Contracts.

## Existing Windows native closure

The immutable `native-win-x64-r1.json` artifact profile records 36 components, all 174
recipe files, the exact four package dependency/feature closures and source identities.
Original archive SHA512 values are independently bound to Git archive commits; the
bzip2 release's 17 source files and all 57 AMF headers were also compared to their Git
objects. Fixed legal/recipe bytes are reviewed inputs; rebuilt native binary hashes
belong to the actual producer receipt and installed SPDX evidence.

The selected source/configuration matters. liblzma uses 0BSD, zstd selects BSD,
miniaudio selects MIT-0, and the RapidJSON examples with different terms are excluded.
Full referenced companions are preserved for IJG, Vulkan, OpenColorIO and OpenImageIO.
OpenImageIO's `function_view.h` retains an NCSA header despite its summary's LLVM
description; the actual header notice is included. ICC/SunSoft and pkgconf LicenseRef
identifiers name the exact recorded permissive texts. libtiff retains its original LZW
notice and the official UC Berkeley advertising-clause amendment. The complete LGPL
source archives preserve their own mixed original licences; this does not enable GPL
or nonfree FFmpeg compilation. The bin2c copyright companion contains the complete MIT
source file: it is admitted source material, not a legal-document exemption. Other
build-only tools are absent from the runtime DLL closure.

The separate compiler-runtime record binds the three currently distributed Microsoft
DLLs to approved hashes, publisher and actual file/product version **14.51.36247.0**.
The enclosing redist directory is **14.51.36231**, a different identity. Public source
repository/commit fields are explicitly null because Microsoft publishes these files
as signed binaries. The official Community redistribution grant/list and the narrow
AGPL System Libraries position are reviewed independently. Original formatted vendor
terms accompany the package. Vendor restrictions apply only to those DLLs; ArcForges
source retains its AGPL rights. A changed version, file, publisher or terms needs a
new reviewed record/profile.

`native.py stage` checks the source inventory, installed versions/recipes/library hashes,
approved compiler-runtime signatures and fixed versions, exact legal companions and
matching LGPL sources. It seals `provenance/native-closure.json` with the source commit,
selected records and every native producer member/hash. Both the independent packager
and candidate inspector verify that receipt and the profile, including every legal
and recipe member. Existing CMake/CTest, P/Invoke and isolated JIT/AOT/C17 consumers
remain mandatory. Main publication and exact public NuGet byte verification close a
release; policy checks alone do not prove product or commercial readiness.
