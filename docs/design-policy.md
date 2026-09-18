# WP00.01: Design policy exports and continuing integrity

Design remains the authored authority. [P2-016](https://github.com/ArcForges/ArcForges-Design/blob/1607374e81955f0a47f319cd6cc8ba1c6e254157/docs/decisions/phase-2-specification-decisions.md#rule-p2-016)
assigns this AGPL exporter, derived data and CI check to DesktopPlatform. Consumers
can read the checked-in JSON without a Design checkout. These files are policy data;
distribution through build packages belongs to WP02/WP05, and this change adds no
packable capability or product source dependency.

The reviewed pin is `1607374e81955f0a47f319cd6cc8ba1c6e254157`. Collection and
negative fixtures found missing scoped anchors, ambiguous and compound citations,
sentence-final citations, an omitted reverse dependency and stale mechanism totals.
Design PRs [15](https://github.com/ArcForges/ArcForges-Design/pull/15),
[16](https://github.com/ArcForges/ArcForges-Design/pull/16) and
[17](https://github.com/ArcForges/ArcForges-Design/pull/17) repair those at their owner.

The exported 135 term rows preserve 148 marked names, five explicit spaces and all
16 contextual forbidden-alias rows. The 429 invariant records retain both catalogue
and coverage locations, statements, architecture homes, mechanisms, planned
verification, owning packages and completion gates. Three retired rows keep their
absence tests. `verificationState: planned-only` does not close PG-11 or prove runtime
behavior. Contracts recognizes only the digest-bound forbidden-alias array at its
registered path; all remaining values and files stay subject to naming scans.

The checker reads 172 current Markdown documents while excluding deprecated input
bodies before reading. The current receipt indexes 7,601 document-scoped rules and
9,436 explicit rule citations, checks 11,411 local links and validates 165 exact
occurrence classifications covering 171 occurrences. It compares both forward
graphs, every active package header/dependency section and the exact reverse graph:
51 active nodes and 158 edges. It checks topological order, unique numbered sections,
mandatory package sections and the owned `.90` evidence row. Future/retired packages
have no active edges. The commerce substep ordering remains explicit.

## Source updates and review

For a proposed Design worktree, run the read-only preview before its documentation
PR merges. Its report includes commit/dirty state and cannot be used as an immutable
export result:

```text
python eng/design_policy.py --design-root /absolute/path/to/design-worktree --preview --report artifacts/evidence/design-preview.json
```

After reviewing and merging the Design change, update the exact commit and source
hashes in `eng/policy/design-source.json` on a DesktopPlatform worktree. Source hashes
use UTF-8 text with normalized LF newlines, matching Git's text content on Windows
and Linux. The corpus digest covers the sorted array of document path and text digest
pairs using compact JSON with sorted keys and unescaped UTF-8. Obtain these values
from the reviewed preview, then generate and independently verify the exports:

```text
python eng/design_policy.py --refresh
python eng/design_policy.py
```

A supplied `--design-root` must be the canonical repository, clean and at the exact
pin for immutable mode. The default obtains a fresh isolated public checkout at that
commit, with checkout hooks disabled. It runs no source programs and never advances
to a branch tip. A source change also requires Contracts to update its exact derived
declaration registration before the family scan accepts the new glossary identity.

## Verification and limits

The 15 test groups use independent small documents and real temporary Git repositories.
They remove, duplicate, reorder and edit export records; alter source statements,
spaces, owners and architecture homes; corrupt links, anchors and classification
counts/hashes; and break every graph representation, node ordering and evidence rows.
They exercise dirty/wrong-pin refusal, preview immutability, deprecated-body exclusion,
sentence punctuation, same-spelled rules in different documents and the CLI's real
failure exit/report. A current-corpus pass alone is insufficient.

Both CI platforms run the fixtures and fetch/verify the pinned real corpus before
package creation. Their full reports are retained as `design-policy-*` artifacts.
Existing native, managed, independent package-consumer and publication gates remain
required. Local immutable export verification passed; PR CI, merge and publication
remain pending until the corresponding run artifacts are reviewed. Policy checks
establish no provider, device, product behavior or commercial activation evidence.
