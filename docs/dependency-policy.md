# Dependency admission and deliberate releases

`eng/policy/dependency-policy.json` admits the exact current NuGet lock closure and
binds normalized source hashes of manifests, locks, projects and native/source
provenance records. The cached NuGet nuspec expressions and their hashes record
the reviewed metadata; no restore or public artifact download is part of this
offline policy check. Existing provenance, native licence/configuration, package
allowlist, Authenticode and source/recipe checks remain required independently.

Run `python eng/dependency_policy.py` and
`python -m unittest discover -s eng -p test_dependency_policy.py -v` for policy
changes. Dependency additions or upgrades must replace the reviewed input receipt,
review the complete affected closure and preserve required notices. Record the
owner, maintenance assessment and outcomes or explicit inapplicability for every
upgrade checklist item. Merely refreshing hashes is not an admission review.
Framework major upgrades additionally assess runtime posture, Native AOT/trim,
native ABI and affected Android Kotlin/JVM/ART/R8 implications under VG-08.
Relevant runtime diagnostics remain local and conditional on existing tools;
missing coverage is recorded honestly. No toolchain installation is implied.

Main publishes exact `1.0.0-ci.RUN.ATTEMPT` candidates to nuget.org through the
existing trusted publisher. Deliberate canonical `vX.Y.Z` tags may publish `X.Y.Z`
only when the tagged commit belongs to main history. The `nuget` environment
must permit main and `v*` tags; the portable guard rejects noncanonical tags,
other repositories/events and stable closures containing prerelease packages.
The same native, managed, packaging and source gates produce the candidate and
the publisher validates its identity before obtaining OIDC credentials. It never
rebuilds, skips colliding versions or overwrites published bytes. The stable path
is configured and tested with offline fixtures, not exercised by creating tags.

Generated business contracts belong to Contracts; this repository does not admit
public/internal schema implementations. The closed runtime ownership and licence
inventories remain the import boundary. Package access does not imply stability.

Review receipts under `eng/policy/dependency-reviews/` are append-only. The checker
compares the accepted Git tree and preserves every historical coordinate/integrity
binding: even a newly reviewed snapshot cannot change bytes under an existing
NuGet/npm version or Maven artifact coordinate. Add a successor receipt for an
actual reviewed upgrade; never edit or delete an earlier receipt.
