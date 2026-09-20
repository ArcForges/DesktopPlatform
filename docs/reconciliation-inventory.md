# Current repository reconciliation

The [WP01.00 Design profile](https://github.com/ArcForges/ArcForges-Design/blob/33bcddd9508ec60c0a2b0d7b53901ee7f50d0a70/docs/assurance/wp01-00-inventory-policy.md) governs `eng/policy/reconciliation/`.

- `source.json` binds the Design authority, WP00 candidate receipt and historical tree.
- `current.json` records nine clean primary commits, their worktrees, 75 build projects and exact published candidate identities. Worktree observations are historical local state, not instructions to read adjacent sources during a build.
- `historical.json` gives all 166 ede43db C# projects an owner, target, reason and disposition, including already absent projects. Absence never means the feature is complete.
- `directories.json` assigns current and planned directories to one repository and scheduled producer. Keep can mean required future content; no empty placeholder is authorized.
- `native.json` keeps historical native admission decisions separate from project counts.

Run `python -m unittest discover -s eng -p test_reconciliation.py -v`, then `python eng/reconciliation.py`. CI checks Windows and Linux before packing. The default run fetches eight immutable owner snapshots plus pinned Design, audits this DesktopPlatform checkout, and verifies all historical/current paths and recorded candidate identities. It does not build adjacent source or call a provider. A fresh read-only family audit accepts all nine `--repository Owner=absolute-root` arguments and an optional local `--design-root`; its report states actual commits, cleanliness and whether each snapshot is current.

The WP00 receipt supplies the already verified public NuGet/npm/Maven/native/desktop/Web/Android/Cloud/AI evidence. The checker validates its exact hash and source identities, not current registry availability or new runtime behavior. Changes to the inventory require review against actual Git trees and the producing step; do not edit a count to hide a missing entry. The existing runtime, licence and provenance checks remain required. Full contract assignment, shared content review, native surface work, test-family mapping and physical moves remain WP01.01 through WP01.05.
