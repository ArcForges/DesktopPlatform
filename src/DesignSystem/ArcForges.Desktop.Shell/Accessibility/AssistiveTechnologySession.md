# Assistive-technology session procedure (PLT.33)

**Status: blocked on a human assistive-technology session (deferred, section 0e), not proven.**

This is the runnable procedure for the dated manual assistive-technology verification that the
[WP-10.07](https://github.com/ArcForges/ArcForges-Design/blob/main/docs/planning/work-packages/10-design-system-and-desktop-shell.md#rule-wp-10.07)
completion gate requires for the shell surfaces declared in `ShellSurfaceCatalog`. The automated shell tests prove the
declarations, the focus contract (`FocusNavigator`), pseudo-localisation and the right-to-left mappings; only a person using a
real screen reader against a real UI adapter can prove that the platform accessibility tree speaks them. No such session has
been run. The user decided on 2026-10-10 that the human session is not run in the current delivery run and is not asked of
them (recorded in the fix8 planning repair note of the [PLT.33 delivery record](https://github.com/ArcForges/ArcForges-Design/blob/main/docs/planning/delivery/lanes/platform.md#task-plt-33),
which calls this decision section 0e). Until a dated result recorded with the form below has been reviewed, every check here is "not proven", and PLT.33 stays
`delivered`, not `complete`.

## 1. Preconditions

Do not start a session unless all of these hold. If one is missing, record the session as "not run" with the missing
precondition; never record a check as passed by inference from the automated tests.

1. **A real Avalonia UI adapter.** The desktop UI framework is Avalonia (P2-026 item 5) with its built-in controls only: V1
   admits no third-party control (P2-026, S9), so the earlier "admitted control set" (PLT.34) precondition is void. The adapter
   must bind every node of all six catalogue surfaces below to a control that appears in the platform accessibility tree (UI
   Automation on Windows, AT-SPI on Linux), resolve names through `ShellText`, and move focus exactly as `FocusNavigator` does.
   It must document its mapping from `AccessibleRole` to UI Automation control types and AT-SPI roles; that mapping is recorded
   with the session. **No such adapter exists today and its owner is an unassigned gap.**
2. **An exact build.** The full 40-character commit of the adapter host, the DesktopPlatform package version it restores, the
   runtime identifier, `Release` configuration, published the way it ships (Native AOT), and the SHA-256 of the main executable.
   A session against a debug or locally modified build is not evidence.
3. **Representative states.** The host can show each surface with the sample states used below: an attention count of 0, 1 and
   3; a palette query with no result, one result and several results; each of the four settings scopes as the effective scope;
   an error presentation with a support reference; and a shutdown prompt with running and unsaved work.
4. **A human tester on a local machine** of a supported runtime identifier. Hosted CI runs no GUI or assistive-technology test
   (P2-017); this session is an explicit local opt-in.

## 2. Platforms and assistive technology

The supported desktop runtime identifiers are those in `eng/build/desktop-rids.props`.

| Runtime identifier | Assistive technology | Session environment to record |
|---|---|---|
| `win-x64` | Narrator (built in) and NVDA | Windows edition, version and OS build (`winver`); NVDA version |
| `win-arm64` | Narrator (built in) and NVDA | As for `win-x64`, on a Windows ARM64 host, plus whether NVDA ran natively or emulated |
| `linux-x64` | Orca | Distribution and version, desktop (GNOME version, Wayland or X11), Orca and at-spi2-core versions |

macOS is out of scope (P2-023): it is never run and never claimed. A platform that was not run is recorded as "not run" with
the reason (for example, `win-arm64` needs a Windows ARM64 host).

Start and stop the screen readers with their standard keys: Narrator `Win+Ctrl+Enter`; NVDA `Ctrl+Alt+N` (stop with
`NVDA+Q`); Orca `Super+Alt+S`. Use NVDA's Speech Viewer to capture what was spoken; for Narrator and Orca, write down the
spoken text as heard.

### Settings for the visual checks

| Check | Windows | Linux (GNOME) |
|---|---|---|
| High contrast | Settings > Accessibility > Contrast themes: any theme | Settings > Accessibility > High Contrast on |
| Reduced motion | Settings > Accessibility > Visual effects > Animation effects off | Settings > Accessibility > Reduce Animation on |
| 200 percent text | Settings > Accessibility > Text size 200% | `gsettings set org.gnome.desktop.interface text-scaling-factor 2.0` |
| Pseudo-locale | the adapter's pseudo-localisation switch, which must call `ShellText.BeginPseudoLocalisation()`; record how it was enabled | same |
| Right-to-left | the adapter's interface culture set to `ar` (or `he`), so `FlowDirections.FromCulture` returns `RightToLeft`; record how it was set | same |

Restore each setting after its check.

## 3. Surface reference

Names are the neutral (English) resources in `Localization/ShellStrings.resx` at the sample arguments the catalogue declares;
live values replace the samples in a real host. "Tab" is the declared focus order within the surface; Tab and Shift+Tab wrap
inside the active surface. A list with roving items is one Tab stop: Tab lands on its active item (the first item, or the one
last moved to), and the arrow keys move between items. Every catalogued roving list is vertical (Up and Down), so right-to-left
does not change the arrow keys in this catalogue; a horizontal roving group would mirror Left and Right. In a right-to-left
layout the leading and trailing panels swap sides on screen (`FlowDirections.ToPhysical`) while the Tab order stays logical.

Known contract gaps, recorded as such and not as adapter failures: the catalogue has no menu role and does not include menu
contributions, and the node contract carries visual state cues but no assistive-technology state (toggled, selected, expanded,
disabled, busy). Record what is spoken for those states; do not count its absence against the adapter.

### 3.1 Workspace window (`shell.workspace`)

Not modal. Tab order: palette button, attention button, settings button, leading panel toggle, leading splitter, trailing
splitter, trailing panel toggle, bottom panel toggle, then wrap. No roving group (the toolbar is horizontal, but its buttons are
separate Tab stops). Enter or Space on the palette button opens the command palette (`shell.palette.open`). The status region
announces politely. The contract does not define splitter resize keys; record what the adapter does.

| Element id | Role | Name | Keyboard | Tab | Live | Command and cues |
|---|---|---|---|---|---|---|
| `shell.workspace` | Window | Workspace | None | - | Off | - |
| `shell.workspace.toolbar` | Toolbar | Workspace toolbar | None | - | Off | horizontal |
| `shell.workspace.palette-button` | Button | Open command palette | TabStop | 10 | Off | `shell.palette.open`; icon only; description "Search for a command and run it from the keyboard." |
| `shell.workspace.attention-button` | Button | Nothing needs your attention | TabStop | 20 | Off | `shell.attention.open`; icon only; name is plural over the count ("1 item needs your attention", "3 items need your attention"); cues colour, text and icon |
| `shell.workspace.settings-button` | Button | Open settings | TabStop | 30 | Off | `shell.settings.open`; icon only |
| `shell.workspace.panel-start` | Region | Leading side panel | None | - | Off | - |
| `shell.workspace.panel-start.toggle` | ToggleButton | Show or hide the leading side panel | TabStop | 40 | Off | `shell.panel.toggle`; icon only; cues icon and text |
| `shell.workspace.splitter-start` | Splitter | Resize the leading side panel | TabStop | 50 | Off | - |
| `shell.workspace.center` | Region | Workspace content | None | - | Off | product content is the product's own surface |
| `shell.workspace.splitter-end` | Splitter | Resize the trailing side panel | TabStop | 60 | Off | - |
| `shell.workspace.panel-end` | Region | Trailing side panel | None | - | Off | - |
| `shell.workspace.panel-end.toggle` | ToggleButton | Show or hide the trailing side panel | TabStop | 70 | Off | `shell.panel.toggle`; icon only; cues icon and text |
| `shell.workspace.panel-bottom` | Region | Bottom panel | None | - | Off | - |
| `shell.workspace.panel-bottom.toggle` | ToggleButton | Show or hide the bottom panel | TabStop | 80 | Off | `shell.panel.toggle`; icon only; cues icon and text |
| `shell.workspace.status` | Status | Status | None | - | Polite | - |

### 3.2 Command palette (`shell.command-palette`)

Modal dialog. On open, focus goes to the query and Tab cycles query, results, close inside the dialog only. The results list is
a vertical roving group: Up and Down move between results, Enter runs the selected result (`shell.palette.run-selected`).
Escape closes the palette (`shell.palette.close`) and returns focus to the element that opened it (normally
`shell.workspace.palette-button`). The result count announces politely as the query changes ("No commands match",
"1 command matches", "3 commands match").

| Element id | Role | Name | Keyboard | Tab | Live | Command and cues |
|---|---|---|---|---|---|---|
| `shell.command-palette` | Dialog | Command palette | None | - | Off | modal; Escape issues `shell.palette.close` |
| `shell.command-palette.query` | SearchBox | Search commands | TabStop | 1 | Off | description "Type to filter commands, then use the arrow keys to choose a result." |
| `shell.command-palette.results` | List | Command results | TabStop | 2 | Off | vertical roving group |
| `shell.command-palette.result` | ListItem | Example command | Roving | - | Off | `shell.palette.run-selected`; name is the command title; cues colour and shape |
| `shell.command-palette.result-count` | Status | No commands match | None | - | Polite | plural over the count |
| `shell.command-palette.close` | Button | Close command palette | TabStop | 3 | Off | `shell.palette.close` |

### 3.3 Scoped settings (`shell.settings`)

Not modal. Tab order: search, scope list (lands on the active scope), reset, then wrap. The scope list is a vertical roving
group. The effective-scope label is not a Tab stop; it must be read with the screen reader's review or reading commands and
must change when the effective scope changes.

| Element id | Role | Name | Keyboard | Tab | Live | Command and cues |
|---|---|---|---|---|---|---|
| `shell.settings` | Region | Settings | None | - | Off | - |
| `shell.settings.search` | SearchBox | Search settings | TabStop | 1 | Off | - |
| `shell.settings.scopes` | List | Setting scopes | TabStop | 2 | Off | vertical roving group |
| `shell.settings.scope.application` | ListItem | Application | Roving | - | Off | cues colour and text |
| `shell.settings.scope.workspace` | ListItem | Workspace | Roving | - | Off | cues colour and text |
| `shell.settings.scope.device` | ListItem | This device | Roving | - | Off | cues colour and text |
| `shell.settings.scope.instance` | ListItem | This window | Roving | - | Off | cues colour and text |
| `shell.settings.effective` | Label | This value comes from the device scope. | None | - | Off | the scope name is live |
| `shell.settings.reset` | Button | Use the inherited value | TabStop | 3 | Off | `shell.settings.reset` |

### 3.4 Attention centre (`shell.attention`)

Not modal. Tab order: item list (lands on the active item), open button, then wrap. The item list is a vertical roving group;
Enter on an item or the open button opens it (`shell.attention.open-item`). New notifications announce politely through the
notifications status without moving focus.

| Element id | Role | Name | Keyboard | Tab | Live | Command and cues |
|---|---|---|---|---|---|---|
| `shell.attention` | Region | Attention centre | None | - | Off | - |
| `shell.attention.live` | Status | Notifications | None | - | Polite | - |
| `shell.attention.items` | List | Items that need your attention | TabStop | 1 | Off | vertical roving group |
| `shell.attention.item` | ListItem | Example item | Roving | - | Off | `shell.attention.open-item`; name is the item title; cues colour, text and icon |
| `shell.attention.open-item` | Button | Open the selected item | TabStop | 2 | Off | `shell.attention.open-item` |

### 3.5 Error dialog (`shell.error-dialog`)

Modal alert dialog. On open the details announce assertively, focus goes to the copy button, and Tab cycles copy, try again,
close inside the dialog only. Escape closes it (`shell.error.close`) and returns focus to its origin. The four detail labels
must be readable with the review or reading commands.

| Element id | Role | Name | Keyboard | Tab | Live | Command and cues |
|---|---|---|---|---|---|---|
| `shell.error-dialog` | AlertDialog | Error | None | - | Off | modal; Escape issues `shell.error.close` |
| `shell.error-dialog.details` | Alert | Error details | None | - | Assertive | - |
| `shell.error-dialog.what` | Label | What happened | None | - | Off | - |
| `shell.error-dialog.retry` | Label | Whether to try again | None | - | Off | - |
| `shell.error-dialog.action` | Label | What you can do | None | - | Off | - |
| `shell.error-dialog.reference` | Label | Support reference | None | - | Off | - |
| `shell.error-dialog.copy` | Button | Copy the support reference | TabStop | 1 | Off | `shell.error.copy-reference`; icon only |
| `shell.error-dialog.try-again` | Button | Try again | TabStop | 2 | Off | `shell.error.retry` |
| `shell.error-dialog.close` | Button | Close | TabStop | 3 | Off | `shell.error.close` |

### 3.6 Shutdown prompt (`shell.shutdown-prompt`)

Modal alert dialog. On open the consequences announce assertively and focus goes to "Keep working"; Tab cycles keep working
and quit inside the prompt only. Escape keeps working (`shell.shutdown.keep-working`), never quits, and returns focus to its
origin.

| Element id | Role | Name | Keyboard | Tab | Live | Command and cues |
|---|---|---|---|---|---|---|
| `shell.shutdown-prompt` | AlertDialog | Quit | None | - | Off | modal; Escape issues `shell.shutdown.keep-working` |
| `shell.shutdown-prompt.consequences` | Alert | What quitting will do | None | - | Assertive | - |
| `shell.shutdown-prompt.keep-working` | Button | Keep working | TabStop | 1 | Off | `shell.shutdown.keep-working` |
| `shell.shutdown-prompt.quit` | Button | Quit | TabStop | 2 | Off | `shell.shutdown.quit` |

Nested modals close in reverse order: an error dialog opened over the command palette returns focus into the palette, and
closing the palette then returns focus to the workspace.

## 4. Checks

Run every check on every surface, once per platform and assistive technology, with the pointer untouched for checks 1 to 7.

| Id | Check | Pass when |
|---|---|---|
| AT-1 | Keyboard-only reach | Every element with a command is reached and activated with Tab, Shift+Tab, the arrow keys, Enter, Space and Escape only. |
| AT-2 | Focus order | Tab visits the Tab stops in the order of the table, Shift+Tab reverses it, both wrap inside the surface, and a roving list is one stop. |
| AT-3 | Visible focus | A focus indicator is visible on every stop and roving item and is not hidden by other content. |
| AT-4 | Announced names | The spoken name of every element equals the table name (or its live value), including icon-only buttons, and the two descriptions are spoken. |
| AT-5 | Roles and states | The spoken role matches the contract role through the adapter's documented mapping; spoken toggle and selection state is recorded (see the known contract gaps). |
| AT-6 | Live announcements | Polite regions speak their change without moving focus or interrupting speech; assertive alerts speak when their dialog opens. |
| AT-7 | Modal trap and restore | Tab never leaves a modal surface; Escape issues the dismiss command in the table and returns focus to the origin element. |
| AT-8 | High contrast | Every element, its text and the focus indicator stay visible, and colour state cues are still distinguishable by their text, icon or shape. |
| AT-9 | Reduced motion | No non-essential animation runs while the operating system setting is on. |
| AT-10 | 200 percent text | All text stays readable without clipping, overlap or lost information, and every element stays reachable. |
| AT-11 | Pseudo-locale | Every visible shell string is accented, expanded and wrapped in exactly one start and one end marker, nothing is clipped, and no unmarked shell text appears (unmarked text is a hard-coded literal). |
| AT-12 | Right-to-left | The leading panel is drawn on the right and the trailing panel on the left, text is right-aligned, Tab order stays logical, the vertical roving lists keep Up and Down, and modal restore is unchanged. |

## 5. Recording a dated session

1. Before starting, fill in the header of the form below. Use an ISO 8601 date and the time zone.
2. Work through section 4 surface by surface. For each cell write `pass`, `fail` or `not run`, and a note for every `fail` and
   every `not run` (what was spoken or seen, and the reason). Do not leave a cell empty and do not mark a check `pass` that was
   not performed in this session.
3. Keep the NVDA Speech Viewer text, or the written transcript for Narrator and Orca, and screenshots for AT-3 and AT-8 to AT-12.
   Use only the sample states from section 1; screenshots and transcripts must contain no personal data, account details,
   tokens or real user content.
4. A failure is reported as a defect against the adapter (or against the contract when the catalogue itself is wrong), not
   corrected in the result.
5. Attach the completed form, the transcripts and the screenshots verbatim to a reviewed pull request that amends the PLT.33
   delivery record in place. Completion is recorded only when both the adapter and a reviewed session exist; the record leaves
   `delivered` only through that review, and any check left `not run` stays listed as not proven.

### Result form

```text
PLT.33 assistive-technology session
Date and time zone:
Tester:
Runtime identifier:              (win-x64 | win-arm64 | linux-x64)
Operating system and build:
Desktop session (Linux):
Assistive technology and version:
Adapter host commit (40 hex):
DesktopPlatform package version:
Executable SHA-256:
Adapter role mapping (link or attachment):
Preconditions 1-4 met:           (yes | no: which)

Surface                      AT-1 AT-2 AT-3 AT-4 AT-5 AT-6 AT-7 AT-8 AT-9 AT-10 AT-11 AT-12
shell.workspace
shell.command-palette
shell.settings
shell.attention
shell.error-dialog
shell.shutdown-prompt

Notes (one line per fail or not run: surface, check, element id, observed, reason):
Transcript and screenshot attachments:
Result: (all pass | failures recorded | incomplete)
```
