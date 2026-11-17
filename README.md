# ShellCheck for OpenIDEA

`inf1mum.shellcheck` — [ShellCheck](https://www.shellcheck.net) diagnostics
for [OpenIDEA](https://github.com/l0ng-ai/openidea): every time you save a
shell script, the IDE runs the `shellcheck` command line on it and its
findings show up in the editor and the Problems view, with ShellCheck's own
suggestions available as quick fixes.

## What it does

- **Check on save.** Saving a shell script (`.sh`, `.bash`, `.zsh`, `.ksh`,
  `.ash`, `.dash`, `.bats`, `.command`, and the usual rc/profile/PKGBUILD file
  names — the same files OpenIDEA's *shellscript* language covers) runs
  `shellcheck -f json` on it as a cancellable task; a newer save cancels the
  running check.
- **Diagnostics.** The JSON report becomes editor diagnostics with the `SC…`
  code on each: ShellCheck's `error`, `warning`, `info` and `style` levels map
  to error, warning, info and hint. A clean report clears the file's old
  squiggles. Columns are converted from ShellCheck's code points to the
  editor's UTF-16 columns (astral characters included).
- **Quick fixes.** Where the report carries one of ShellCheck's own fix
  suggestions (`fix.replacements` — e.g. SC2086's *double quote to prevent
  globbing*), the editor offers *ShellCheck: apply fix for SC2086*. Only
  ShellCheck's own suggestions are applied, verbatim, and only while their
  offsets still match the document — the plugin never invents edits of its
  own.
- **Commands** (search for "ShellCheck"):
  - *ShellCheck: Check Current File* — runs the check now (the file as saved
    on disk) and reports the number of findings;
  - *ShellCheck: Show Installation Notes* — how to install `shellcheck` and
    re-select the binary for the permission.

## Install

From the community marketplace (Settings › Plugins › Available › search
"ShellCheck"), or download `inf1mum.shellcheck-0.1.0.oiplugin` from
[Releases](https://github.com/Inf1mum/openidea-shellcheck/releases) and use
Settings › Plugins › *Install Plugin from Disk…*.

You also need the `shellcheck` binary on your machine (`brew install
shellcheck`, `sudo apt install shellcheck`, `winget install shellcheck`, …).
When you allow the plugin's `process:shellcheck` permission, the IDE finds it
on `PATH` and pins exactly that binary; the same dialog is where you can
select a custom binary location (for example a Homebrew path). If you install
shellcheck afterwards, clear and re-allow the permission in Settings ›
Plugins › ShellCheck so the IDE can select it again.

## Settings

Settings › Plugins › ShellCheck:

| Setting | Meaning |
| --- | --- |
| `minSeverity` | The least severe level that is still reported: `style` (default, everything), `info`, `warning` or `error`. |
| `exclude` | Globs of shell scripts that are never checked, e.g. `**/vendor/**`. `*` stays inside one path segment, `**` crosses segments, `?` is one character; a pattern without `/` matches the file name alone, a pattern with `/` is anchored to the path root. |
| `extraArgs` | Extra command-line arguments for `shellcheck`, passed before the file — e.g. `--enable=all` or `-e SC1090,SC1091`. |

(There is deliberately no "path override" setting: the IDE pins the binary at
permission time, and running any other program would need its own permission.
The re-allow dialog above is the supported way to point the plugin at a
different binary.)

## Capabilities and why

The manifest requires `project.read`, `events`, `storage` and
`process:shellcheck`. ShellCheck asks for nothing else — in particular no
`network:*`, no `editor.write`, no `events.input`.

| Capability | Risk | Why ShellCheck needs it |
| --- | --- | --- |
| `process:shellcheck` | **High** — the IDE describes it as "equivalent to running arbitrary code on this machine" | Runs the external `shellcheck` binary on saved files; that is the whole plugin. The binary is pinned when you allow the permission. |
| `project.read` | Low | Finds the open project a saved file belongs to (the check runs in the project root), reads the file back to map the report onto editor ranges, and publishing diagnostics requires it. |
| `events` | Low | Subscribes to `file-saved` — the trigger of every check. |
| `storage` | Low | One key: the UTC day the user was last told that `shellcheck` looks unavailable, so failed saves remind at most once a day instead of on every save. |

## Honest limits

- **Saved files only.** The check runs the binary on the file as saved on
  disk; unsaved buffer contents are not checked (the host's diagnostics
  provider interface for unsaved text is not used).
- **Quick fixes only where ShellCheck has one.** Not every finding carries a
  `fix` in the JSON report; those show as diagnostics without a code action.
  Fixes apply ShellCheck's suggestion verbatim and are dropped when the
  document has drifted off the reported offsets (save again to refresh).
- **Style is a hint.** ShellCheck's `style` level maps to the host's hint
  severity; how prominently hints show depends on the IDE.
- **Windows paths.** The plugin matches the report's `file` field against the
  saved path with the host's path shapes in mind (drive letters, UNC, `\\?\`
  prefixes); a relative report matches by suffix.
- **Notification discipline.** When `shellcheck` cannot run (permission not
  granted, or the pinned binary is gone), each save retries silently and the
  friendly notice appears at most once per UTC day; *Show Installation
  Notes* always explains the fix.

## Development

```sh
cargo test                 # logic, against the SDK's mock host
openidea-plugin build      # → dist/plugin.wasm + the install-time checks
```

The plugin depends on the
[`openidea-plugin` SDK](https://github.com/l0ng-ai/openidea/tree/main/sdk/rust/openidea-plugin)
(pinned to tag `v0.1.46`) and builds for `wasm32-wasip2`. The unit tests cover
the JSON report parsing (real ShellCheck output shapes, missing fix/end
fields), severity mapping and the minimum-severity filter, exclude globs,
code-point → UTF-16 column and offset mapping, diagnostic range clamping,
report-path matching (including Windows shapes), the check-on-save wiring,
quick fixes, the extra-args plumbing, the clean-report clearing, and the
graceful degradation paths (permission denied, vanished binary, broken
report) with the once-a-day notice.

## License

[Apache-2.0](LICENSE).
