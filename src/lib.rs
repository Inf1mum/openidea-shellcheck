//! ShellCheck for OpenIDEA: runs the `shellcheck` command line on a shell
//! script when it is saved (as a cancellable task; a newer save cancels the
//! running check), publishes the problems as diagnostics, and offers
//! ShellCheck's own suggestions as quick fixes where the JSON report carries
//! them.
//!
//! The check degrades gracefully: when the `shellcheck` binary cannot be run
//! (the permission is not granted, or the pinned binary is gone), the plugin
//! tells the user once per UTC day — never once per save — and the
//! *ShellCheck: Show Installation Notes* command always explains how to
//! install and re-select the binary.

use openidea_plugin::host::{self, storage};
use openidea_plugin::providers::{CodeAction, Document, Providers};
use openidea_plugin::{
    Diagnostic, Error, Event, Invocation, LogLevel, NotificationLevel, Plugin, Position, Project, Range, Severity,
    TextEdit, register_plugin,
};
use serde::Deserialize;
use std::collections::BTreeMap;

/// Storage key of the UTC day (`YYYYMMDD`) the user was last told that
/// `shellcheck` looks unavailable — the friendly notice repeats at most once
/// a day, no matter how many saves fail.
const UNAVAILABLE_NOTIFIED: &str = "unavailable-notified-day";

/// Extensions OpenIDEA's shellscript language checks (`languages/shellscript.toml`).
const SHELL_EXTENSIONS: [&str; 8] = ["sh", "bash", "zsh", "ksh", "ash", "dash", "bats", "command"];
/// File names the same language also treats as shell scripts (compared
/// case-insensitively, hence lowercase here).
const SHELL_FILENAMES: [&str; 15] = [
    ".bashrc",
    ".bash_profile",
    ".bash_login",
    ".bash_logout",
    ".bash_aliases",
    ".profile",
    ".zshrc",
    ".zshenv",
    ".zprofile",
    ".zlogin",
    ".zlogout",
    ".kshrc",
    "pkgbuild",
    "apkbuild",
    ".envrc",
];

/// Whether a saved path looks like a shell script (by name, the same files
/// OpenIDEA's shellscript language covers).
pub fn is_shell_script(path: &str) -> bool {
    let normalized = path.replace('\\', "/");
    let name = normalized.rsplit('/').next().unwrap_or(path);
    let lower = name.to_ascii_lowercase();
    if SHELL_FILENAMES.contains(&lower.as_str()) {
        return true;
    }
    match lower.rsplit_once('.') {
        Some((_, ext)) => SHELL_EXTENSIONS.contains(&ext),
        None => false,
    }
}

// ---------------------------------------------------------------------------
// Globs (the `exclude` setting)
// ---------------------------------------------------------------------------

/// `pattern` matches `path`: `*` runs within a path segment, `**` runs across
/// segments, `?` is one character of a segment. A pattern without `/` matches
/// the file name alone (`*.min.js`). Backslashes count as separators.
pub fn glob_match(pattern: &str, path: &str) -> bool {
    let path = path.replace('\\', "/");
    if !pattern.contains('/') && match_from(pattern.as_bytes(), file_name(&path).as_bytes()) {
        return true;
    }
    match_from(pattern.as_bytes(), path.as_bytes())
}

fn match_from(p: &[u8], t: &[u8]) -> bool {
    match p.first() {
        None => t.is_empty(),
        Some(b'*') => {
            let double = p.get(1) == Some(&b'*');
            let rest = if double { &p[2..] } else { &p[1..] };
            if match_from(rest, t) {
                return true;
            }
            for i in 0..t.len() {
                if !double && t[i] == b'/' {
                    break;
                }
                if match_from(rest, &t[i + 1..]) {
                    return true;
                }
            }
            false
        }
        Some(b'?') => t.first().is_some_and(|&c| c != b'/') && match_from(&p[1..], &t[1..]),
        Some(&c) => t.first() == Some(&c) && match_from(&p[1..], &t[1..]),
    }
}

/// Everything after the last separator (the whole text when there is none).
fn file_name(path: &str) -> &str {
    path.rsplit('/').next().unwrap_or(path)
}

/// The `exclude` globs, as the user set them (default: none).
fn excluded_globs() -> Vec<String> {
    host::setting("exclude")
        .and_then(|v| serde_json::from_str::<Vec<String>>(&v).ok())
        .unwrap_or_default()
}

fn is_excluded(path: &str, globs: &[String]) -> bool {
    globs.iter().any(|g| glob_match(g, path))
}

// ---------------------------------------------------------------------------
// Settings
// ---------------------------------------------------------------------------

/// The `minSeverity` setting: the least severe level still reported. ShellCheck
/// levels, most to least severe: error, warning, info, style. The default
/// (`style`) reports everything.
fn min_severity() -> Severity {
    match host::setting("minSeverity").and_then(|v| serde_json::from_str::<String>(&v).ok()).as_deref() {
        Some("error") => Severity::Error,
        Some("warning") => Severity::Warning,
        Some("info") => Severity::Info,
        _ => Severity::Hint,
    }
}

/// Severity rank, most to least severe: Error < Warning < Info < Hint.
fn rank(severity: Severity) -> u8 {
    match severity {
        Severity::Error => 0,
        Severity::Warning => 1,
        Severity::Info => 2,
        Severity::Hint => 3,
    }
}

/// Whether `severity` is at least as severe as `floor`.
pub fn at_least(severity: Severity, floor: Severity) -> bool {
    rank(severity) <= rank(floor)
}

/// The `extraArgs` setting: extra command-line arguments for shellcheck
/// (e.g. `--enable=all`), passed after `-f json1` and before the file.
fn extra_args() -> Vec<String> {
    host::setting("extraArgs")
        .and_then(|v| serde_json::from_str::<Vec<String>>(&v).ok())
        .unwrap_or_default()
}

// ---------------------------------------------------------------------------
// ShellCheck's JSON report (`shellcheck -f json1 <file>`)
// ---------------------------------------------------------------------------

/// One ShellCheck replacement: the half-open range of the file to overwrite
/// with `replacement` (0-based code-point line and column; a zero-width range
/// inserts).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Replacement {
    /// 0-based.
    pub line: u32,
    pub column: u32,
    /// 0-based (`endLine`/`endColumn` of the report, 1-based there).
    pub end_line: u32,
    pub end_column: u32,
    pub replacement: String,
}

/// One reported problem.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Problem {
    /// The file the problem is about, as the report spelled it.
    pub file: String,
    /// 0-based.
    pub line: u32,
    /// 0-based code-point column within the line.
    pub column: u32,
    /// 0-based end (`endLine`/`endColumn` of the report, 1-based there).
    pub end_line: u32,
    pub end_column: u32,
    pub severity: Severity,
    /// The check's code as shown in the editor (`SC2086`).
    pub code: String,
    pub message: String,
    /// ShellCheck's own suggested replacement, when the report carries one.
    pub fix: Option<Vec<Replacement>>,
}

#[derive(Deserialize)]
struct RawProblem {
    file: String,
    /// 1-based.
    line: u32,
    #[serde(default, rename = "endLine")]
    end_line: Option<u32>,
    /// 1-based.
    column: u32,
    #[serde(default, rename = "endColumn")]
    end_column: Option<u32>,
    level: String,
    code: i64,
    message: String,
    #[serde(default)]
    fix: Option<RawFix>,
}

#[derive(Deserialize)]
struct RawFix {
    #[serde(default)]
    replacements: Vec<RawReplacement>,
}

#[derive(Deserialize)]
struct RawReplacement {
    /// 1-based.
    line: u32,
    #[serde(default, rename = "endLine")]
    end_line: Option<u32>,
    /// 1-based.
    column: u32,
    #[serde(default, rename = "endColumn")]
    end_column: Option<u32>,
    replacement: String,
}

/// ShellCheck's level → the host's severity (`style` is a hint; an unknown
/// level is shown as info rather than dropped).
fn severity_of(level: &str) -> Severity {
    match level {
        "error" => Severity::Error,
        "warning" => Severity::Warning,
        "style" => Severity::Hint,
        _ => Severity::Info,
    }
}

/// The enclosing `comments` object of ShellCheck's `-f json1` report.
#[derive(Deserialize)]
struct RawReport {
    comments: Vec<RawProblem>,
}

/// Problems from ShellCheck's `-f json1` report (the `comments` array of
/// `{"comments": [ … ]}`), 1-based line and column numbers turned 0-based.
pub fn parse_report(json: &str) -> Result<Vec<Problem>, Error> {
    let raw: RawReport =
        serde_json::from_str(json).map_err(|e| Error::Failed(format!("shellcheck: unreadable report: {e}")))?;
    Ok(raw
        .comments
        .into_iter()
        .map(|p| Problem {
            file: p.file,
            line: p.line.saturating_sub(1),
            column: p.column.saturating_sub(1),
            end_line: p.end_line.unwrap_or(p.line).saturating_sub(1),
            end_column: p.end_column.unwrap_or(p.column).saturating_sub(1),
            severity: severity_of(&p.level),
            code: format!("SC{}", p.code),
            message: p.message,
            fix: p.fix.and_then(|f| {
                (!f.replacements.is_empty()).then(|| {
                    f.replacements
                        .into_iter()
                        .map(|r| Replacement {
                            line: r.line.saturating_sub(1),
                            column: r.column.saturating_sub(1),
                            end_line: r.end_line.unwrap_or(r.line).saturating_sub(1),
                            end_column: r.end_column.unwrap_or(r.column).saturating_sub(1),
                            replacement: r.replacement,
                        })
                        .collect()
                })
            }),
        })
        .collect())
}

/// Whether the report's `file` is the saved `path` (WASI plugins run on every
/// host, so interpret the host's path rather than cfg(windows)).
fn windows_path(path: &str) -> String {
    let path = path.replace('\\', "/");
    if let Some(rest) = path.strip_prefix("//?/UNC/") {
        format!("//{rest}")
    } else {
        path.strip_prefix("//?/").unwrap_or(&path).to_owned()
    }
}

fn report_matches_file(reported: &str, path: &str) -> bool {
    let drive = path.as_bytes().get(1) == Some(&b':') && path.as_bytes()[0].is_ascii_alphabetic();
    if drive || path.starts_with("//") || path.starts_with(r"\\") {
        let (reported, path) = (windows_path(reported), windows_path(path));
        reported == path || path.ends_with(&reported)
    } else {
        reported == path || path.ends_with(reported)
    }
}

// ---------------------------------------------------------------------------
// Positions: ShellCheck counts code points, the editor counts UTF-16 units
// ---------------------------------------------------------------------------

/// The UTF-16 column of a code-point `column` within `line`.
pub fn utf16_column(line: &str, column: u32) -> u32 {
    let mut units = 0u32;
    for (seen, c) in line.chars().enumerate() {
        if seen as u32 >= column {
            break;
        }
        units += c.len_utf16() as u32;
    }
    units
}

/// The editor position of a 0-based code-point (line, column) in `text`
/// (`None` when the line or the column is past the end — a report that no
/// longer fits the document must not move text).
pub fn position_of(text: &str, line: u32, column: u32) -> Option<Position> {
    let line_text = text.split('\n').nth(line as usize)?;
    (column as usize <= line_text.chars().count()).then(|| Position::new(line, utf16_column(line_text, column)))
}

/// The problem as an editor diagnostic: code-point columns become UTF-16
/// columns (clamped to the line), and an empty span widens to one character
/// so it still squiggles.
fn diagnostic(p: &Problem, text: &str) -> Diagnostic {
    let lines: Vec<&str> = text.split('\n').collect();
    let line_len = |l: usize| -> u32 { lines.get(l).map_or(0, |l| l.encode_utf16().count() as u32) };
    let start_line = p.line as usize;
    let start = Position::new(
        p.line,
        utf16_column(lines.get(start_line).copied().unwrap_or(""), p.column).min(line_len(start_line)),
    );
    let end_line = p.end_line as usize;
    let mut end = Position::new(
        p.end_line,
        utf16_column(lines.get(end_line).copied().unwrap_or(""), p.end_column).min(line_len(end_line)),
    );
    if end <= start {
        let len = line_len(start_line);
        end = if start.character < len { Position::new(p.line, start.character + 1) } else { Position::new(p.line, len) };
    }
    let range = Range::new(start, end.max(start));
    Diagnostic::new(range, p.severity, p.message.clone()).code(p.code.clone())
}

// ---------------------------------------------------------------------------
// Projects and days
// ---------------------------------------------------------------------------

/// The project containing `path`.
fn project_of(path: &str) -> Option<Project> {
    host::projects()
        .ok()?
        .into_iter()
        .filter(|p| p.root().is_ok_and(|r| is_under(path, &r)))
        .max_by_key(|p| p.root().map(|r| r.len()).unwrap_or(0))
}

/// Whether `path` is `root` or inside it (`/proj-x/a` is not inside `/proj`).
fn is_under(path: &str, root: &str) -> bool {
    path.strip_prefix(root)
        .is_some_and(|rest| rest.is_empty() || root.ends_with(['/', '\\']) || rest.starts_with(['/', '\\']))
}

/// Days since the epoch → proleptic Gregorian year, month, day
/// (Howard Hinnant's `civil_from_days`).
fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    (if m <= 2 { y + 1 } else { y }, m, d)
}

/// `secs` since the epoch as the UTC day `YYYYMMDD`.
pub fn day_key(secs: u64) -> String {
    let (y, m, d) = civil_from_days((secs / 86_400) as i64);
    format!("{y:04}{m:02}{d:02}")
}

fn today() -> String {
    day_key(std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0))
}

// ---------------------------------------------------------------------------
// The plugin
// ---------------------------------------------------------------------------

#[derive(Default)]
pub struct ShellCheck {
    /// Last results per file (for quick fixes; rebuilt by the next save).
    problems: BTreeMap<String, Vec<Problem>>,
}

/// The installation notes, also shown by the command of the same name.
const INSTALL_NOTES: &str = "ShellCheck is an external binary the IDE runs on saved shell scripts.\n\n\
Install it with your package manager:\n\
• macOS: brew install shellcheck\n\
• Debian/Ubuntu: sudo apt install shellcheck\n\
• Fedora: sudo dnf install ShellCheck\n\
• Windows: winget install shellcheck (or scoop install shellcheck)\n\n\
Then open Settings › Plugins › ShellCheck, clear and re-allow the `process:shellcheck` \
permission and select the binary when asked — the IDE runs exactly that binary. \
A custom binary location (for example a Homebrew path) is chosen in the same dialog.";

impl ShellCheck {
    /// Checks `path` and publishes the result. `Err(Cancelled)` when a newer
    /// save (or the user) cancelled it; other errors are explained to the
    /// user by the caller (`notify_unavailable`).
    fn check(&mut self, path: &str) -> Result<usize, Error> {
        let project = project_of(path).ok_or_else(|| Error::NotFound(format!("{path} is not in an open project")))?;
        let name = path.rsplit(['/', '\\']).next().unwrap_or(path);
        let task = host::begin_task(&format!("ShellCheck: {name}"), true);
        let mut args = vec!["-f".to_owned(), "json1".into()];
        args.extend(extra_args());
        args.push(path.to_owned());
        let out = project.run_process("shellcheck", &args, None)?;
        if task.is_cancelled() {
            return Err(Error::Cancelled);
        }
        // Exit status 0: no problems; 1: problems found. The JSON report is
        // the source of truth — anything shellcheck did not produce is a
        // failure (missing binary, unreadable file, broken output).
        let report = parse_report(&out.stdout)?;
        let problems: Vec<Problem> = report
            .into_iter()
            .filter(|p| report_matches_file(&p.file, path))
            .filter(|p| at_least(p.severity, min_severity()))
            .collect();
        let text = project.read_file(path).unwrap_or_default();
        let diagnostics: Vec<Diagnostic> = problems.iter().map(|p| diagnostic(p, &text)).collect();
        host::publish_diagnostics(path, &diagnostics)?;
        let n = problems.len();
        self.problems.insert(path.to_owned(), problems);
        Ok(n)
    }

    /// Tells the user, at most once per UTC day, that `shellcheck` could not
    /// be run and what to do about it — saves must not spam the notice.
    fn notify_unavailable(&self, error: &Error) {
        let today = today();
        if storage::get(UNAVAILABLE_NOTIFIED).ok().flatten().as_deref() == Some(today.as_str()) {
            host::log(LogLevel::Info, &format!("ShellCheck: the check failed again: {error}"));
            return;
        }
        let body = match error {
            Error::Denied(cap) => format!(
                "The `{cap}` permission is not granted, so files are not checked. Allow it in \
                 Settings › Plugins › ShellCheck and select the `shellcheck` binary when asked."
            ),
            other => format!(
                "`shellcheck` could not be run: {other}. Install it (run \"ShellCheck: Show Installation \
                 Notes\" for the commands), then clear and re-allow the `process:shellcheck` permission in \
                 Settings › Plugins › ShellCheck so the IDE can select the binary."
            ),
        };
        let _ = storage::set(UNAVAILABLE_NOTIFIED, &today);
        host::notify(NotificationLevel::Warning, "ShellCheck", &body);
    }
}

impl Providers for ShellCheck {
    fn code_actions(&mut self, doc: &Document, selection: Range) -> Vec<CodeAction> {
        let Some(problems) = self.problems.get(&doc.path) else { return Vec::new() };
        let mut out = Vec::new();
        for p in problems.iter().filter(|p| p.line >= selection.start.line && p.line <= selection.end.line) {
            // Only ShellCheck's own suggestions are offered — nothing is
            // synthesized textually, so a fix applies exactly what
            // shellcheck would have rewritten.
            let Some(fix) = &p.fix else { continue };
            let mut edits = Vec::new();
            let mut applicable = true;
            for r in fix {
                match (position_of(&doc.text, r.line, r.column), position_of(&doc.text, r.end_line, r.end_column)) {
                    (Some(start), Some(end)) if start <= end => {
                        edits.push(TextEdit { range: Range::new(start, end), text: r.replacement.clone() });
                    }
                    _ => {
                        applicable = false; // the document drifted off the report
                        break;
                    }
                }
            }
            if !applicable || edits.is_empty() {
                continue;
            }
            out.push(CodeAction {
                title: format!("ShellCheck: apply fix for {}", p.code),
                kind: Some("quickfix".into()),
                preferred: true,
                edits: vec![(doc.path.clone(), edits)],
                data: None,
            });
        }
        out
    }
}

impl Plugin for ShellCheck {
    fn run_command(&mut self, id: &str, ctx: &Invocation, _arg: Option<&str>) -> Result<Option<String>, Error> {
        match id {
            "check" => {
                let editor = ctx.editor().ok_or("no file is open")?;
                let path = editor.path();
                match self.check(&path) {
                    Ok(n) => Ok(Some(format!("{n} problems"))),
                    Err(e) => {
                        self.notify_unavailable(&e);
                        Err(e)
                    }
                }
            }
            "install-notes" => {
                host::notify(NotificationLevel::Info, "ShellCheck", INSTALL_NOTES);
                Ok(None)
            }
            _ => Err(Error::NotFound(format!("command {id}"))),
        }
    }

    fn handle_events(&mut self, events: &[Event], _ctx: &Invocation) {
        let mut saved: Vec<&str> = events
            .iter()
            .filter_map(|e| match e {
                Event::FileSaved(p) if is_shell_script(p) => Some(p.as_str()),
                _ => None,
            })
            .collect();
        saved.sort_unstable();
        saved.dedup();
        let globs = excluded_globs();
        for path in saved {
            if is_excluded(path, &globs) {
                continue;
            }
            match self.check(path) {
                Ok(_) => {}
                Err(Error::Cancelled) => return, // a newer save takes over
                Err(e) => {
                    self.notify_unavailable(&e);
                    return; // one notice per batch; the next save tries again
                }
            }
        }
    }
}

register_plugin!(ShellCheck, providers);

#[cfg(all(test, not(target_arch = "wasm32")))]
mod tests {
    use super::*;
    use openidea_plugin::ProcessOutput;
    use openidea_plugin::mock::MockHost;

    /// The script the wiring tests check: `echo $TARGET` on line 3 (0-based),
    /// with the variable at code points 42..49 of the file, and the stray
    /// `done` that ShellCheck reports SC1010 and SC1089 on.
    const SCRIPT: &str = "#!/usr/bin/env bash\nset -e\nTARGET=$1\necho $TARGET\necho done\ndone\n";

    /// A report in the shape ShellCheck 0.11.0 prints with `-f json1`, captured
    /// from the real binary in one run over two files (`deploy.sh` above plus
    /// `src/other.sh` containing `echo $(($x + 1))`; only the `file` paths are
    /// renamed to the mock project): SC2086 carries its fix as two zero-width
    /// quote insertions, the stray `done` produces SC1010 and SC1089 without
    /// one, and `other.sh`'s entries must not leak into deploy.sh's result.
    const REPORT: &str = r#"{"comments": [
    {
        "file": "/project/src/other.sh",
        "line": 1,
        "endLine": 1,
        "column": 1,
        "endColumn": 1,
        "level": "error",
        "code": 2148,
        "message": "Tips depend on target shell and yours is unknown. Add a shebang or a 'shell' directive.",
        "fix": null
    },
    {
        "file": "/project/src/other.sh",
        "line": 1,
        "endLine": 1,
        "column": 9,
        "endColumn": 11,
        "level": "warning",
        "code": 2154,
        "message": "x is referenced but not assigned.",
        "fix": null
    },
    {
        "file": "/project/src/other.sh",
        "line": 1,
        "endLine": 1,
        "column": 9,
        "endColumn": 11,
        "level": "style",
        "code": 2004,
        "message": "$/${} is unnecessary on arithmetic variables.",
        "fix": null
    },
    {
        "file": "/project/src/deploy.sh",
        "line": 4,
        "endLine": 4,
        "column": 6,
        "endColumn": 13,
        "level": "info",
        "code": 2086,
        "message": "Double quote to prevent globbing and word splitting.",
        "fix": {
            "replacements": [
                { "column": 6, "endColumn": 6, "endLine": 4, "insertionPoint": "afterEnd", "line": 4, "precedence": 7, "replacement": "\"" },
                { "column": 13, "endColumn": 13, "endLine": 4, "insertionPoint": "beforeStart", "line": 4, "precedence": 7, "replacement": "\"" }
            ]
        }
    },
    {
        "file": "/project/src/deploy.sh",
        "line": 5,
        "endLine": 5,
        "column": 6,
        "endColumn": 6,
        "level": "warning",
        "code": 1010,
        "message": "Use semicolon or linefeed before 'done' (or quote to make it literal).",
        "fix": null
    },
    {
        "file": "/project/src/deploy.sh",
        "line": 6,
        "endLine": 6,
        "column": 1,
        "endColumn": 1,
        "level": "error",
        "code": 1089,
        "message": "Parsing stopped here. Is this keyword correctly matched up?",
        "fix": null
    }
]}"#;

    /// The tab-indented script ShellCheck 0.11.0 reports SC2059 on, and the
    /// `-f json1` report the real binary prints for it (columns 9..16: with
    /// `json1` a tab counts as one character).
    const TABBED_SCRIPT: &str = "#!/bin/sh\n\tprintf \"$USER\"\n";
    const TABBED_REPORT: &str = r#"{"comments": [
    {
        "file": "/project/src/tabbed.sh",
        "line": 2,
        "endLine": 2,
        "column": 9,
        "endColumn": 16,
        "level": "info",
        "code": 2059,
        "message": "Don't use variables in the printf format string. Use printf '..%s..' \"$foo\".",
        "fix": null
    }
]}"#;

    fn report_host() -> MockHost {
        let host = MockHost::install()
            .with_capabilities(&["project.read", "events", "storage", "process:shellcheck"]);
        host.add_file("src/deploy.sh", SCRIPT);
        host.on_process("shellcheck", |args, _| {
            assert_eq!(&args[..3], ["-f", "json1", "/project/src/deploy.sh"]);
            Ok(ProcessOutput { status: Some(1), stdout: REPORT.into(), stderr: String::new() })
        });
        host
    }

    #[test]
    fn parses_shellcheck_json() {
        let r = parse_report(REPORT).expect("a report");
        assert_eq!(r.len(), 6);
        let quoted = &r[3];
        assert_eq!(quoted.file, "/project/src/deploy.sh");
        assert_eq!(quoted.code, "SC2086");
        assert_eq!(quoted.severity, Severity::Info);
        assert_eq!((quoted.line, quoted.column, quoted.end_line, quoted.end_column), (3, 5, 3, 12));
        assert_eq!(quoted.message, "Double quote to prevent globbing and word splitting.");
        assert_eq!(
            quoted.fix,
            Some(vec![
                Replacement { line: 3, column: 5, end_line: 3, end_column: 5, replacement: "\"".into() },
                Replacement { line: 3, column: 12, end_line: 3, end_column: 12, replacement: "\"".into() },
            ]),
            "the fix's two zero-width quote insertions, as ShellCheck reports them"
        );
        assert_eq!((r[4].severity, r[4].code.as_str()), (Severity::Warning, "SC1010"));
        assert_eq!(r[4].fix, None, "no fix, no replacement");
        assert_eq!((r[5].severity, r[5].code.as_str()), (Severity::Error, "SC1089"));
        assert_eq!((r[5].line, r[5].column, r[5].end_line, r[5].end_column), (5, 0, 5, 0));
        assert_eq!(r[2].severity, Severity::Hint, "style is a hint");
        assert!(r[2].fix.is_none());
        assert_eq!(r[0].severity, Severity::Error, "the other file's error maps like ours do");
    }

    #[test]
    fn a_report_without_fixes_or_ends_still_parses() {
        let r = parse_report(
            r#"{"comments": [{"file": "a.sh", "line": 2, "column": 3, "level": "warning", "code": 2086, "message": "m"}]}"#,
        )
        .expect("a report");
        assert_eq!(r.len(), 1);
        assert_eq!((r[0].line, r[0].column, r[0].end_line, r[0].end_column), (1, 2, 1, 2), "ends default to the start");
        assert_eq!(r[0].fix, None);
        assert!(parse_report("not json").is_err());
        assert!(parse_report("").is_err(), "no output is a failure, not a clean file");
        assert!(parse_report("[]").is_err(), "the legacy `-f json` array is not the json1 report");
        assert!(parse_report(r#"{"comments": []}"#).is_ok_and(|r| r.is_empty()), "an empty report is a clean file");
    }

    #[test]
    fn a_tab_indented_line_publishes_its_real_range() {
        let host = MockHost::install()
            .with_capabilities(&["project.read", "events", "storage", "process:shellcheck"]);
        host.add_file("src/tabbed.sh", TABBED_SCRIPT);
        host.on_process("shellcheck", |_, _| {
            Ok(ProcessOutput { status: Some(1), stdout: TABBED_REPORT.into(), stderr: String::new() })
        });
        let mut p = ShellCheck::default();
        p.handle_events(&[Event::FileSaved("/project/src/tabbed.sh".into())], &host.invocation());
        let d = &host.diagnostics()["/project/src/tabbed.sh"];
        assert_eq!(d.len(), 1);
        assert_eq!(d[0].code.as_deref(), Some("SC2059"));
        assert_eq!(
            d[0].range,
            Range::new(Position::new(1, 8), Position::new(1, 15)),
            "the tab counts as one character, not as a stop of 8"
        );
    }

    #[test]
    fn severity_filter_orders_style_below_info() {
        assert!(at_least(Severity::Error, Severity::Error));
        assert!(at_least(Severity::Warning, Severity::Warning));
        assert!(!at_least(Severity::Info, Severity::Warning));
        assert!(!at_least(Severity::Hint, Severity::Info), "style is the least severe");
        assert!(at_least(Severity::Hint, Severity::Hint));
    }

    #[test]
    fn shell_files_are_recognized_by_name() {
        for path in [
            "/p/deploy.sh", "C:\\p\\x.BASH", "/p/run.zsh", "/p/ci.bats", "/p/a.command", "/p/.bashrc",
            "/p/.zshenv", "/p/PKGBUILD", "/p/.envrc", "/p/APKBUILD",
        ] {
            assert!(is_shell_script(path), "{path}");
        }
        for path in ["/p/notes.txt", "/p/main.rs", "/p/makefile", "/p/.gitignore", "/p/sh"] {
            assert!(!is_shell_script(path), "{path}");
        }
    }

    #[test]
    fn exclude_globs_match_paths_and_file_names() {
        assert!(glob_match("**/vendor/**", "/p/vendor/x.sh"));
        assert!(!glob_match("**/vendor/**", "/p/src/x.sh"));
        assert!(glob_match("*.dev.sh", "deploy.dev.sh"), "a pattern without / matches the file name");
        assert!(glob_match("*.dev.sh", "src/deploy.dev.sh"));
        assert!(!glob_match("*.dev.sh", "src/deploy.sh"));
        assert!(glob_match("src/*.sh", "src/main.sh"));
        assert!(!glob_match("src/*.sh", "src/deep/main.sh"));
        assert!(glob_match("**/src/*.sh", "C:\\p\\src\\main.sh"), "backslashes are separators");
        assert!(glob_match("se?ret.sh", "secret.sh"));
    }

    #[test]
    fn code_point_positions_become_utf16() {
        assert_eq!(position_of("abc", 0, 1), Some(Position::new(0, 1)));
        assert_eq!(position_of("abc", 0, 3), Some(Position::new(0, 3)), "the end of the line resolves");
        assert_eq!(position_of("abc", 0, 99), None, "a column past the line does not resolve");
        assert_eq!(position_of("😀x", 0, 1), Some(Position::new(0, 2)), "one astral code point is two UTF-16 units");
        assert_eq!(position_of("😀x", 0, 2), Some(Position::new(0, 3)));
        let text = "ab\nc😀\n";
        assert_eq!(position_of(text, 1, 0), Some(Position::new(1, 0)));
        assert_eq!(position_of(text, 1, 2), Some(Position::new(1, 3)), "the astral character is two units");
        assert_eq!(position_of(text, 2, 0), Some(Position::new(2, 0)), "the empty last line");
        assert_eq!(position_of(text, 3, 0), None, "a line past the end does not resolve");
    }

    #[test]
    fn diagnostics_map_columns_and_widen_empty_spans() {
        let text = "😀x\nok\n"; // line 0: 2 code points, 3 UTF-16 units
        let p = Problem {
            file: "a.sh".into(),
            line: 0,
            column: 0,
            end_line: 0,
            end_column: 2, // code points: the whole "😀x" (3 UTF-16 units)
            severity: Severity::Warning,
            code: "SC1".into(),
            message: "m".into(),
            fix: None,
        };
        assert_eq!(diagnostic(&p, text).range, Range::new(Position::new(0, 0), Position::new(0, 3)));
        // An empty span widens to one character so it still squiggles.
        let empty = Problem { column: 1, end_column: 1, ..p.clone() };
        assert_eq!(diagnostic(&empty, text).range, Range::new(Position::new(0, 2), Position::new(0, 3)));
        // A column past the line end clamps to the line.
        let past = Problem { column: 99, end_column: 100, ..p.clone() };
        assert_eq!(diagnostic(&past, text).range, Range::new(Position::new(0, 3), Position::new(0, 3)));
        // A line past the end of the document stays at its start.
        let gone = Problem { line: 9, end_line: 9, column: 1, end_column: 3, ..p.clone() };
        assert_eq!(diagnostic(&gone, text).range, Range::new(Position::new(9, 0), Position::new(9, 0)));
    }

    #[test]
    fn report_paths_must_match_the_saved_file() {
        assert!(report_matches_file("/project/src/a.sh", "/project/src/a.sh"));
        assert!(report_matches_file("src/a.sh", "/project/src/a.sh"), "a relative report matches by suffix");
        assert!(!report_matches_file("/other/src/a.sh", "/project/src/a.sh"));
        assert!(report_matches_file(r"C:\project\src\a.sh", "C:/project/src/a.sh"));
        assert!(report_matches_file(r"\\?\C:\project\src\a.sh", "C:/project/src/a.sh"));
        assert!(!report_matches_file(r"C:\project-x\src\a.sh", "C:/project/src/a.sh"));
    }

    #[test]
    fn a_project_contains_only_its_own_paths() {
        assert!(is_under("/proj/A.sh", "/proj"));
        assert!(is_under("C:\\proj\\A.sh", "C:\\proj"));
        assert!(is_under("/A.sh", "/"));
        assert!(!is_under("/proj-x/A.sh", "/proj"));
    }

    #[test]
    fn checks_saved_shell_files_and_publishes_fixes() {
        let host = report_host();
        let mut p = ShellCheck::default();
        p.handle_events(
            &[Event::FileSaved("/project/src/deploy.sh".into()), Event::FileSaved("/project/notes.txt".into())],
            &host.invocation(),
        );
        assert_eq!(host.process_runs().len(), 1, "only shell scripts");
        assert_eq!(host.process_runs()[0].cwd.as_deref(), Some("/project"));
        let d = &host.diagnostics()["/project/src/deploy.sh"];
        assert_eq!(d.len(), 3, "info, warning and error; the other file's entries are not ours");
        assert_eq!(d[0].code.as_deref(), Some("SC2086"));
        assert_eq!(d[0].range, Range::new(Position::new(3, 5), Position::new(3, 12)));
        assert_eq!(d[1].severity, Severity::Warning);
        assert_eq!(
            d[1].range,
            Range::new(Position::new(4, 5), Position::new(4, 6)),
            "the zero-width span widens to one character so it still squiggles"
        );
        assert_eq!(d[2].severity, Severity::Error);
        assert!(host.tasks()[0].ended, "the cancellable task is done");

        // The quick fix comes from ShellCheck's own replacements (two
        // zero-width quote insertions around `$TARGET`), applied as two edits.
        let doc = Document {
            path: "/project/src/deploy.sh".into(),
            language: "shellscript".into(),
            version: 1,
            text: SCRIPT.into(),
        };
        let actions = p.code_actions(&doc, Range::new(Position::new(3, 0), Position::new(3, 5)));
        assert_eq!(actions.len(), 1);
        assert_eq!(actions[0].title, "ShellCheck: apply fix for SC2086");
        assert_eq!(actions[0].edits[0].0, "/project/src/deploy.sh");
        let edits = &actions[0].edits[0].1;
        assert_eq!(edits.len(), 2);
        assert_eq!(edits[0].range, Range::new(Position::new(3, 5), Position::new(3, 5)));
        assert_eq!(edits[0].text, "\"");
        assert_eq!(edits[1].range, Range::new(Position::new(3, 12), Position::new(3, 12)));
        assert_eq!(edits[1].text, "\"");
        // A selection on the error line (no fix) offers nothing.
        let actions = p.code_actions(&doc, Range::new(Position::new(2, 0), Position::new(2, 0)));
        assert!(actions.is_empty());
        // Fix offsets that no longer fit the drifted document are not offered.
        let drifted = Document { text: "echo $OTHER\n".into(), ..doc.clone() };
        assert!(p.code_actions(&drifted, Range::new(Position::new(0, 0), Position::new(3, 0))).is_empty());
    }

    #[test]
    fn a_clean_report_clears_old_problems() {
        let host = report_host();
        let mut p = ShellCheck::default();
        p.handle_events(&[Event::FileSaved("/project/src/deploy.sh".into())], &host.invocation());
        assert_eq!(host.diagnostics()["/project/src/deploy.sh"].len(), 3);
        host.on_process("shellcheck", |_, _| {
            Ok(ProcessOutput { status: Some(0), stdout: r#"{"comments": []}"#.into(), stderr: String::new() })
        });
        p.handle_events(&[Event::FileSaved("/project/src/deploy.sh".into())], &host.invocation());
        assert!(!host.diagnostics().contains_key("/project/src/deploy.sh"), "a clean run clears the squiggles");
        assert!(host.notifications().is_empty());
    }

    #[test]
    fn the_minimum_severity_setting_filters_the_report() {
        let host = report_host();
        host.set_setting("minSeverity", "\"warning\"");
        let mut p = ShellCheck::default();
        p.handle_events(&[Event::FileSaved("/project/src/deploy.sh".into())], &host.invocation());
        let d = &host.diagnostics()["/project/src/deploy.sh"];
        assert_eq!(d.len(), 2, "the info entry is dropped, error and warning stay");
        host.set_setting("minSeverity", "\"error\"");
        p.handle_events(&[Event::FileSaved("/project/src/deploy.sh".into())], &host.invocation());
        let d = &host.diagnostics()["/project/src/deploy.sh"];
        assert_eq!(d.len(), 1);
        assert_eq!(d[0].severity, Severity::Error);
        host.set_setting("minSeverity", "\"nonsense\"");
        p.handle_events(&[Event::FileSaved("/project/src/deploy.sh".into())], &host.invocation());
        assert_eq!(host.diagnostics()["/project/src/deploy.sh"].len(), 3, "an unknown value reports everything");
    }

    #[test]
    fn excluded_paths_are_not_checked() {
        let host = MockHost::install()
            .with_capabilities(&["project.read", "events", "storage", "process:shellcheck"]);
        host.add_file("src/deploy.sh", SCRIPT);
        host.add_file("vendor/dep/setup.sh", SCRIPT);
        host.on_process("shellcheck", |_, _| {
            Ok(ProcessOutput { status: Some(0), stdout: r#"{"comments": []}"#.into(), stderr: String::new() })
        });
        host.set_setting("exclude", r#"["**/vendor/**"]"#);
        let mut p = ShellCheck::default();
        p.handle_events(
            &[
                Event::FileSaved("/project/src/deploy.sh".into()),
                Event::FileSaved("/project/vendor/dep/setup.sh".into()),
            ],
            &host.invocation(),
        );
        assert_eq!(host.process_runs().len(), 1);
        assert_eq!(host.process_runs()[0].args.last().map(String::as_str), Some("/project/src/deploy.sh"));
    }

    #[test]
    fn non_shell_saves_run_nothing() {
        let host = MockHost::install()
            .with_capabilities(&["project.read", "events", "storage", "process:shellcheck"]);
        let mut p = ShellCheck::default();
        p.handle_events(
            &[
                Event::FileSaved("/project/notes.txt".into()),
                Event::FileSaved("/project/src/main.rs".into()),
                Event::FileSaved("/project/Makefile".into()),
            ],
            &host.invocation(),
        );
        assert!(host.process_runs().is_empty());
        assert!(host.diagnostics().is_empty());
        assert!(host.notifications().is_empty());
    }

    #[test]
    fn a_denied_permission_is_reported_once_a_day() {
        let host = MockHost::install().with_capabilities(&["project.read", "events", "storage"]);
        host.add_file("src/a.sh", SCRIPT);
        host.add_file("src/b.sh", SCRIPT);
        let mut p = ShellCheck::default();
        let ctx = host.invocation();
        p.handle_events(
            &[Event::FileSaved("/project/src/a.sh".into()), Event::FileSaved("/project/src/b.sh".into())],
            &ctx,
        );
        let notes = host.notifications();
        assert_eq!(notes.len(), 1, "failed saves, one notice");
        assert!(notes[0].body.contains("process:shellcheck"), "{}", notes[0].body);
        assert!(!host.diagnostics().contains_key("/project/src/a.sh"));
        let marker = host.storage()[UNAVAILABLE_NOTIFIED].clone();
        assert_eq!(marker.len(), 8, "the day marker is a YYYYMMDD day");
        // More failed saves the same day stay quiet.
        p.handle_events(&[Event::FileSaved("/project/src/b.sh".into())], &ctx);
        assert_eq!(host.notifications().len(), 1);
    }

    #[test]
    fn a_vanished_binary_is_a_friendly_notice_once_a_day() {
        let host = MockHost::install()
            .with_capabilities(&["project.read", "events", "storage", "process:shellcheck"]);
        host.add_file("src/a.sh", SCRIPT);
        // What the host answers when the approved binary is gone from PATH.
        host.on_process("shellcheck", |_, _| {
            Err(Error::Failed(
                "process:shellcheck: `shellcheck` was not found on PATH when this permission was allowed. \
                 Restarting doesn't approve a program installed later: once `shellcheck` is on PATH, \
                 clear process:shellcheck in Settings › Plugins and select it again"
                    .into(),
            ))
        });
        let mut p = ShellCheck::default();
        let ctx = host.invocation();
        p.handle_events(&[Event::FileSaved("/project/src/a.sh".into())], &ctx);
        let notes = host.notifications();
        assert_eq!(notes.len(), 1);
        assert!(notes[0].body.contains("Install it"), "{}", notes[0].body);
        assert!(notes[0].body.contains("Installation Notes"), "{}", notes[0].body);
        // Same day: no repeat.
        p.handle_events(&[Event::FileSaved("/project/src/a.sh".into())], &ctx);
        assert_eq!(host.notifications().len(), 1);
    }

    #[test]
    fn a_broken_report_is_a_failure_not_a_crash() {
        let host = MockHost::install()
            .with_capabilities(&["project.read", "events", "storage", "process:shellcheck"]);
        host.add_file("src/a.sh", SCRIPT);
        host.on_process("shellcheck", |_, _| {
            Ok(ProcessOutput {
                status: Some(2),
                stdout: String::new(),
                stderr: "a.sh: openBinaryFile: does not exist".into(),
            })
        });
        let mut p = ShellCheck::default();
        p.handle_events(&[Event::FileSaved("/project/src/a.sh".into())], &host.invocation());
        let notes = host.notifications();
        assert_eq!(notes.len(), 1, "the failure is explained once");
        assert!(notes[0].body.contains("could not be run"), "{}", notes[0].body);
        assert!(!host.diagnostics().contains_key("/project/src/a.sh"), "nothing stale is published");
    }

    #[test]
    fn extra_args_land_between_the_format_and_the_file() {
        let host = MockHost::install()
            .with_capabilities(&["project.read", "events", "storage", "process:shellcheck"]);
        host.add_file("src/a.sh", SCRIPT);
        host.on_process("shellcheck", |args, _| {
            assert_eq!(args, &["-f", "json1", "--enable=all", "-e", "SC1091", "/project/src/a.sh"]);
            Ok(ProcessOutput { status: Some(0), stdout: r#"{"comments": []}"#.into(), stderr: String::new() })
        });
        host.set_setting("extraArgs", r#"["--enable=all", "-e", "SC1091"]"#);
        ShellCheck::default().handle_events(&[Event::FileSaved("/project/src/a.sh".into())], &host.invocation());
        assert_eq!(host.process_runs().len(), 1);
    }

    #[test]
    fn the_check_command_counts_and_install_notes_explain() {
        let host = report_host();
        host.open_editor("/project/src/deploy.sh", "shellscript", SCRIPT, &[]);
        let mut p = ShellCheck::default();
        let ctx = host.invocation();
        assert_eq!(p.run_command("check", &ctx, None).unwrap().as_deref(), Some("3 problems"));
        assert_eq!(p.run_command("install-notes", &ctx, None).unwrap(), None);
        let notes = host.notifications();
        assert_eq!(notes.len(), 1);
        assert!(notes[0].body.contains("apt install shellcheck"), "{}", notes[0].body);
        assert!(notes[0].body.contains("process:shellcheck"));
        assert!(p.run_command("nope", &ctx, None).is_err());
        // Without an open editor the command says so.
        let bare = MockHost::install().with_capabilities(&["project.read", "events", "storage", "process:shellcheck"]);
        assert_eq!(
            ShellCheck::default().run_command("check", &bare.invocation(), None).unwrap_err(),
            Error::Failed("no file is open".into())
        );
    }

    #[test]
    fn the_install_notes_do_not_depend_on_storage() {
        let host = MockHost::install().with_capabilities(&["project.read", "events", "process:shellcheck"]);
        ShellCheck::default().run_command("install-notes", &host.invocation(), None).unwrap();
        assert_eq!(host.notifications().len(), 1, "no storage capability needed to read the notes");
    }
}
