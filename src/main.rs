mod inspect;
mod pem;
mod render;

use clap::{CommandFactory, Parser, ValueEnum};
use render::{Diagnostic, Entry, Level, Options, Sort, TextMode};
use std::io::{IsTerminal, Read, Write};
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use time::OffsetDateTime;

const EXAMPLES: &str = "\
Examples:
  pbpaste | x509pretty                       annotate PEM text from the clipboard
  x509pretty a.pem b.pem                     annotate both files, print to stdout
  x509pretty -i a.pem -i b.pem -o all.pem    write both into one file
  x509pretty --inplace certs/*.pem           annotate in place, original kept as <file>.pretty
  x509pretty --sort fullchain.pem            order each chain leaf -> intermediate -> root
  x509pretty --reverse fullchain.pem         order each chain root -> intermediate -> leaf
  x509pretty --clean bundle.pem              remove duplicate blocks

Shell completion:
  bash  add to ~/.bashrc:
          eval \"$(x509pretty --completion bash)\"
  zsh   add to ~/.zshrc, after compinit:
          eval \"$(x509pretty --completion zsh)\"
        or install it once into a directory on $fpath (before compinit):
          x509pretty --completion zsh > ~/.zfunc/_x509pretty
          # ~/.zshrc: fpath=(~/.zfunc $fpath); autoload -Uz compinit && compinit
  Open a new shell afterwards.

Exit codes: 0 ok, 1 warnings, 2 errors.";

/// Annotate PEM files: every block stays byte-identical, certificates get a readable comment.
#[derive(Parser, Debug)]
#[command(version, after_help = EXAMPLES)]
struct Cli {
    /// Input files ("-" for stdin); stdin is read when none are given
    files: Vec<PathBuf>,

    /// Input file, can be repeated
    #[arg(short = 'i', long = "in", value_name = "FILE")]
    inputs: Vec<PathBuf>,

    /// Write all output to this file instead of stdout
    #[arg(short, long, value_name = "FILE", conflicts_with = "inplace")]
    out: Option<PathBuf>,

    /// Annotate each input file in place; the original is saved as <file>.pretty
    #[arg(long)]
    inplace: bool,

    /// Reorder linked certificates into chain order (leaf first)
    #[arg(short, long, conflicts_with = "reverse")]
    sort: bool,

    /// Reorder linked certificates into reverse chain order (root first)
    #[arg(short, long)]
    reverse: bool,

    /// Remove duplicate blocks (default: only mark them with a warning)
    #[arg(short, long)]
    clean: bool,

    /// Drop all text outside PEM blocks
    #[arg(long, conflicts_with = "keep_text")]
    clean_text: bool,

    /// Keep all text outside PEM blocks
    #[arg(long)]
    keep_text: bool,

    /// Never use colors (also honored: NO_COLOR)
    #[arg(long)]
    no_color: bool,

    /// Print a shell completion script and exit (setup: see end of --help)
    #[arg(long, value_name = "SHELL")]
    completion: Option<CompletionShell>,
}

#[derive(Clone, Copy, Debug, ValueEnum)]
enum CompletionShell {
    Bash,
    Zsh,
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    if let Some(shell) = cli.completion {
        let shell = match shell {
            CompletionShell::Bash => clap_complete::Shell::Bash,
            CompletionShell::Zsh => clap_complete::Shell::Zsh,
        };
        clap_complete::generate(shell, &mut Cli::command(), "x509pretty", &mut std::io::stdout());
        return ExitCode::SUCCESS;
    }

    let files: Vec<PathBuf> = cli.files.iter().chain(&cli.inputs).cloned().collect();
    let text = match (cli.clean_text, cli.keep_text) {
        (true, _) => TextMode::Clean,
        (_, true) => TextMode::Keep,
        _ => TextMode::Default,
    };
    let sort = match (cli.sort, cli.reverse) {
        (true, _) => Sort::LeafFirst,
        (_, true) => Sort::RootFirst,
        _ => Sort::Off,
    };
    let opts = Options {
        text,
        sort,
        dedupe: cli.clean,
        color: false,
    };
    let now = now();
    let color_allowed = !cli.no_color && std::env::var_os("NO_COLOR").is_none_or(|v| v.is_empty());

    let mut diagnostics = Vec::new();
    let result = if cli.inplace {
        run_inplace(&files, opts, now, &mut diagnostics)
    } else {
        let color = color_allowed && cli.out.is_none() && std::io::stdout().is_terminal();
        run_stream(
            &files,
            cli.out.as_deref(),
            Options { color, ..opts },
            now,
            &mut diagnostics,
        )
    };
    if let Err(e) = result {
        diagnostics.push(Diagnostic {
            level: Level::Error,
            message: e,
        });
    }

    let color = color_allowed && std::io::stderr().is_terminal();
    let mut stderr = std::io::stderr().lock();
    for d in &diagnostics {
        let (level, code) = match d.level {
            Level::Error => ("error", "31"),
            Level::Warning => ("warning", "33"),
            Level::Note => ("note", "0"),
        };
        let line = format!("{level}: {}", d.message);
        let _ = if color {
            writeln!(stderr, "\x1b[{code}m{line}\x1b[0m")
        } else {
            writeln!(stderr, "{line}")
        };
    }
    if diagnostics.iter().any(|d| d.level == Level::Error) {
        ExitCode::from(2)
    } else if diagnostics.iter().any(|d| d.level == Level::Warning) {
        ExitCode::from(1)
    } else {
        ExitCode::SUCCESS
    }
}

/// Reference time for validity checks. `X509PRETTY_NOW` (Unix seconds) pins it
/// so tests stay stable; it is intentionally undocumented.
fn now() -> OffsetDateTime {
    std::env::var("X509PRETTY_NOW")
        .ok()
        .and_then(|s| s.parse().ok())
        .and_then(|secs| OffsetDateTime::from_unix_timestamp(secs).ok())
        .unwrap_or_else(OffsetDateTime::now_utc)
}

fn read_input(path: &Path) -> Result<(String, Vec<u8>), String> {
    if path.as_os_str() == "-" {
        let mut buf = Vec::new();
        std::io::stdin()
            .read_to_end(&mut buf)
            .map_err(|e| format!("cannot read stdin: {e}"))?;
        return Ok(("<stdin>".into(), buf));
    }
    let data = std::fs::read(path).map_err(|e| format!("cannot read {}: {e}", path.display()))?;
    Ok((path.display().to_string(), data))
}

/// Reads every input before anything is written: one unreadable file aborts
/// the whole run, so no partial output or half-edited file set is left behind.
fn read_all(files: &[PathBuf]) -> Result<Vec<(String, Vec<u8>)>, String> {
    files.iter().map(|path| read_input(path)).collect()
}

fn entries(source: &str, data: &[u8], now: OffsetDateTime, diagnostics: &mut Vec<Diagnostic>) -> Vec<Entry> {
    let parsed = pem::parse(data);
    for e in parsed.errors {
        diagnostics.push(Diagnostic {
            level: Level::Error,
            message: format!("{source}: {e}"),
        });
    }
    parsed
        .units
        .into_iter()
        .map(|unit| Entry {
            info: unit
                .block
                .as_ref()
                .and_then(|b| inspect::inspect(b, now))
                .map(|mut info| {
                    inspect::add_name_from_text(&mut info, &unit.text);
                    info
                }),
            unit,
            source: source.to_string(),
            removed: Vec::new(),
        })
        .collect()
}

fn run_stream(
    files: &[PathBuf],
    out: Option<&Path>,
    opts: Options,
    now: OffsetDateTime,
    diagnostics: &mut Vec<Diagnostic>,
) -> Result<(), String> {
    let stdin = [PathBuf::from("-")];
    let files = if files.is_empty() { &stdin[..] } else { files };
    let mut all = Vec::new();
    for (source, data) in read_all(files)? {
        all.extend(entries(&source, &data, now, diagnostics));
    }
    let rendered = render::render(all, opts);
    diagnostics.extend(rendered.diagnostics);
    match out {
        Some(path) => std::fs::write(path, &rendered.output)
            .map_err(|e| format!("cannot write {}: {e}", path.display())),
        None => std::io::stdout()
            .write_all(&rendered.output)
            .map_err(|e| format!("cannot write stdout: {e}")),
    }
}

fn run_inplace(
    files: &[PathBuf],
    opts: Options,
    now: OffsetDateTime,
    diagnostics: &mut Vec<Diagnostic>,
) -> Result<(), String> {
    if files.is_empty() || files.iter().any(|f| f.as_os_str() == "-") {
        return Err("--inplace needs input files (stdin cannot be edited in place)".into());
    }
    for (path, (source, data)) in files.iter().zip(read_all(files)?) {
        let rendered = render::render(entries(&source, &data, now, diagnostics), opts);
        diagnostics.extend(rendered.diagnostics);
        if let Err(e) = replace_file(path, &data, &rendered.output) {
            diagnostics.push(Diagnostic {
                level: Level::Error,
                message: e,
            });
        }
    }
    Ok(())
}

/// Saves the original as `<file>.pretty`, then swaps in the new content via a
/// temporary file so an interrupted run never leaves a half-written file.
fn replace_file(path: &Path, original: &[u8], new: &[u8]) -> Result<(), String> {
    let with_suffix = |suffix: &str| {
        let mut name = path.as_os_str().to_owned();
        name.push(suffix);
        PathBuf::from(name)
    };
    let backup = with_suffix(".pretty");
    std::fs::write(&backup, original).map_err(|e| format!("cannot write {}: {e}", backup.display()))?;
    let tmp = with_suffix(".x509pretty.tmp");
    std::fs::write(&tmp, new).map_err(|e| format!("cannot write {}: {e}", tmp.display()))?;
    if let Ok(meta) = std::fs::metadata(path) {
        let _ = std::fs::set_permissions(&tmp, meta.permissions());
    }
    std::fs::rename(&tmp, path).map_err(|e| format!("cannot replace {}: {e}", path.display()))
}
