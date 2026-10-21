//! Builds the annotated output: numbers blocks, links and optionally sorts
//! certificate chains, and decides which surrounding text survives.

use crate::inspect::{Info, Kind, Warning};
use crate::pem::{Block, Unit};
use std::collections::HashMap;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum TextMode {
    /// Text directly above a commented block is replaced, all other text kept.
    #[default]
    Default,
    /// All text outside PEM blocks is dropped.
    Clean,
    /// All text is kept; only comments from an earlier run are replaced.
    Keep,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Sort {
    /// Keep the input order.
    #[default]
    Off,
    /// Chains ordered leaf, intermediates, root (`--sort`).
    LeafFirst,
    /// Chains ordered root, intermediates, leaf (`--reverse`).
    RootFirst,
}

#[derive(Debug, Clone, Copy, Default)]
pub struct Options {
    pub text: TextMode,
    pub sort: Sort,
    /// Remove duplicate blocks instead of only marking them.
    pub dedupe: bool,
    pub color: bool,
}

/// A unit plus what is known about its block and where it came from.
pub struct Entry {
    pub unit: Unit,
    pub info: Option<Info>,
    pub source: String,
    /// Source and label of each duplicate of this block removed by `--clean`.
    pub removed: Vec<(String, String)>,
}

#[derive(Debug, PartialEq, Eq)]
pub enum Level {
    /// Informational, does not change the exit code.
    Note,
    Warning,
    Error,
}

pub struct Diagnostic {
    pub level: Level,
    pub message: String,
}

pub struct Rendered {
    pub output: Vec<u8>,
    pub diagnostics: Vec<Diagnostic>,
}

pub fn render(mut entries: Vec<Entry>, opts: Options) -> Rendered {
    // Duplicates go first so they cannot take part in chain linking.
    if opts.dedupe {
        entries = remove_duplicates(entries, opts.text);
    }
    if opts.sort != Sort::Off {
        let order = sort_order(&entries, &link_issuers(&entries), opts.sort == Sort::RootFirst);
        let mut slots: Vec<Option<Entry>> = entries.into_iter().map(Some).collect();
        entries = order.iter().map(|&i| slots[i].take().unwrap()).collect();
    }
    let issuers = link_issuers(&entries);

    // Output position (1-based) of every entry that holds a block.
    let mut positions = vec![0; entries.len()];
    let mut n = 0;
    for (i, e) in entries.iter().enumerate() {
        if e.unit.block.is_some() {
            n += 1;
            positions[i] = n;
        }
    }

    // Without --clean, duplicates are only marked: a warning pointing at the first occurrence.
    let duplicate_of = duplicates(&entries);

    let mut output = Vec::new();
    let mut diagnostics = Vec::new();
    for (i, entry) in entries.iter().enumerate() {
        for (source, label) in &entry.removed {
            diagnostics.push(Diagnostic {
                level: Level::Note,
                message: format!("{source}: removed duplicate of #{} ({label})", positions[i]),
            });
        }
        let mut info = entry.info.clone();
        if let (Some(first), Some(block)) = (duplicate_of[i], &entry.unit.block) {
            let text = format!("duplicate of #{}", positions[first]);
            match &mut info {
                Some(info) => info.warnings.push(Warning { text, severe: false }),
                // Blocks without a comment (e.g. encrypted keys) are reported on stderr only.
                None => diagnostics.push(Diagnostic {
                    level: Level::Warning,
                    message: format!(
                        "{}: block #{} ({}): {text}",
                        entry.source, positions[i], block.label
                    ),
                }),
            }
        }
        let comment = info.as_ref().zip(entry.unit.block.as_ref()).map(|(info, block)| {
            let issued_by = issuers[i].map(|j| positions[j]);
            for w in &info.warnings {
                diagnostics.push(Diagnostic {
                    level: Level::Warning,
                    message: format!(
                        "{}: {} #{}: {}",
                        entry.source,
                        kind_word(info.kind),
                        positions[i],
                        w.text
                    ),
                });
            }
            if let Some(err) = &info.error {
                diagnostics.push(Diagnostic {
                    level: Level::Error,
                    message: format!(
                        "{}: {} #{}: {err}",
                        entry.source,
                        kind_word(info.kind),
                        positions[i]
                    ),
                });
            }
            comment(info, positions[i], issued_by, block, opts.color)
        });

        let text = match opts.text {
            TextMode::Clean => &[][..],
            TextMode::Default if comment.is_some() => &[][..],
            _ => strip_own_comment(&entry.unit.text),
        };
        output.extend_from_slice(text);
        if let Some(c) = comment {
            output.extend_from_slice(c.as_bytes());
        }
        if let Some(block) = &entry.unit.block {
            output.extend_from_slice(&block.raw);
        }
    }
    Rendered { output, diagnostics }
}

fn kind_word(kind: Kind) -> String {
    kind.name().to_lowercase()
}

/// For every block that repeats an earlier one (same label and content, line
/// wrapping ignored), the index of the entry holding the first occurrence.
fn duplicates(entries: &[Entry]) -> Vec<Option<usize>> {
    let mut first_seen = HashMap::new();
    entries
        .iter()
        .enumerate()
        .map(|(i, e)| {
            let block = e.unit.block.as_ref()?;
            let first = *first_seen
                .entry((block.label.clone(), block.content()))
                .or_insert(i);
            (first != i).then_some(first)
        })
        .collect()
}

/// Drops repeated blocks for `--clean`, noting each removal on the first
/// occurrence. Text above a removed block only survives with `--keep-text`,
/// where it moves down to the next unit.
fn remove_duplicates(entries: Vec<Entry>, text: TextMode) -> Vec<Entry> {
    let duplicate_of = duplicates(&entries);
    let mut kept: Vec<Entry> = Vec::with_capacity(entries.len());
    let mut new_index = vec![0; entries.len()];
    let mut carry = Vec::new();
    for (i, mut entry) in entries.into_iter().enumerate() {
        if let (Some(first), Some(block)) = (duplicate_of[i], &entry.unit.block) {
            if text == TextMode::Keep {
                carry.extend_from_slice(strip_own_comment(&entry.unit.text));
            }
            kept[new_index[first]]
                .removed
                .push((entry.source, block.label.clone()));
            continue;
        }
        if !carry.is_empty() {
            carry.extend_from_slice(&entry.unit.text);
            entry.unit.text = std::mem::take(&mut carry);
        }
        new_index[i] = kept.len();
        kept.push(entry);
    }
    if !carry.is_empty() {
        kept.push(Entry {
            unit: Unit {
                text: carry,
                block: None,
            },
            info: None,
            source: String::new(),
            removed: Vec::new(),
        });
    }
    kept
}

/// For every certificate, the index of the entry holding its issuer.
fn link_issuers(entries: &[Entry]) -> Vec<Option<usize>> {
    entries
        .iter()
        .enumerate()
        .map(|(i, e)| {
            let info = cert_info(e)?;
            if info.is_self_signed() {
                return None;
            }
            entries.iter().enumerate().position(|(j, other)| {
                let Some(o) = cert_info(other) else { return false };
                j != i
                    && o.subject.is_some()
                    && o.subject == info.issuer
                    && (info.aki.is_none() || o.ski.is_none() || info.aki == o.ski)
            })
        })
        .collect()
}

fn cert_info(e: &Entry) -> Option<&Info> {
    e.info
        .as_ref()
        .filter(|i| i.kind == Kind::Certificate && i.error.is_none())
}

/// New entry order for `--sort`/`--reverse`: each chain is placed where its
/// first certificate stood, ordered leaf first (or root first when
/// `root_first`); all other entries keep their order.
fn sort_order(entries: &[Entry], issuers: &[Option<usize>], root_first: bool) -> Vec<usize> {
    let len = entries.len();
    // Union-find over issuer links gives the chains.
    let mut parent: Vec<usize> = (0..len).collect();
    fn root(p: &mut [usize], mut i: usize) -> usize {
        while p[i] != i {
            p[i] = p[p[i]];
            i = p[i];
        }
        i
    }
    for (i, issuer) in issuers.iter().enumerate() {
        if let Some(j) = *issuer {
            let (a, b) = (root(&mut parent, i), root(&mut parent, j));
            parent[a] = b;
        }
    }
    // Hops from a certificate up to the top of its chain; cycles are cut.
    let depth = |mut i: usize| {
        let mut d = 0;
        while let Some(j) = issuers[i] {
            d += 1;
            i = j;
            if d > len {
                break;
            }
        }
        d
    };

    let mut order = Vec::with_capacity(len);
    let mut placed = vec![false; len];
    for i in 0..len {
        if placed[i] {
            continue;
        }
        let r = root(&mut parent, i);
        let mut chain: Vec<usize> = (0..len).filter(|&j| root(&mut parent, j) == r).collect();
        if chain.len() > 1 {
            if root_first {
                chain.sort_by_key(|&j| (depth(j), j));
            } else {
                chain.sort_by_key(|&j| (std::cmp::Reverse(depth(j)), j));
            }
        }
        for j in chain {
            placed[j] = true;
            order.push(j);
        }
    }
    order
}

fn comment(info: &Info, pos: usize, issued_by: Option<usize>, block: &Block, color: bool) -> String {
    let nl = block.newline();
    let paint = |code: &str, line: String| {
        if color {
            format!("\x1b[{code}m{line}\x1b[0m{nl}")
        } else {
            format!("{line}{nl}")
        }
    };
    let mut header = format!("# {} #{pos}", info.kind.name());
    if let Some(m) = issued_by {
        header.push_str(&format!(" issued by #{m}"));
    }
    let mut out = paint("1", header);
    let field = |label: &str, value: &str| format!("#   {:<12}{value}", format!("{label}:"));
    for (label, value) in &info.fields {
        out.push_str(&format!("{}{nl}", field(label, value)));
    }
    for w in &info.warnings {
        out.push_str(&paint(
            if w.severe { "31" } else { "33" },
            field("WARNING", &w.text),
        ));
    }
    if let Some(err) = &info.error {
        out.push_str(&paint("31", field("ERROR", err)));
    }
    out
}

/// Removes a trailing comment written by an earlier x509pretty run. Only an
/// exact match of the format is removed; anything unclear stays.
fn strip_own_comment(text: &[u8]) -> &[u8] {
    let lines: Vec<&[u8]> = text.split_inclusive(|&b| b == b'\n').collect();
    let content = |l: &[u8]| -> Option<String> {
        let s = std::str::from_utf8(l).ok()?;
        Some(s.trim_end_matches(['\r', '\n']).to_string())
    };
    let mut start = lines.len();
    while start > 0 {
        let Some(line) = content(lines[start - 1]) else {
            break;
        };
        if is_detail_line(&line) {
            start -= 1;
        } else {
            break;
        }
    }
    if start == 0 {
        return text;
    }
    match content(lines[start - 1]) {
        Some(line) if is_header_line(&line) => {
            let keep: usize = lines[..start - 1].iter().map(|l| l.len()).sum();
            &text[..keep]
        }
        _ => text,
    }
}

fn is_header_line(line: &str) -> bool {
    let Some(rest) = line.strip_prefix("# ") else {
        return false;
    };
    let Some(rest) = ["Certificate #", "CSR #", "Private key #", "Public key #"]
        .iter()
        .find_map(|k| rest.strip_prefix(k))
    else {
        return false;
    };
    let (num, tail) = rest.split_at(rest.find(|c: char| !c.is_ascii_digit()).unwrap_or(rest.len()));
    !num.is_empty()
        && (tail.is_empty()
            || tail
                .strip_prefix(" issued by #")
                .is_some_and(|m| !m.is_empty() && m.chars().all(|c| c.is_ascii_digit())))
}

fn is_detail_line(line: &str) -> bool {
    let Some(rest) = line.strip_prefix("#   ") else {
        return false;
    };
    let Some((label, _)) = rest.split_once(':') else {
        return false;
    };
    [
        "Subject",
        "Issuer",
        "Serial",
        "Valid",
        "SANs",
        "Public key",
        "Signature",
        "SHA-256",
        "Algorithm",
        "Name",
        "WARNING",
        "ERROR",
    ]
    .contains(&label)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strips_only_exact_own_comments() {
        let own =
            b"keep me\n# Certificate #2 issued by #3\n#   Subject:    CN=x\n#   WARNING:    self-signed\n";
        assert_eq!(strip_own_comment(own), b"keep me\n");
        let foreign = b"# Certificate of my friend\n#   Subject:    CN=x\n";
        assert_eq!(strip_own_comment(foreign), foreign);
        let unknown_label = b"# Certificate #1\n#   Owner:      me\n";
        assert_eq!(strip_own_comment(unknown_label), unknown_label);
    }
}
