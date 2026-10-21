//! Byte-preserving PEM tokenizer: splits input into text runs and PEM blocks
//! without touching a single byte of either.

use base64::Engine;

/// A PEM block exactly as it appeared in the input, BEGIN and END lines included.
#[derive(Debug, Clone)]
pub struct Block {
    pub label: String,
    pub raw: Vec<u8>,
}

impl Block {
    /// Line ending used by the block, so inserted comments match the file.
    pub fn newline(&self) -> &'static str {
        if self.raw.windows(2).any(|w| w == b"\r\n") {
            "\r\n"
        } else {
            "\n"
        }
    }

    /// Legacy OpenSSL encryption (`Proc-Type: 4,ENCRYPTED` headers inside the block).
    pub fn has_headers(&self) -> bool {
        self.body_lines().any(|l| l.contains(&b':'))
    }

    /// Decoded DER content; fails for blocks with headers or invalid base64.
    pub fn der(&self) -> Result<Vec<u8>, String> {
        if self.has_headers() {
            return Err("block has encryption headers".into());
        }
        base64::engine::general_purpose::STANDARD
            .decode(self.content())
            .map_err(|e| format!("invalid base64: {e}"))
    }

    /// Body without any whitespace: equal for the same object regardless of
    /// line wrapping or line endings.
    pub fn content(&self) -> Vec<u8> {
        self.body_lines()
            .flatten()
            .copied()
            .filter(|b| !b.is_ascii_whitespace())
            .collect()
    }

    fn body_lines(&self) -> impl Iterator<Item = &[u8]> {
        let lines: Vec<&[u8]> = self.raw.split_inclusive(|&b| b == b'\n').collect();
        let n = lines.len();
        lines.into_iter().skip(1).take(n.saturating_sub(2))
    }
}

/// Text (possibly empty) followed by an optional block. A file is a list of
/// units; only the last unit of a file can lack a block.
#[derive(Debug, Clone)]
pub struct Unit {
    pub text: Vec<u8>,
    pub block: Option<Block>,
}

pub struct Parsed {
    pub units: Vec<Unit>,
    pub errors: Vec<String>,
}

fn marker<'a>(line: &'a [u8], kind: &str) -> Option<&'a str> {
    let line = std::str::from_utf8(line).ok()?.trim();
    line.strip_prefix(&format!("-----{kind} "))?.strip_suffix("-----")
}

pub fn parse(input: &[u8]) -> Parsed {
    let lines: Vec<&[u8]> = input.split_inclusive(|&b| b == b'\n').collect();
    let mut units = Vec::new();
    let mut errors = Vec::new();
    let mut text = Vec::new();
    let mut i = 0;
    while i < lines.len() {
        let Some(label) = marker(lines[i], "BEGIN") else {
            text.extend_from_slice(lines[i]);
            i += 1;
            continue;
        };
        let end = (i + 1..lines.len()).find(|&j| marker(lines[j], "END") == Some(label));
        let Some(end) = end else {
            errors.push(format!("unterminated PEM block {label}"));
            for line in &lines[i..] {
                text.extend_from_slice(line);
            }
            break;
        };
        let raw = lines[i..=end].concat();
        units.push(Unit {
            text: std::mem::take(&mut text),
            block: Some(Block {
                label: label.to_string(),
                raw,
            }),
        });
        i = end + 1;
    }
    if !text.is_empty() {
        units.push(Unit { text, block: None });
    }
    Parsed { units, errors }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_is_byte_identical() {
        let input = b"hello\r\n-----BEGIN X-----\r\nQUJD\r\n-----END X-----\r\ntail";
        let parsed = parse(input);
        let mut out = Vec::new();
        for u in &parsed.units {
            out.extend_from_slice(&u.text);
            if let Some(b) = &u.block {
                out.extend_from_slice(&b.raw);
            }
        }
        assert_eq!(out, input);
        let block = parsed.units[0].block.as_ref().unwrap();
        assert_eq!(block.newline(), "\r\n");
        assert_eq!(block.der().unwrap(), b"ABC");
    }

    #[test]
    fn unterminated_block_is_kept_as_text() {
        let parsed = parse(b"-----BEGIN X-----\nQUJD\n");
        assert_eq!(parsed.errors.len(), 1);
        assert!(parsed.units[0].block.is_none());
    }
}
