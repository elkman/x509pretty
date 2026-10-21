# x509pretty

Annotate PEM files: every block stays byte-identical and in place, and each
certificate gets a human-readable comment above it. The output is still a valid
PEM file that every tool can read.

```text
# Certificate #2 issued by #3
#   Subject:    CN=www.example.test
#   Issuer:     O=Example Test, CN=Example Test Intermediate CA
#   Serial:     77:A3:73:D4:87:BB:5C:E9:7C:25:55:DB:F1:86:8F:C6:96:68:90:A8
#   Valid:      2026-10-21 07:31:45 UTC – 2027-01-19 07:31:45 UTC (90 days left)
#   SANs:       DNS:www.example.test, DNS:example.test
#   Public key: RSA 2048 bit
#   Signature:  ecdsa-with-SHA256
#   SHA-256:    14:4C:ED:EF:B8:AF:29:7B:48:18:CE:67:55:68:3C:01:DA:B6:B7:D5:C6:FF:D1:EA:99:2A:7D:D3:5C:69:95:8C
-----BEGIN CERTIFICATE-----
MIICaDCCAg6gAwIBAgIUd6Nz1Ie7XOl8JVXb8YaPxpZokKgwCgYIKoZIzj0EAwIw
…
-----END CERTIFICATE-----
```

- Works offline, never decrypts or changes private keys, no OpenSSL dependency.
- Certificates, CSRs, unencrypted private keys and public keys are annotated;
  encrypted keys, CRLs and unknown blocks are copied 1:1 without a comment.
- Problems are flagged in the comment and on stderr: expired, expiring in
  under 30 days, not yet valid, SHA-1/MD5 signatures, RSA keys under 2048 bit,
  self-signed certificates, duplicate blocks.

Requirements and design decisions: [docs/requirements.md](docs/requirements.md).

## Installation

Requires a Rust toolchain, Rust 1.88 or newer.

```sh
cargo install --path .
```

This puts `x509pretty` into `~/.cargo/bin`.

## Usage

```text
x509pretty [OPTIONS] [FILES]...
```

| Option | Effect |
| --- | --- |
| `FILES`, `-i`, `--in FILE` | Input files, in order; `-` or no file reads stdin |
| `-o`, `--out FILE` | Write all output into one file instead of stdout |
| `--inplace` | Annotate each input file in place; the original is saved as `<file>.pretty` |
| `-s`, `--sort` | Reorder each certificate chain leaf → intermediate → root |
| `-r`, `--reverse` | Reorder each certificate chain root → intermediate → leaf |
| `-c`, `--clean` | Remove duplicate blocks (default: only mark them) |
| `--clean-text` | Drop all text outside PEM blocks |
| `--keep-text` | Keep all text outside PEM blocks |
| `--no-color` | Never use colors (`NO_COLOR` is honored too) |
| `--completion bash\|zsh` | Print a shell completion script |

Examples:

```sh
pbpaste | x509pretty                     # annotate PEM text from the clipboard
x509pretty a.pem b.pem                   # both files, concatenated on stdout
x509pretty -i a.pem -i b.pem -o all.pem  # both files into one output file
x509pretty --inplace certs/*.pem         # annotate in place, keep <file>.pretty
x509pretty --sort --clean fullchain.pem  # chain order, duplicates removed
```

### Output rules

- **Order:** blocks keep their input order unless `--sort` or `--reverse` is
  given. A sorted chain is placed where its first certificate stood; all other
  blocks keep their order.
- **Numbering:** every block counts (`#1`, `#2`, …), including blocks without a
  comment. `issued by #N` links a certificate to its issuer in the same output.
- **Text outside blocks:** by default, text directly above a commented block is
  replaced by the comment and all other text is kept. `--clean-text` drops all
  of it, `--keep-text` keeps all of it.
- **Repeated runs:** comments written by an earlier run are recognized by
  their exact format and replaced, never stacked. Running the tool on its own
  output gives the same output.
- **Friendly names:** a `friendlyName` from OpenSSL's `Bag Attributes`
  (`openssl pkcs12 -nodes`) or from PKCS#8 key attributes is shown as `Name:`.
- **Duplicates:** blocks with the same type and content (line wrapping
  ignored) are marked `duplicate of #N`; with `--clean` they are removed and
  reported as a `note:` on stderr.
- **Line endings:** CRLF input gets CRLF comments.

### Colors

Colors are used only when writing to a terminal: comment headers bold,
warnings yellow, expired/not-yet-valid and errors red. Messages on stderr are
colored the same way when stderr is a terminal. `--no-color` or `NO_COLOR`
turns colors off.

### Exit codes

| Code | Meaning |
| --- | --- |
| 0 | OK (notes about removed duplicates do not count) |
| 1 | At least one warning |
| 2 | At least one error: unreadable input file, malformed block, unterminated PEM block, write failure |

Every warning and error is printed to stderr, e.g.
`warning: legacy.pem: certificate #1: SHA-1 signature`.
An unreadable input file aborts the run before anything is written.

## Shell completion

```sh
# bash, in ~/.bashrc
eval "$(x509pretty --completion bash)"

# zsh, in ~/.zshrc after compinit
eval "$(x509pretty --completion zsh)"

# zsh, alternatively install once into a directory on $fpath (before compinit)
x509pretty --completion zsh > ~/.zfunc/_x509pretty
```

`source <(…)` does not work with the bash 3.2 shipped with macOS; use `eval`.

## Development

```sh
cargo test                   # unit and integration tests
cargo clippy --all-targets
cargo fmt
```

| Path | Content |
| --- | --- |
| `src/pem.rs` | Byte-preserving PEM tokenizer |
| `src/inspect.rs` | Facts per block: certificate, CSR, private and public key |
| `src/render.rs` | Numbering, chain links, sorting, duplicates, text modes, comments |
| `src/main.rs` | Command line, input/output, exit codes |
| `tests/cli.rs` | Integration tests against the binary |
| `tests/fixtures/` | Test certificates and keys generated with OpenSSL 4.0.3 |

The fixtures were issued on 2026-10-21 07:31:45 UTC. The tests pin the clock to
that moment with the environment variable `X509PRETTY_NOW` (Unix seconds) so
that validity checks stay stable; it is not meant for normal use.

The fixtures contain test-only private keys. Never use them for anything else.
