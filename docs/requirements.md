# x509pretty – Requirements

As of 2026-10-21. Working copy: [Claude doc](https://claude.ai/artifact/65pWUBmnbR95K652N5UL16);
this file is the version kept with the code.

## Purpose & Goals

x509pretty is a command-line tool written in Rust that turns a PEM input into an
annotated copy: every block stays byte-identical and in place, and each
certificate gets a human-readable comment above it.

- **Problem:** PEM bundles are opaque; inspecting them with `openssl` needs a
  separate command per block and splitting the file first.
- **Goal 1:** One command annotates every certificate in one or more PEM files,
  keeping all blocks and their order unchanged.
- **Goal 2:** The output stays a valid PEM file that every tool can still read.
- **Goal 3:** The essentials of a certificate (subject, issuer, validity, SANs,
  key) and its problems are readable at a glance.
- **Goal 4:** Private keys and other blocks are passed through untouched: never
  decrypted or altered; readable ones may get a comment.

## Users & Use Cases

| ID | Role | User story |
| --- | --- | --- |
| US-01 | Administrator | As an admin, I want every certificate in a `fullchain.pem` annotated with its expiry date, so I can plan renewals. |
| US-02 | Administrator | As an admin, I want to annotate a bundle that contains private keys without the keys being touched, so the file stays deployable. |
| US-03 | Developer | As a developer, I want to pipe PEM text through the tool (`pbpaste \| x509pretty`), so I can inspect it without saving a file. |
| US-04 | Developer | As a developer, I want to check SANs and key usage before deploying a certificate. |
| US-05 | Pentester | As a pentester, I want weak algorithms and short keys flagged, so findings are obvious. |
| US-06 | Automation | As a script, I want a non-zero exit code and a message on stderr when the input contains an expired certificate. |
| US-07 | Administrator | As an admin, I want to annotate many PEM files in place with a backup of each, so I can document a whole certificate directory. |

## Functional Requirements

Prioritized with MoSCoW. Status: all Must, Should and Could items are
implemented in 0.1.0; Won't items are not.

| ID | Requirement | Priority | Acceptance criterion | Ref |
| --- | --- | --- | --- | --- |
| FR-01 | Read stdin and write stdout when no input file is given | Must | `cat bundle.pem \| x509pretty` writes the annotated copy to stdout | US-03 |
| FR-02 | Accept one or more input files as positional arguments or with `-i`/`--in` (repeatable); an unreadable file aborts the run before any output is written (exit 2) | Must | `x509pretty a.pem b.pem` processes both, in argument order | US-01 |
| FR-03 | Write to stdout, or to one file with `-o`/`--out`; several inputs are concatenated in argument order | Must | `x509pretty a.pem b.pem -o all.pem` writes the blocks of `a.pem`, then `b.pem` | US-01 |
| FR-04 | `--inplace` (long form only): per input file, save the original as `<file>.pretty` and write the annotated copy to `<file>` | Must | After `x509pretty --inplace a.pem`, `a.pem.pretty` equals the old `a.pem` | US-07 |
| FR-05 | Keep the input order unless `--sort`/`--reverse` is given; copy every PEM block byte-identical | Must | Output without its comment lines contains exactly the input's PEM blocks | US-02 |
| FR-06 | Put a comment above each `CERTIFICATE` block: position, friendly name (from OpenSSL Bag Attributes, if present), subject, issuer, serial, validity, days remaining, SANs, public key, signature algorithm, SHA-256 fingerprint | Must | Comment lines start with `# ` | US-01, US-04 |
| FR-07 | Echo all other blocks 1:1 (private keys encrypted or not, public keys, CSRs, CRLs, unknown types); never decrypt or alter them | Must | An encrypted key appears byte-identical in the output; no passphrase prompt | US-02 |
| FR-08 | Text outside PEM blocks: by default, text directly above a commented block is replaced by its comment and all other text is kept; `--clean-text` drops all of it; `--keep-text` keeps all of it. Comments from an earlier x509pretty run are recognized only by their exact format and replaced, never stacked; anything unclear is kept | Should | Running the tool on its own output gives the same output, in every mode | – |
| FR-09 | Add warnings to the comment: expired, not yet valid, expires in < 30 days, SHA-1/MD5 signature, RSA < 2048 bit, self-signed | Should | An expired certificate shows `WARNING: expired … days ago` | US-05 |
| FR-10 | Use color only when writing to a terminal; off with `--no-color` or `NO_COLOR` | Should | Output to a file or pipe contains no ANSI codes | US-05 |
| FR-11 | Exit code 0 = ok, 1 = warnings, 2 = errors; print each warning and error to stderr (yellow and red on a terminal) | Must | Expired certificate → exit 1 and `warning: …` on stderr | US-06 |
| FR-12 | Echo a malformed certificate block 1:1 with an error comment and continue | Should | Broken block #2 is kept, #1 and #3 are annotated, exit 2 | – |
| FR-13 | Shell completion with `--completion bash\|zsh` | Should | `x509pretty --completion zsh` prints a working completion script | – |
| FR-14 | Name the issuing certificate in the comment header; the Issuer line always shows the full name | Could | Header reads `# Certificate #2 issued by #3` | US-01 |
| FR-15 | JSON output (`--json`) | Won't | – | US-06 |
| FR-16 | Detailed list of all extensions (`--verbose`) | Won't | – | US-04 |
| FR-17 | `-s`/`--sort`: reorder linked certificates into chain order (leaf, intermediates, root), placed at the position of the chain's first certificate in the input; other blocks keep their order. `-r`/`--reverse` sorts root first instead | Should | Input intermediate, key, leaf → output leaf, intermediate, key | US-01 |
| FR-18 | Comment other blocks only when their content is readable: CSR (subject, SANs, public key, signature algorithm); unencrypted private key (friendly name from PKCS#8 attributes or OpenSSL Bag Attributes, algorithm, size or curve); public key (algorithm, size or curve). No comment for encrypted keys, CRLs or unknown types | Should | A CSR shows its subject; an encrypted key has no comment line above it | US-02, US-04 |
| FR-19 | Detect duplicate blocks (same type and content, line wrapping ignored); mark them with a warning; `-c`/`--clean` removes them instead (reported as a note on stderr, exit code unchanged) | Should | Second copy of a certificate shows `WARNING: duplicate of #1`; exit 1 | US-01 |

## Non-Functional Requirements

| ID | Category | Requirement | Measure |
| --- | --- | --- | --- |
| NFR-01 | Security | Private key material is copied byte-identical, never decrypted, and never appears in log or error messages | Test compares key blocks in input and output |
| NFR-02 | Security | No network access; files are written only to the `--out` target or with `--inplace` | Code review |
| NFR-03 | Robustness | Parser survives malformed or hostile input without crashing | Fuzzing, no panics |
| NFR-04 | Performance | Fast on typical bundles | < 100 ms for a file with 10 blocks |
| NFR-05 | Portability | Written in Rust; single static binary for Linux, macOS, Windows (amd64, arm64) | No OpenSSL dependency |
| NFR-06 | Usability | Color only when writing to a terminal | Piped output has no ANSI codes |
| NFR-07 | Usability | `--help` with examples and completion setup; all output, help and errors in English | Review |
| NFR-08 | Quality | Automated tests with sample PEM files | Coverage ≥ 80 % |
| NFR-09 | Maintainability | README, documented build, CI pipeline | Green CI on every commit |

Not yet in place: fuzzing (NFR-03), a coverage measurement (NFR-08) and a CI
pipeline (NFR-09).

## Examples

Generated with the test fixtures in `tests/fixtures/` at 2026-10-21 07:31:45
UTC. Base64 bodies are shortened with `…` here; the tool copies them in full.

### Example 1 — bundle with encrypted key and chain

`x509pretty bundle.pem`, input:

```text
Bag Attributes
    friendlyName: www.example.test
-----BEGIN ENCRYPTED PRIVATE KEY-----
MIIFJTBfBgkqhkiG9w0BBQ0wUjAxBgkqhkiG9w0BBQwwJAQQNcCIL2vz1t9JJfYf
…
-----END ENCRYPTED PRIVATE KEY-----
-----BEGIN CERTIFICATE-----
MIICaDCCAg6gAwIBAgIUd6Nz1Ie7XOl8JVXb8YaPxpZokKgwCgYIKoZIzj0EAwIw
…
-----END CERTIFICATE-----
-----BEGIN CERTIFICATE-----
MIIBnDCCAUKgAwIBAgIUZSb9srXFi4Zn8nlQYVGu97rglsMwCgYIKoZIzj0EAwIw
…
-----END CERTIFICATE-----
```

Output (exit code 0): the text above the encrypted key is kept because nothing
is inserted there; the key is echoed unchanged; both certificates get a comment.

```text
Bag Attributes
    friendlyName: www.example.test
-----BEGIN ENCRYPTED PRIVATE KEY-----
MIIFJTBfBgkqhkiG9w0BBQ0wUjAxBgkqhkiG9w0BBQwwJAQQNcCIL2vz1t9JJfYf
…
-----END ENCRYPTED PRIVATE KEY-----
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
# Certificate #3
#   Subject:    O=Example Test, CN=Example Test Intermediate CA
#   Issuer:     O=Example Test, CN=Example Test Root CA
#   Serial:     65:26:FD:B2:B5:C5:8B:86:67:F2:79:50:61:51:AE:F7:BA:E0:96:C3
#   Valid:      2026-10-21 07:31:45 UTC – 2031-10-20 07:31:45 UTC (1825 days left)
#   Public key: EC P-256
#   Signature:  ecdsa-with-SHA256
#   SHA-256:    61:87:2E:12:B9:B3:5B:17:FC:96:CF:5A:FB:5E:47:40:06:5A:26:7B:1E:59:F5:85:D5:0C:18:4E:41:52:0B:59
-----BEGIN CERTIFICATE-----
MIIBnDCCAUKgAwIBAgIUZSb9srXFi4Zn8nlQYVGu97rglsMwCgYIKoZIzj0EAwIw
…
-----END CERTIFICATE-----
```

### Example 2 — legacy certificate with warnings

`x509pretty legacy.pem`, stdout:

```text
# Certificate #1
#   Subject:    CN=legacy.example.test
#   Issuer:     CN=legacy.example.test (self-signed)
#   Serial:     5E:90:D8:DF:52:AE:BA:AF:35:FA:61:FF:1A:44:1F:C3:EF:CF:FB:26
#   Valid:      2026-10-21 07:31:45 UTC – 2027-10-21 07:31:45 UTC (365 days left)
#   Public key: RSA 1024 bit
#   Signature:  sha1WithRSAEncryption
#   SHA-256:    88:DB:9F:F3:5D:DF:B9:DA:9F:F1:B5:AF:42:E4:5C:F0:5C:90:68:5D:BC:33:0A:29:88:DE:D4:C5:1A:A6:F1:28
#   WARNING:    RSA key shorter than 2048 bit
#   WARNING:    SHA-1 signature
#   WARNING:    self-signed
-----BEGIN CERTIFICATE-----
MIIB9zCCAWCgAwIBAgIUXpDY31Kuuq81+mH/GkQfw+/P+yYwDQYJKoZIhvcNAQEF
…
-----END CERTIFICATE-----
```

stderr, exit code 1:

```text
warning: legacy.pem: certificate #1: RSA key shorter than 2048 bit
warning: legacy.pem: certificate #1: SHA-1 signature
warning: legacy.pem: certificate #1: self-signed
```

### Example 3 — PKCS#12 export with friendly names

`openssl pkcs12 -in leaf.p12 -nodes | x509pretty` (default text mode, so the
`Bag Attributes` above both blocks are replaced by the comments):

```text
# Certificate #1
#   Name:       www.example.test
#   Subject:    CN=www.example.test
…
-----BEGIN CERTIFICATE-----
…
-----END CERTIFICATE-----
# Private key #2
#   Name:       www.example.test
#   Algorithm:  RSA 2048 bit
-----BEGIN PRIVATE KEY-----
…
-----END PRIVATE KEY-----
```

### Example 4 — invocations

| Command | Result |
| --- | --- |
| `pbpaste \| x509pretty` | Annotated copy on stdout |
| `x509pretty a.pem b.pem` | Both files annotated, concatenated on stdout |
| `x509pretty --in a.pem --in b.pem -o all.pem` | Both files annotated into `all.pem` |
| `x509pretty --inplace certs/*.pem` | Each file annotated in place; original kept as `<file>.pretty` |
| `x509pretty --clean-text bundle.pem` | Like Example 1, but the `Bag Attributes` lines are dropped too |
| `x509pretty --sort chain.pem` | Certificates reordered leaf → intermediate → root; other blocks keep their order |
| `x509pretty --reverse chain.pem` | Certificates reordered root → intermediate → leaf |
| `x509pretty --clean bundle.pem` | Duplicate blocks removed, each noted on stderr |
| `x509pretty --completion zsh > _x509pretty` | zsh completion script |

## Out of Scope

- Input formats other than PEM: DER, PKCS#7, PKCS#12, JKS
- Fetching certificates from TLS servers
- Validation against a trust store, revocation checks (CRL, OCSP)
- Converting or splitting blocks; reordering only with `--sort`/`--reverse` (FR-17)
- Decrypting private keys
- Graphical or web interface

## Decisions

| Question | Decision |
| --- | --- |
| Other PEM types (`PUBLIC KEY`, `CERTIFICATE REQUEST`, `X509 CRL`)? | Echoed 1:1; readable ones get a comment (FR-07, FR-18) |
| Encrypted keys: show details with a passphrase? | Never decrypted, echoed 1:1 without comment (FR-07) |
| Text outside PEM blocks? | Kept by default except directly above commented blocks; `--clean-text` / `--keep-text` (FR-08) |
| One or several input files? | Several, into one output or each in place (FR-02 to FR-04) |
| Exit code on warnings? | Exit 1, each warning printed to stderr (FR-11) |
| Implementation language? | Rust (NFR-05) |
| Short option `-i`? | `-i` = `--in`; `--inplace` has no short form |
| Name of the `--inplace` backup? | `<file>.pretty` holds the original |
| Position comment for echoed blocks? | Only when the content is readable, never for encrypted keys (FR-18) |
| Earlier x509pretty comments with `--keep-text`? | Replaced, defensively: only exact x509pretty comments (FR-08) |
| Duplicates? | Marked with a warning; removed only with `--clean` (FR-19) |
| Friendly names? | Shown as `Name:` for certificates and unencrypted keys (FR-06, FR-18) |
