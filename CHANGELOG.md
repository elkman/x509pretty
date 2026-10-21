# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).
How releases are made: [docs/releasing.md](docs/releasing.md).

## [v0.1.0] - 21.10.2026

### Added

- Annotated copy of PEM input: every block stays byte-identical and in place;
  certificates get a comment with subject, issuer, serial, validity, SANs,
  public key, signature algorithm and SHA-256 fingerprint.
- Comments for CSRs, unencrypted private keys and public keys; encrypted keys,
  CRLs and unknown blocks are copied without a comment.
- Friendly names from OpenSSL `Bag Attributes` and PKCS#8 key attributes.
- Warnings for expired, not yet valid and soon expiring certificates, SHA-1/MD5
  signatures, RSA keys under 2048 bit, self-signed certificates and duplicate
  blocks; exit codes 0 (ok), 1 (warnings), 2 (errors).
- Input from stdin or several files (`-i`/`--in`), output to stdout,
  `-o`/`--out` or `--inplace` with `<file>.pretty` backup.
- Chain sorting with `-s`/`--sort` (leaf first) and `-r`/`--reverse` (root first).
- Duplicate removal with `-c`/`--clean`.
- Text modes `--clean-text` and `--keep-text`; repeated runs replace earlier
  comments instead of stacking them.
- Colors on terminals for stdout and stderr; `--no-color` and `NO_COLOR`.
- Shell completion for bash and zsh (`--completion`).
- CI on GitHub Actions and release binaries for Linux, macOS and Windows
  (x86_64 and arm64).

[v0.1.0]: https://github.com/elkman/x509pretty/commits/0.1.0
