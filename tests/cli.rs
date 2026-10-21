use assert_cmd::Command;
use std::path::{Path, PathBuf};

/// 2026-10-21 07:31:45 UTC, the moment the fixtures were issued.
const NOW: &str = "1792567905";

fn fixture(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures")
        .join(name)
}

fn read(name: &str) -> Vec<u8> {
    std::fs::read(fixture(name)).unwrap()
}

fn cmd() -> Command {
    let mut c = Command::cargo_bin("x509pretty").unwrap();
    c.env("X509PRETTY_NOW", NOW).env_remove("NO_COLOR");
    c
}

fn run_stdin(input: &[u8], args: &[&str]) -> (Vec<u8>, String, i32) {
    let out = cmd().args(args).write_stdin(input.to_vec()).output().unwrap();
    (
        out.stdout,
        String::from_utf8(out.stderr).unwrap(),
        out.status.code().unwrap(),
    )
}

fn bundle() -> Vec<u8> {
    [
        b"Bag Attributes\n    friendlyName: www.example.test\n".to_vec(),
        read("leaf.enc.key"),
        read("leaf.pem"),
        read("intermediate.pem"),
    ]
    .concat()
}

/// Output lines that are not comments, i.e. the PEM content.
fn without_comments(data: &[u8]) -> Vec<u8> {
    data.split_inclusive(|&b| b == b'\n')
        .filter(|l| !l.starts_with(b"# "))
        .flatten()
        .copied()
        .collect()
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    haystack.windows(needle.len()).any(|w| w == needle)
}

#[test]
fn annotates_bundle_and_keeps_blocks_identical() {
    let (out, err, code) = run_stdin(&bundle(), &[]);
    let text = String::from_utf8(out.clone()).unwrap();
    assert_eq!(code, 0, "stderr: {err}");
    assert!(err.is_empty());
    // Text above the key stays, nothing is inserted there (FR-08, FR-18).
    assert!(text.starts_with(
        "Bag Attributes\n    friendlyName: www.example.test\n-----BEGIN ENCRYPTED PRIVATE KEY-----"
    ));
    assert!(text.contains("# Certificate #2 issued by #3\n#   Subject:    CN=www.example.test\n"));
    assert!(text.contains(
        "#   Valid:      2026-10-21 07:31:45 UTC \u{2013} 2027-01-19 07:31:45 UTC (90 days left)\n"
    ));
    assert!(text.contains("#   SANs:       DNS:www.example.test, DNS:example.test\n"));
    assert!(text.contains("# Certificate #3\n"));
    assert!(text.contains("#   Public key: EC P-256\n"));
    assert_eq!(without_comments(&out), bundle());
    assert!(contains(&out, &read("leaf.enc.key")));
}

#[test]
fn output_is_stable_when_run_on_itself() {
    for mode in [&[][..], &["--keep-text"][..], &["--clean-text"][..]] {
        let (first, _, _) = run_stdin(&bundle(), mode);
        let (second, _, _) = run_stdin(&first, mode);
        assert_eq!(
            String::from_utf8(second).unwrap(),
            String::from_utf8(first).unwrap(),
            "mode {mode:?}"
        );
    }
}

#[test]
fn text_modes() {
    let input = [
        b"intro\n".to_vec(),
        read("leaf.pem"),
        b"between\n".to_vec(),
        read("leaf.enc.key"),
        b"tail\n".to_vec(),
    ]
    .concat();
    let text = |args: &[&str]| String::from_utf8(run_stdin(&input, args).0).unwrap();

    let default = text(&[]);
    assert!(!default.contains("intro"), "text above a certificate is replaced");
    assert!(default.contains("between\n-----BEGIN ENCRYPTED"));
    assert!(default.ends_with("tail\n"));

    let clean = text(&["--clean-text"]);
    assert!(!clean.contains("intro") && !clean.contains("between") && !clean.contains("tail"));

    let keep = text(&["--keep-text"]);
    assert!(keep.starts_with("intro\n# Certificate #1"));
    assert!(keep.contains("between\n") && keep.ends_with("tail\n"));
}

#[test]
fn foreign_comments_are_kept_with_keep_text() {
    let input = [b"# Certificate of my web server\n".to_vec(), read("leaf.pem")].concat();
    let (out, _, _) = run_stdin(&input, &["--keep-text"]);
    assert!(
        String::from_utf8(out)
            .unwrap()
            .starts_with("# Certificate of my web server\n# Certificate #1")
    );
}

#[test]
fn warnings_go_to_stderr_with_exit_code_1() {
    let (out, err, code) = run_stdin(&read("legacy.pem"), &[]);
    let text = String::from_utf8(out).unwrap();
    assert_eq!(code, 1);
    assert!(text.contains("#   WARNING:    SHA-1 signature\n"));
    assert!(text.contains("#   Public key: RSA 1024 bit\n"));
    assert!(err.contains("warning: <stdin>: certificate #1: SHA-1 signature\n"));
    assert!(err.contains("warning: <stdin>: certificate #1: RSA key shorter than 2048 bit\n"));
    assert!(err.contains("warning: <stdin>: certificate #1: self-signed\n"));
}

#[test]
fn expired_certificate() {
    let (out, err, code) = run_stdin(&read("expired.pem"), &[]);
    assert_eq!(code, 1);
    assert!(String::from_utf8(out).unwrap().contains("(expired 293 days ago)"));
    assert!(err.contains("certificate #1: expired 293 days ago"));
}

#[test]
fn malformed_certificate_is_kept_and_reported() {
    let broken = b"-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n";
    let input = [read("leaf.pem"), broken.to_vec(), read("intermediate.pem")].concat();
    let (out, err, code) = run_stdin(&input, &[]);
    let text = String::from_utf8(out.clone()).unwrap();
    assert_eq!(code, 2);
    assert!(text.contains("# Certificate #2\n#   ERROR:      cannot parse"));
    assert!(text.contains("# Certificate #3\n"));
    assert!(err.contains("error: <stdin>: certificate #2: cannot parse"));
    assert_eq!(without_comments(&out), input);
}

#[test]
fn other_blocks() {
    let input = [
        read("leaf.key"),
        read("leaf.csr"),
        read("expired.pub"),
        read("expired.ec.key"),
        read("intermediate.crl"),
    ]
    .concat();
    let (out, _, code) = run_stdin(&input, &[]);
    let text = String::from_utf8(out.clone()).unwrap();
    assert_eq!(code, 0);
    assert!(text.contains("# Private key #1\n#   Algorithm:  RSA 2048 bit\n-----BEGIN PRIVATE KEY-----"));
    assert!(text.contains("# CSR #2\n#   Subject:    CN=www.example.test\n"));
    assert!(text.contains("# Public key #3\n#   Algorithm:  EC P-384\n"));
    assert!(text.contains("# Private key #4\n#   Algorithm:  EC P-384\n-----BEGIN EC PRIVATE KEY-----"));
    assert!(!text.contains("#5"), "CRLs get no comment");
    assert_eq!(without_comments(&out), input);
}

#[test]
fn sort_orders_chain_leaf_first() {
    let input = [
        read("root.pem"),
        read("leaf.enc.key"),
        read("intermediate.pem"),
        read("leaf.pem"),
    ]
    .concat();
    let (out, _, _) = run_stdin(&input, &["--sort"]);
    let text = String::from_utf8(out).unwrap();
    let pos = |needle: &str| text.find(needle).unwrap_or_else(|| panic!("missing {needle}"));
    assert!(text.contains("# Certificate #1 issued by #2\n#   Subject:    CN=www.example.test"));
    assert!(text.contains(
        "# Certificate #2 issued by #3\n#   Subject:    O=Example Test, CN=Example Test Intermediate CA"
    ));
    assert!(text.contains("# Certificate #3\n#   Subject:    O=Example Test, CN=Example Test Root CA"));
    assert!(pos("Example Test Root CA\n#   Issuer") < pos("BEGIN ENCRYPTED PRIVATE KEY"));
}

#[test]
fn several_files_into_one_output() {
    let dir = tempdir();
    let out = dir.join("all.pem");
    let leaf = fixture("leaf.pem");
    let int = fixture("intermediate.pem");
    cmd()
        .arg(&leaf)
        .arg("-i")
        .arg(&int)
        .arg("-o")
        .arg(&out)
        .assert()
        .code(0);
    let text = std::fs::read_to_string(&out).unwrap();
    assert!(text.contains("# Certificate #1 issued by #2"));
    assert!(!text.contains('\x1b'));
}

#[test]
fn inplace_keeps_original_as_pretty() {
    let dir = tempdir();
    let target = dir.join("bundle.pem");
    std::fs::write(&target, bundle()).unwrap();
    cmd().arg("--inplace").arg(&target).assert().code(0);
    assert_eq!(std::fs::read(dir.join("bundle.pem.pretty")).unwrap(), bundle());
    let annotated = std::fs::read_to_string(&target).unwrap();
    assert!(annotated.contains("# Certificate #2 issued by #3"));
}

#[test]
fn inplace_needs_files() {
    let (_, err, code) = run_stdin(&bundle(), &["--inplace"]);
    assert_eq!(code, 2);
    assert!(err.contains("--inplace needs input files"));
}

#[test]
fn crlf_line_endings_are_preserved() {
    let crlf: Vec<u8> = String::from_utf8(read("leaf.pem"))
        .unwrap()
        .replace('\n', "\r\n")
        .into_bytes();
    let (out, _, _) = run_stdin(&crlf, &[]);
    let text = String::from_utf8(out.clone()).unwrap();
    assert!(text.starts_with("# Certificate #1\r\n#   Subject:    CN=www.example.test\r\n"));
    assert!(contains(&out, &crlf));
}

#[test]
fn completion_scripts() {
    for shell in ["bash", "zsh"] {
        let out = cmd().args(["--completion", shell]).output().unwrap();
        assert!(out.status.success());
        assert!(String::from_utf8(out.stdout).unwrap().contains("--inplace"));
    }
}

fn tempdir() -> PathBuf {
    use std::sync::atomic::{AtomicUsize, Ordering};
    static N: AtomicUsize = AtomicUsize::new(0);
    let dir = std::env::temp_dir().join(format!(
        "x509pretty-test-{}-{}",
        std::process::id(),
        N.fetch_add(1, Ordering::SeqCst)
    ));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

#[test]
fn duplicates_are_marked_not_removed() {
    let input = [
        read("leaf.pem"),
        read("leaf.enc.key"),
        read("leaf.pem"),
        read("leaf.enc.key"),
    ]
    .concat();
    let (out, err, code) = run_stdin(&input, &[]);
    let text = String::from_utf8(out.clone()).unwrap();
    assert_eq!(code, 1);
    assert!(text.contains("#   WARNING:    duplicate of #1\n"));
    assert!(err.contains("warning: <stdin>: certificate #3: duplicate of #1\n"));
    assert!(err.contains("warning: <stdin>: block #4 (ENCRYPTED PRIVATE KEY): duplicate of #2\n"));
    assert_eq!(without_comments(&out), input);
}

#[test]
fn duplicates_are_found_despite_different_line_endings() {
    let crlf: Vec<u8> = String::from_utf8(read("leaf.pem"))
        .unwrap()
        .replace('\n', "\r\n")
        .into_bytes();
    let (_, err, _) = run_stdin(&[read("leaf.pem"), crlf].concat(), &[]);
    assert!(err.contains("certificate #2: duplicate of #1"));
}

#[test]
fn unreadable_file_aborts_without_output() {
    let dir = tempdir();
    let out = dir.join("all.pem");
    let missing = dir.join("missing.pem");
    let result = cmd()
        .arg(fixture("leaf.pem"))
        .arg(&missing)
        .arg("-o")
        .arg(&out)
        .output()
        .unwrap();
    assert_eq!(result.status.code(), Some(2));
    assert!(
        String::from_utf8(result.stderr)
            .unwrap()
            .contains("error: cannot read")
    );
    assert!(!out.exists());

    let result = cmd().arg(fixture("leaf.pem")).arg(&missing).output().unwrap();
    assert_eq!(result.status.code(), Some(2));
    assert!(result.stdout.is_empty());

    let target = dir.join("bundle.pem");
    std::fs::write(&target, bundle()).unwrap();
    cmd().arg("--inplace").arg(&target).arg(&missing).assert().code(2);
    assert_eq!(std::fs::read(&target).unwrap(), bundle());
    assert!(!dir.join("bundle.pem.pretty").exists());
}

#[test]
fn reverse_orders_chain_root_first() {
    let input = [
        read("leaf.pem"),
        read("leaf.enc.key"),
        read("root.pem"),
        read("intermediate.pem"),
    ]
    .concat();
    let (out, _, _) = run_stdin(&input, &["--reverse"]);
    let text = String::from_utf8(out).unwrap();
    assert!(text.contains("# Certificate #1\n#   Subject:    O=Example Test, CN=Example Test Root CA"));
    assert!(text.contains(
        "# Certificate #2 issued by #1\n#   Subject:    O=Example Test, CN=Example Test Intermediate CA"
    ));
    assert!(text.contains("# Certificate #3 issued by #2\n#   Subject:    CN=www.example.test"));
    assert!(text.find("CN=www.example.test\n").unwrap() < text.find("BEGIN ENCRYPTED PRIVATE KEY").unwrap());

    let (_, err, code) = run_stdin(&input, &["--sort", "--reverse"]);
    assert_eq!(code, 2);
    assert!(err.contains("cannot be used with"));
}

#[test]
fn clean_removes_duplicates() {
    let input = [
        read("leaf.pem"),
        read("leaf.enc.key"),
        read("leaf.pem"),
        read("intermediate.pem"),
        read("leaf.enc.key"),
    ]
    .concat();
    let (out, err, code) = run_stdin(&input, &["--clean"]);
    let text = String::from_utf8(out.clone()).unwrap();
    assert_eq!(code, 0, "removing duplicates on request is not a warning: {err}");
    assert_eq!(
        without_comments(&out),
        [read("leaf.pem"), read("leaf.enc.key"), read("intermediate.pem")].concat()
    );
    assert!(text.contains("# Certificate #1 issued by #3\n"));
    assert!(!text.contains("duplicate"));
    assert!(err.contains("note: <stdin>: removed duplicate of #1 (CERTIFICATE)\n"));
    assert!(err.contains("note: <stdin>: removed duplicate of #2 (ENCRYPTED PRIVATE KEY)\n"));
}

#[test]
fn clean_with_keep_text_keeps_text_of_removed_blocks() {
    let input = [
        read("leaf.pem"),
        b"note about the copy\n".to_vec(),
        read("leaf.pem"),
        b"tail\n".to_vec(),
    ]
    .concat();
    let (out, _, _) = run_stdin(&input, &["--clean", "--keep-text"]);
    let text = String::from_utf8(out).unwrap();
    assert!(text.ends_with("-----END CERTIFICATE-----\nnote about the copy\ntail\n"));
    let (out, _, _) = run_stdin(&input, &["--clean"]);
    assert!(!String::from_utf8(out).unwrap().contains("note about the copy"));
}

#[test]
fn friendly_names_from_bag_attributes() {
    let input = read("leaf.p12.pem");
    let (out, _, code) = run_stdin(&input, &[]);
    let text = String::from_utf8(out.clone()).unwrap();
    assert_eq!(code, 0);
    assert!(text.contains(
        "# Certificate #1\n#   Name:       www.example.test\n#   Subject:    CN=www.example.test\n"
    ));
    assert!(text.contains("# Private key #2\n#   Name:       www.example.test\n#   Algorithm:  RSA 2048 bit\n-----BEGIN PRIVATE KEY-----"));
    assert!(
        !text.contains("Bag Attributes"),
        "text above commented blocks is replaced by default"
    );
    let (again, _, _) = run_stdin(&out, &[]);
    assert_eq!(
        String::from_utf8(again).unwrap(),
        text,
        "the name survives a second run"
    );

    let (keep, _, _) = run_stdin(&input, &["--keep-text"]);
    assert!(
        String::from_utf8(keep).unwrap().contains(
            "Key Attributes: <No Attributes>\n# Private key #2\n#   Name:       www.example.test\n"
        )
    );
}
