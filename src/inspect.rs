//! Turns a PEM block into the facts shown in its comment. Private keys are only
//! measured (algorithm, size); no key material ever leaves this module.

use crate::pem::Block;
use ::time::{OffsetDateTime, UtcOffset};
use sha2::{Digest, Sha256};
use x509_parser::der_parser::ber::{BerObjectContent, Class};
use x509_parser::der_parser::der::{parse_der, parse_der_oid};
use x509_parser::extensions::{GeneralName, ParsedExtension};
use x509_parser::prelude::*;
use x509_parser::public_key::PublicKey;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    Certificate,
    Csr,
    PrivateKey,
    PublicKey,
}

impl Kind {
    pub fn name(self) -> &'static str {
        match self {
            Kind::Certificate => "Certificate",
            Kind::Csr => "CSR",
            Kind::PrivateKey => "Private key",
            Kind::PublicKey => "Public key",
        }
    }
}

#[derive(Debug, Clone)]
pub struct Warning {
    pub text: String,
    /// Shown in red instead of yellow.
    pub severe: bool,
}

#[derive(Debug, Clone)]
pub struct Info {
    pub kind: Kind,
    pub fields: Vec<(&'static str, String)>,
    pub warnings: Vec<Warning>,
    pub error: Option<String>,
    /// Raw DER names and key identifiers, used to link certificates.
    pub subject: Option<Vec<u8>>,
    pub issuer: Option<Vec<u8>>,
    pub ski: Option<Vec<u8>>,
    pub aki: Option<Vec<u8>>,
}

impl Info {
    fn new(kind: Kind) -> Self {
        Info {
            kind,
            fields: Vec::new(),
            warnings: Vec::new(),
            error: None,
            subject: None,
            issuer: None,
            ski: None,
            aki: None,
        }
    }

    fn failed(kind: Kind, msg: String) -> Self {
        Info {
            error: Some(msg),
            ..Info::new(kind)
        }
    }

    fn warn(&mut self, text: impl Into<String>, severe: bool) {
        self.warnings.push(Warning {
            text: text.into(),
            severe,
        });
    }

    pub fn is_self_signed(&self) -> bool {
        self.subject.is_some()
            && self.subject == self.issuer
            && (self.ski.is_none() || self.aki.is_none() || self.ski == self.aki)
    }
}

/// `None` means the block gets no comment (encrypted keys, CRLs, unknown types).
pub fn inspect(block: &Block, now: OffsetDateTime) -> Option<Info> {
    let kind = match block.label.as_str() {
        "CERTIFICATE" | "X509 CERTIFICATE" => Kind::Certificate,
        "CERTIFICATE REQUEST" | "NEW CERTIFICATE REQUEST" => Kind::Csr,
        "PRIVATE KEY" | "RSA PRIVATE KEY" | "EC PRIVATE KEY" => Kind::PrivateKey,
        "PUBLIC KEY" | "RSA PUBLIC KEY" => Kind::PublicKey,
        _ => return None,
    };
    if kind == Kind::PrivateKey && block.has_headers() {
        return None;
    }
    let der = match block.der() {
        Ok(der) => der,
        Err(e) => return Some(Info::failed(kind, e)),
    };
    let result = match kind {
        Kind::Certificate => certificate(&der, now),
        Kind::Csr => csr(&der),
        Kind::PrivateKey => private_key(&block.label, &der),
        Kind::PublicKey => public_key(&block.label, &der),
    };
    Some(result.unwrap_or_else(|e| Info::failed(kind, format!("cannot parse: {e}"))))
}

fn certificate(der: &[u8], now: OffsetDateTime) -> Result<Info, String> {
    let (_, cert) = X509Certificate::from_der(der).map_err(|e| e.to_string())?;
    let mut info = Info::new(Kind::Certificate);
    info.subject = Some(cert.subject().as_raw().to_vec());
    info.issuer = Some(cert.issuer().as_raw().to_vec());
    for ext in cert.extensions() {
        match ext.parsed_extension() {
            ParsedExtension::SubjectKeyIdentifier(id) => info.ski = Some(id.0.to_vec()),
            ParsedExtension::AuthorityKeyIdentifier(aki) => {
                info.aki = aki.key_identifier.as_ref().map(|id| id.0.to_vec())
            }
            _ => {}
        }
    }
    let self_signed = info.is_self_signed();

    info.fields.push(("Subject", name(cert.subject())));
    let issuer = name(cert.issuer());
    info.fields.push((
        "Issuer",
        if self_signed {
            format!("{issuer} (self-signed)")
        } else {
            issuer
        },
    ));
    info.fields.push(("Serial", hex(cert.raw_serial())));

    let not_before = cert.validity().not_before.to_datetime();
    let not_after = cert.validity().not_after.to_datetime();
    let days_left = (not_after - now).whole_days();
    let state = if now > not_after {
        let ago = (now - not_after).whole_days();
        info.warn(format!("expired {ago} days ago"), true);
        format!("expired {ago} days ago")
    } else if now < not_before {
        info.warn("not yet valid", true);
        "not yet valid".to_string()
    } else {
        if days_left < 30 {
            info.warn(format!("expires in {days_left} days"), false);
        }
        format!("{days_left} days left")
    };
    info.fields.push((
        "Valid",
        format!("{} \u{2013} {} ({state})", date(not_before), date(not_after)),
    ));

    if let Ok(Some(san)) = cert.subject_alternative_name() {
        info.fields
            .push(("SANs", general_names(&san.value.general_names)));
    }
    spki_fields(&mut info, cert.public_key());
    signature_field(&mut info, &cert.signature_algorithm.algorithm);
    info.fields.push(("SHA-256", hex(&Sha256::digest(der))));
    if self_signed {
        info.warn("self-signed", false);
    }
    Ok(info)
}

fn csr(der: &[u8]) -> Result<Info, String> {
    let (_, req) = X509CertificationRequest::from_der(der).map_err(|e| e.to_string())?;
    let cri = &req.certification_request_info;
    let mut info = Info::new(Kind::Csr);
    info.fields.push(("Subject", name(&cri.subject)));
    if let Some(exts) = req.requested_extensions() {
        for ext in exts {
            if let ParsedExtension::SubjectAlternativeName(san) = ext {
                info.fields.push(("SANs", general_names(&san.general_names)));
            }
        }
    }
    spki_fields(&mut info, &cri.subject_pki);
    signature_field(&mut info, &req.signature_algorithm.algorithm);
    Ok(info)
}

fn private_key(label: &str, der: &[u8]) -> Result<Info, String> {
    let mut info = Info::new(Kind::PrivateKey);
    let algorithm = match label {
        "RSA PRIVATE KEY" => rsa_bits_from_pkcs1(der).map(|bits| (format!("RSA {bits} bit"), Some(bits)))?,
        "EC PRIVATE KEY" => (ec_private_key_curve(der), None),
        _ => pkcs8_algorithm(der)?,
    };
    if let Some(name) = pkcs8_friendly_name(der) {
        info.fields.push(("Name", name));
    }
    info.fields.push(("Algorithm", algorithm.0));
    if let Some(bits) = algorithm.1 {
        rsa_size_warning(&mut info, bits);
    }
    Ok(info)
}

fn public_key(label: &str, der: &[u8]) -> Result<Info, String> {
    let mut info = Info::new(Kind::PublicKey);
    if label == "RSA PUBLIC KEY" {
        let bits = rsa_bits_from_sequence(der, 0)?;
        info.fields.push(("Algorithm", format!("RSA {bits} bit")));
        rsa_size_warning(&mut info, bits);
    } else {
        let (_, spki) = SubjectPublicKeyInfo::from_der(der).map_err(|e| e.to_string())?;
        let (text, bits) = describe_spki(&spki);
        info.fields.push(("Algorithm", text));
        if let Some(bits) = bits {
            rsa_size_warning(&mut info, bits);
        }
    }
    Ok(info)
}

fn spki_fields(info: &mut Info, spki: &SubjectPublicKeyInfo) {
    let (text, rsa_bits) = describe_spki(spki);
    info.fields.push(("Public key", text));
    if let Some(bits) = rsa_bits {
        rsa_size_warning(info, bits);
    }
}

fn signature_field(info: &mut Info, oid: &x509_parser::der_parser::oid::Oid) {
    let name = oid_name(oid);
    let lower = name.to_ascii_lowercase();
    if lower.contains("sha1") {
        info.warn("SHA-1 signature", false);
    } else if lower.contains("md5") || lower.contains("md2") {
        info.warn("MD5 signature", false);
    }
    info.fields.push(("Signature", name));
}

fn rsa_size_warning(info: &mut Info, bits: usize) {
    if bits < 2048 {
        info.warn("RSA key shorter than 2048 bit", false);
    }
}

/// Human-readable key description, plus the size when it is an RSA key.
fn describe_spki(spki: &SubjectPublicKeyInfo) -> (String, Option<usize>) {
    let alg = &spki.algorithm;
    match alg.algorithm.to_id_string().as_str() {
        "1.2.840.113549.1.1.1" | "1.2.840.113549.1.1.10" => match spki.parsed() {
            Ok(PublicKey::RSA(rsa)) => {
                let bits = int_bits(rsa.modulus);
                (format!("RSA {bits} bit"), Some(bits))
            }
            _ => ("RSA".into(), None),
        },
        "1.2.840.10045.2.1" => {
            let curve = alg
                .parameters
                .as_ref()
                .and_then(|p| p.as_oid().ok())
                .map(|oid| curve_name(&oid.to_id_string()))
                .unwrap_or_else(|| "EC".into());
            (curve, None)
        }
        "1.2.840.10040.4.1" => match spki.parsed() {
            Ok(PublicKey::DSA(y)) => (format!("DSA {} bit", int_bits(y)), None),
            _ => ("DSA".into(), None),
        },
        other => (
            simple_algorithm(other).unwrap_or_else(|| oid_name(&alg.algorithm)),
            None,
        ),
    }
}

/// For a certificate or an unencrypted private key without a name of its own,
/// takes the friendly name from the text directly above the block: a
/// `friendlyName:` line of OpenSSL's `Bag Attributes`, or the `Name:` line of
/// an earlier x509pretty comment (so a second run keeps it).
pub fn add_name_from_text(info: &mut Info, text: &[u8]) {
    let named_kind = matches!(info.kind, Kind::Certificate | Kind::PrivateKey);
    if !named_kind || info.error.is_some() || info.fields.iter().any(|(l, _)| *l == "Name") {
        return;
    }
    let name = String::from_utf8_lossy(text).lines().rev().find_map(|line| {
        let line = line.trim_end_matches('\r');
        let value = match line.strip_prefix("#   Name:") {
            Some(v) => v,
            None => line
                .trim_start()
                .strip_prefix("friendlyName:")
                .filter(|_| line.starts_with(char::is_whitespace))?,
        };
        Some(value.trim().to_string()).filter(|v| !v.is_empty())
    });
    if let Some(name) = name {
        info.fields.insert(0, ("Name", name));
    }
}

/// PrivateKeyInfo ::= SEQUENCE { version, algorithm, privateKey, [0] attributes OPTIONAL }
/// with the PKCS#9 friendlyName attribute (BMPString).
fn pkcs8_friendly_name(der: &[u8]) -> Option<String> {
    let (_, obj) = parse_der(der).ok()?;
    let attributes = obj
        .as_sequence()
        .ok()?
        .iter()
        .find(|item| item.header.class() == Class::ContextSpecific && item.header.tag().0 == 0)?;
    let mut data = match &attributes.content {
        BerObjectContent::Unknown(any) => any.data,
        _ => return None,
    };
    while !data.is_empty() {
        let (rest, attr) = parse_der(data).ok()?;
        data = rest;
        let attr = attr.as_sequence().ok()?;
        if attr.first()?.as_oid().ok()?.to_id_string() != "1.2.840.113549.1.9.20" {
            continue;
        }
        let value = attr.get(1)?.as_set().ok()?.first()?;
        return match &value.content {
            BerObjectContent::BmpString(raw) => {
                let units: Vec<u16> = raw
                    .as_chunks::<2>()
                    .0
                    .iter()
                    .map(|c| u16::from_be_bytes(*c))
                    .collect();
                String::from_utf16(&units).ok()
            }
            _ => value.as_str().ok().map(str::to_string),
        };
    }
    None
}

fn pkcs8_algorithm(der: &[u8]) -> Result<(String, Option<usize>), String> {
    let (_, obj) = parse_der(der).map_err(|e| e.to_string())?;
    let seq = obj.as_sequence().map_err(|e| e.to_string())?;
    let alg = seq
        .get(1)
        .and_then(|a| a.as_sequence().ok())
        .ok_or("missing algorithm")?;
    let oid = alg
        .first()
        .and_then(|o| o.as_oid().ok())
        .ok_or("missing algorithm OID")?;
    let id = oid.to_id_string();
    Ok(match id.as_str() {
        "1.2.840.113549.1.1.1" | "1.2.840.113549.1.1.10" => {
            let inner = seq.get(2).and_then(|k| k.as_slice().ok()).ok_or("missing key")?;
            let bits = rsa_bits_from_pkcs1(inner)?;
            (format!("RSA {bits} bit"), Some(bits))
        }
        "1.2.840.10045.2.1" => {
            let curve = alg
                .get(1)
                .and_then(|p| p.as_oid().ok())
                .map(|o| curve_name(&o.to_id_string()));
            (curve.unwrap_or_else(|| "EC".into()), None)
        }
        other => (simple_algorithm(other).unwrap_or_else(|| oid_name(oid)), None),
    })
}

/// RSAPrivateKey ::= SEQUENCE { version, modulus, ... }
fn rsa_bits_from_pkcs1(der: &[u8]) -> Result<usize, String> {
    rsa_bits_from_sequence(der, 1)
}

fn rsa_bits_from_sequence(der: &[u8], index: usize) -> Result<usize, String> {
    let (_, obj) = parse_der(der).map_err(|e| e.to_string())?;
    let seq = obj.as_sequence().map_err(|e| e.to_string())?;
    let modulus = seq
        .get(index)
        .and_then(|m| m.as_slice().ok())
        .ok_or("missing modulus")?;
    Ok(int_bits(modulus))
}

/// ECPrivateKey ::= SEQUENCE { version, privateKey, [0] parameters OPTIONAL, ... }
fn ec_private_key_curve(der: &[u8]) -> String {
    let curve = parse_der(der).ok().and_then(|(_, obj)| {
        obj.as_sequence().ok()?.iter().find_map(|item| {
            if item.header.class() != Class::ContextSpecific || item.header.tag().0 != 0 {
                return None;
            }
            let data = match &item.content {
                BerObjectContent::Unknown(any) => any.data,
                BerObjectContent::Tagged(_, _, inner) => {
                    return inner.as_oid().ok().map(|o| o.to_id_string());
                }
                _ => return None,
            };
            let (_, oid) = parse_der_oid(data).ok()?;
            oid.as_oid().ok().map(|o| o.to_id_string())
        })
    });
    curve.map(|c| curve_name(&c)).unwrap_or_else(|| "EC".into())
}

fn curve_name(oid: &str) -> String {
    match oid {
        "1.2.840.10045.3.1.7" => "EC P-256".into(),
        "1.3.132.0.34" => "EC P-384".into(),
        "1.3.132.0.35" => "EC P-521".into(),
        "1.3.132.0.10" => "EC secp256k1".into(),
        "1.3.36.3.3.2.8.1.1.7" => "EC brainpoolP256r1".into(),
        "1.3.36.3.3.2.8.1.1.11" => "EC brainpoolP384r1".into(),
        "1.3.36.3.3.2.8.1.1.13" => "EC brainpoolP512r1".into(),
        other => format!("EC (curve {other})"),
    }
}

fn simple_algorithm(oid: &str) -> Option<String> {
    Some(
        match oid {
            "1.3.101.110" => "X25519",
            "1.3.101.111" => "X448",
            "1.3.101.112" => "Ed25519",
            "1.3.101.113" => "Ed448",
            _ => return None,
        }
        .into(),
    )
}

fn oid_name(oid: &x509_parser::der_parser::oid::Oid) -> String {
    oid2sn(oid, oid_registry())
        .map(str::to_string)
        .unwrap_or_else(|_| oid.to_id_string())
}

/// Bit length of a big-endian unsigned integer (leading zero bytes ignored).
fn int_bits(bytes: &[u8]) -> usize {
    let bytes = match bytes.iter().position(|&b| b != 0) {
        Some(i) => &bytes[i..],
        None => return 0,
    };
    (bytes.len() - 1) * 8 + (8 - bytes[0].leading_zeros() as usize)
}

fn name(n: &X509Name) -> String {
    n.to_string_with_registry(oid_registry())
        .unwrap_or_else(|_| n.to_string())
}

fn general_names(names: &[GeneralName]) -> String {
    names
        .iter()
        .map(|n| match n {
            GeneralName::DNSName(s) => format!("DNS:{s}"),
            GeneralName::RFC822Name(s) => format!("email:{s}"),
            GeneralName::URI(s) => format!("URI:{s}"),
            GeneralName::IPAddress(ip) => format!("IP:{}", ip_address(ip)),
            other => other.to_string(),
        })
        .collect::<Vec<_>>()
        .join(", ")
}

fn ip_address(bytes: &[u8]) -> String {
    match bytes.len() {
        4 => std::net::Ipv4Addr::from(<[u8; 4]>::try_from(bytes).unwrap()).to_string(),
        16 => std::net::Ipv6Addr::from(<[u8; 16]>::try_from(bytes).unwrap()).to_string(),
        _ => hex(bytes),
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes
        .iter()
        .map(|b| format!("{b:02X}"))
        .collect::<Vec<_>>()
        .join(":")
}

fn date(t: OffsetDateTime) -> String {
    let t = t.to_offset(UtcOffset::UTC);
    format!(
        "{:04}-{:02}-{:02} {:02}:{:02}:{:02} UTC",
        t.year(),
        t.month() as u8,
        t.day(),
        t.hour(),
        t.minute(),
        t.second()
    )
}

#[cfg(test)]
mod tests {
    use super::{int_bits, pkcs8_friendly_name};

    #[test]
    fn friendly_name_from_pkcs8_attributes() {
        // Ed25519 PrivateKeyInfo with attributes [0] { friendlyName = BMPString "test" }
        let mut der = vec![
            0x30, 0x49, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2B, 0x65, 0x70,
        ];
        der.extend([0x04, 0x22, 0x04, 0x20]);
        der.extend([0x11; 32]);
        der.extend([
            0xA0, 0x19, 0x30, 0x17, 0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x09, 0x14,
        ]);
        der.extend([
            0x31, 0x0A, 0x1E, 0x08, 0x00, b't', 0x00, b'e', 0x00, b's', 0x00, b't',
        ]);
        assert_eq!(pkcs8_friendly_name(&der).as_deref(), Some("test"));
        assert_eq!(pkcs8_friendly_name(&der[..2 + 3 + 7 + 36]), None);
    }

    #[test]
    fn bit_length_ignores_leading_zeros() {
        assert_eq!(int_bits(&[0x00, 0x80, 0x00]), 16);
        assert_eq!(int_bits(&[0x01, 0x00]), 9);
        assert_eq!(int_bits(&[0x00]), 0);
    }
}
