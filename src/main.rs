use std::io::{Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::thread;
use std::time::Duration;

use clap::Parser;
use der::{Decode, asn1::ObjectIdentifier};
use rustls::DigitallySignedStruct;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls_pki_types::{CertificateDer, ServerName, UnixTime};
use spki::SubjectPublicKeyInfoOwned;
use x509_cert::Certificate;

mod ct;
mod curves;

const OID_EC: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.2.1");
const OID_P256: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.3.1.7");
const OID_P384: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.132.0.34");
const OID_P521: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.132.0.35");
const OID_K256: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.132.0.10");
const FIRST_CCADB_YEAR: u64 = 1999;

#[derive(Parser)]
#[command(
    version,
    about = "Check whether an EC public key (or certificate) was generated from a low-value private key.\n\
             Exit codes: 0 = not found in range, 1 = private key found, 2 = error."
)]
struct Cli {
    /// Path to a PEM/DER public key or certificate, or an https:// (or tls://host:port) URL
    /// whose server certificate is fetched. Use "-" or omit to read from stdin.
    path: Option<PathBuf>,

    /// Inclusive private key range to check, as "MIN-MAX" or just "MAX".
    #[arg(short, long, default_value = "0-32767")]
    range: String,

    /// Number of worker threads (default: available CPUs).
    #[arg(short, long)]
    threads: Option<std::num::NonZeroUsize>,

    /// For URLs, only check the leaf certificate instead of the whole presented chain.
    #[arg(long)]
    leaf_only: bool,

    /// For .csv input, the (case-insensitive) header of the column holding the public key or PEM
    /// certificate (default: auto-detect).
    #[arg(long)]
    column: Option<String>,

    /// Only print vulnerable results (hide OK and SKIP lines).
    #[arg(short, long)]
    quiet: bool,

    /// Download the CCADB "All Certificate PEMs" report for every year since 1999 and check all
    /// certificates in them.
    #[arg(long, conflicts_with = "path")]
    check_ccadb: bool,

    /// CCADB year(s): YEAR, MIN-MAX, -MAX (from 1999), or MIN- (through this year).
    #[arg(long, requires = "check_ccadb", allow_hyphen_values = true)]
    year: Option<String>,

    /// Load ctlogs.dev details for vulnerable certificates (or keys with a Pro API key).
    /// Sends certificate/SPKI SHA-256 fingerprints only for findings.
    #[arg(long)]
    ct_details: bool,
}

fn parse_range(s: &str) -> Result<(u64, u64), String> {
    let num = |t: &str| {
        t.trim()
            .parse::<u64>()
            .map_err(|e| format!("invalid range value '{t}': {e}"))
    };
    let (lo, hi) = match s.split_once('-') {
        Some((a, b)) => (num(a)?, num(b)?),
        None => (0, num(s)?),
    };
    if lo > hi {
        return Err(format!("range minimum {lo} exceeds maximum {hi}"));
    }
    Ok((lo, hi))
}

fn parse_years(s: &str, current_year: u64) -> Result<(u64, u64), String> {
    let year = |value: &str| {
        value
            .trim()
            .parse::<u64>()
            .map_err(|e| format!("invalid CCADB year '{value}': {e}"))
    };
    let (lo, hi) = match s.trim().split_once('-') {
        Some((lo, hi)) => {
            let (lo, hi) = (lo.trim(), hi.trim());
            if lo.is_empty() && hi.is_empty() {
                return Err("CCADB year range must have at least one endpoint".into());
            }
            (
                if lo.is_empty() {
                    FIRST_CCADB_YEAR
                } else {
                    year(lo)?
                },
                if hi.is_empty() {
                    current_year
                } else {
                    year(hi)?
                },
            )
        }
        None => {
            let year = year(s)?;
            (year, year)
        }
    };
    if lo > hi {
        return Err(format!("CCADB year minimum {lo} exceeds maximum {hi}"));
    }
    if lo < FIRST_CCADB_YEAR || hi > current_year {
        return Err(format!(
            "CCADB years must be between {FIRST_CCADB_YEAR} and {current_year}"
        ));
    }
    Ok((lo, hi))
}

/// Bypasses certificate and handshake-signature verification for inspection only.
/// A successful connection must not be treated as authenticated server identity.
#[derive(Debug)]
struct AcceptAny(Arc<rustls::crypto::CryptoProvider>);

impl ServerCertVerifier for AcceptAny {
    fn verify_server_cert(
        &self,
        _: &CertificateDer<'_>,
        _: &[CertificateDer<'_>],
        _: &ServerName<'_>,
        _: &[u8],
        _: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }
    fn verify_tls12_signature(
        &self,
        _: &[u8],
        _: &CertificateDer<'_>,
        _: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }
    fn verify_tls13_signature(
        &self,
        _: &[u8],
        _: &CertificateDer<'_>,
        _: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }
    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.0.signature_verification_algorithms.supported_schemes()
    }
}

fn is_url(s: &str) -> bool {
    s.starts_with("https://") || s.starts_with("tls://")
}

/// Performs a TLS handshake and returns the DER of every certificate the server presents (leaf first).
fn fetch_chain(raw: &str) -> Result<Vec<Vec<u8>>, String> {
    let url = url::Url::parse(raw).map_err(|e| format!("invalid URL: {e}"))?;
    let host = match url.host().ok_or("URL has no host")? {
        url::Host::Domain(name) => name.to_string(),
        url::Host::Ipv4(addr) => addr.to_string(),
        url::Host::Ipv6(addr) => addr.to_string(),
    };
    let port = url.port().unwrap_or(443);

    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let config = rustls::ClientConfig::builder_with_provider(provider.clone())
        .with_safe_default_protocol_versions()
        .map_err(|e| format!("TLS config error: {e}"))?
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(AcceptAny(provider)))
        .with_no_client_auth();

    let name =
        ServerName::try_from(host.clone()).map_err(|e| format!("invalid host '{host}': {e}"))?;
    let mut conn = rustls::ClientConnection::new(Arc::new(config), name)
        .map_err(|e| format!("TLS error: {e}"))?;

    let timeout = Duration::from_secs(10);
    let addresses = (host.as_str(), port)
        .to_socket_addrs()
        .map_err(|e| format!("cannot resolve {host}: {e}"))?;
    let mut last_error = format!("no address for {host}");
    let mut socket = None;
    for addr in addresses {
        match TcpStream::connect_timeout(&addr, timeout) {
            Ok(sock) => {
                socket = Some(sock);
                break;
            }
            Err(e) => last_error = format!("cannot connect to {host}:{port}: {e}"),
        }
    }
    let mut sock = socket.ok_or(last_error)?;
    sock.set_read_timeout(Some(timeout))
        .map_err(|e| format!("cannot set read timeout: {e}"))?;
    sock.set_write_timeout(Some(timeout))
        .map_err(|e| format!("cannot set write timeout: {e}"))?;

    while conn.is_handshaking() {
        conn.complete_io(&mut sock)
            .map_err(|e| format!("TLS handshake with {host}:{port} failed: {e}"))?;
    }
    let chain: Vec<Vec<u8>> = conn
        .peer_certificates()
        .unwrap_or_default()
        .iter()
        .map(|c| c.as_ref().to_vec())
        .collect();
    if chain.is_empty() {
        return Err("server presented no certificate".into());
    }
    Ok(chain)
}

/// Reads a CSV file; see `parse_csv`.
fn read_csv(path: &PathBuf, column: Option<&str>) -> Result<Vec<(String, Vec<u8>)>, String> {
    let rdr = csv::ReaderBuilder::new()
        .from_path(path)
        .map_err(|e| format!("cannot read {}: {e}", path.display()))?;
    let rows = parse_csv(rdr, column)?;
    if rows.is_empty() {
        return Err("CSV contains no keys or certificates".into());
    }
    Ok(rows)
}

/// Returns (row tag, PEM bytes) for each non-empty value in the key column.
/// Prefer public-key and PEM headers over a generic "certificate" column.
fn parse_csv<R: Read>(
    mut rdr: csv::Reader<R>,
    column: Option<&str>,
) -> Result<Vec<(String, Vec<u8>)>, String> {
    let headers = rdr
        .headers()
        .map_err(|e| format!("bad CSV header: {e}"))?
        .clone();
    let find =
        |pred: &dyn Fn(&str) -> bool| headers.iter().position(|h| pred(&h.trim().to_lowercase()));
    let col = match column {
        Some(c) => find(&|h| h == c.trim().to_lowercase()),
        None => find(&|h| h.contains("public key"))
            .or_else(|| find(&|h| h.contains("pem")))
            .or_else(|| find(&|h| h == "certificate")),
    }
    .ok_or_else(|| {
        format!(
            "no public key/certificate column found (headers: {})",
            headers.iter().collect::<Vec<_>>().join(", ")
        )
    })?;
    let name_cols: Vec<usize> = ["ca owner", "certificate name", "sha-256 fingerprint"]
        .iter()
        .filter_map(|n| find(&|h| h == *n))
        .collect();

    let mut rows = Vec::new();
    for (i, rec) in rdr.records().enumerate() {
        let rec = rec.map_err(|e| format!("bad CSV row {}: {e}", i + 2))?;
        let value = rec
            .get(col)
            .ok_or_else(|| format!("CSV row {} is missing the key column", i + 2))?
            .trim();
        if value.is_empty() {
            continue;
        }
        let names: Vec<&str> = name_cols.iter().filter_map(|&c| rec.get(c)).collect();
        let tag = format!("row {} {}", i + 2, names.join("/"))
            .trim()
            .to_string();
        rows.push((tag, value.as_bytes().to_vec()));
    }
    Ok(rows)
}

fn read_input(path: &Option<PathBuf>) -> Result<Vec<u8>, String> {
    let mut buf = Vec::new();
    match path {
        Some(p) if p.as_os_str() != "-" => {
            buf = std::fs::read(p).map_err(|e| format!("cannot read {}: {e}", p.display()))?
        }
        _ => {
            std::io::stdin()
                .read_to_end(&mut buf)
                .map_err(|e| format!("cannot read stdin: {e}"))?;
        }
    }
    if buf.is_empty() {
        return Err("input is empty".into());
    }
    Ok(buf)
}

fn decode_input(data: &[u8]) -> Result<Vec<u8>, String> {
    if data.trim_ascii_start().starts_with(b"-----BEGIN") {
        // CCADB can wrap valid Base64 at inconsistent widths. Rewrap the body
        // without relaxing the decoder's boundary or Base64 validation.
        let mut lines = data
            .trim_ascii()
            .split(|&byte| matches!(byte, b'\r' | b'\n'));
        let header = lines
            .next()
            .ok_or("invalid PEM: missing beginning boundary")?;
        let footer = lines
            .next_back()
            .ok_or("invalid PEM: missing ending boundary")?;
        let body: Vec<u8> = lines
            .flatten()
            .copied()
            .filter(|byte| !byte.is_ascii_whitespace())
            .collect();
        let mut normalized = Vec::with_capacity(data.len());
        normalized.extend_from_slice(header);
        normalized.push(b'\n');
        for chunk in body.chunks(64) {
            normalized.extend_from_slice(chunk);
            normalized.push(b'\n');
        }
        normalized.extend_from_slice(footer);
        let (label, der) =
            pem_rfc7468::decode_vec(&normalized).map_err(|e| format!("invalid PEM: {e}"))?;
        if !matches!(label, "CERTIFICATE" | "PUBLIC KEY" | "TRUSTED CERTIFICATE") {
            return Err(format!("unsupported PEM label '{label}'"));
        }
        Ok(der)
    } else {
        Ok(data.to_vec())
    }
}

fn parse_certificate(der_bytes: &[u8]) -> Result<(SubjectPublicKeyInfoOwned, String), String> {
    match Certificate::from_der(der_bytes) {
        Ok(cert) => {
            let tbs = cert.tbs_certificate();
            return Ok((
                tbs.subject_public_key_info().clone(),
                format!("subject \"{}\"", tbs.subject()),
            ));
        }
        Err(error)
            if matches!(
                error.kind(),
                der::ErrorKind::Value {
                    tag: der::Tag::UtcTime | der::Tag::GeneralizedTime
                }
            ) => {}
        Err(error) => return Err(error.to_string()),
    }

    // Some legacy certificates use timezone offsets forbidden by RFC 5280.
    // Inspect them with OpenSSL without rewriting the signed DER or CT fingerprint.
    // OpenSSL's decoder accepts trailing data, so check the outer DER boundary first.
    der::asn1::AnyRef::from_der(der_bytes).map_err(|e| e.to_string())?;
    let cert = openssl::x509::X509::from_der(der_bytes).map_err(|e| e.to_string())?;
    for time in [cert.not_before(), cert.not_after()] {
        // Decoding an ASN.1 time string alone does not validate its calendar fields.
        time.diff(time)
            .map_err(|e| format!("invalid certificate validity time: {e}"))?;
    }
    let key_der = cert
        .public_key()
        .and_then(|key| key.public_key_to_der())
        .map_err(|e| format!("cannot extract certificate public key: {e}"))?;
    let spki = SubjectPublicKeyInfoOwned::from_der(&key_der).map_err(|e| e.to_string())?;
    Ok((spki, format!("subject {:?}", cert.subject_name())))
}

fn parse_spki(data: &[u8]) -> Result<(SubjectPublicKeyInfoOwned, String), String> {
    let der_bytes = decode_input(data)?;
    let certificate_error = match parse_certificate(&der_bytes) {
        Ok(parsed) => return Ok(parsed),
        Err(error) => error,
    };
    SubjectPublicKeyInfoOwned::from_der(&der_bytes)
        .map(|s| (s, "public key".to_string()))
        .map_err(|e| {
            format!(
                "input is neither a valid X.509 certificate nor a SubjectPublicKeyInfo \
                 (certificate: {certificate_error}; public key: {e})"
            )
        })
}

/// Splits the range across threads; each walks its chunk by repeated point addition.
macro_rules! search_curve {
    ($krate:ident, $point:expr, $lo:expr, $hi:expr, $threads:expr, $found:expr, $done:expr) => {{
        use $krate::{ProjectivePoint, PublicKey, Scalar};

        let target: ProjectivePoint = PublicKey::from_sec1_bytes($point)
            .map_err(|e| format!("invalid EC public key point: {e}"))?
            .to_projective();

        // Scalar 0 is the identity and never a valid private key.
        let lo: u64 = $lo.max(1);
        let hi: u64 = $hi;
        if lo <= hi {
            let total = hi - lo + 1;
            let n = ($threads as u64).min(total);
            let found: &AtomicU64 = $found;
            let done: &AtomicBool = $done;

            thread::scope(|s| {
                for i in 0..n {
                    let (start, end) = range_chunk(lo, hi, n, i);
                    s.spawn(move || {
                        let g = ProjectivePoint::GENERATOR;
                        let mut cur = g * Scalar::from(start);
                        let mut k = start;
                        loop {
                            if done.load(Ordering::Relaxed) {
                                return;
                            }
                            if cur == target {
                                found.store(k, Ordering::SeqCst);
                                done.store(true, Ordering::SeqCst);
                                return;
                            }
                            if k == end {
                                return;
                            }
                            cur += g;
                            k += 1;
                        }
                    });
                }
            });
        }
        Ok::<(), String>(())
    }};
}

fn range_chunk(lo: u64, hi: u64, workers: u64, index: u64) -> (u64, u64) {
    let total = hi - lo + 1;
    let size = total / workers;
    let remainder = total % workers;
    // Callers exclude zero and require 1 <= workers <= total, index < workers.
    // Distributing the remainder avoids ceiling-based chunk overflow near u64::MAX.
    let start = lo + index * size + index.min(remainder);
    let len = size + u64::from(index < remainder);
    (start, start + (len - 1))
}

fn year_from_unix_seconds(seconds: u64) -> u64 {
    // Count whole UTC calendar years; an average year length misclassifies New Year.
    let mut days = seconds / 86_400;
    let mut year = 1970;
    loop {
        let leap = year % 4 == 0 && (year % 100 != 0 || year % 400 == 0);
        let length = if leap { 366 } else { 365 };
        if days < length {
            return year;
        }
        days -= length;
        year += 1;
    }
}

fn run() -> Result<bool, String> {
    let cli = Cli::parse();
    let (lo, hi) = parse_range(&cli.range)?;
    let threads = cli
        .threads
        .map(|n| n.get())
        .or_else(|| thread::available_parallelism().ok().map(|n| n.get()))
        .unwrap_or(1);

    let mut out = std::io::stdout();

    if cli.check_ccadb {
        let this_year = year_from_unix_seconds(
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_err(|e| e.to_string())?
                .as_secs(),
        );
        let (first_year, last_year) = match &cli.year {
            Some(years) => parse_years(years, this_year)?,
            None => (FIRST_CCADB_YEAR, this_year),
        };
        let mut any_found = false;
        let mut failures = 0;
        for year in first_year..=last_year {
            eprintln!("Downloading CCADB certificates valid from {year}...");
            let rows = match fetch_ccadb_year(year) {
                Ok(rows) => rows,
                Err(e) => {
                    eprintln!("error: {year}: {e}");
                    failures += 1;
                    continue;
                }
            };
            eprintln!("Checking {} certificates from {year}", rows.len());
            let rows: Vec<_> = rows
                .into_iter()
                .map(|(t, d)| (format!("{year} {t}"), d))
                .collect();
            any_found |= check_inputs(&rows, true, &cli, lo, hi, threads, &mut out)?;
        }
        if failures > 0 {
            return Err(format!("{failures} CCADB year(s) failed to download"));
        }
        return Ok(any_found);
    }

    let url = cli.path.as_ref().map(|p| p.to_string_lossy().into_owned());
    let is_csv = cli
        .path
        .as_ref()
        .is_some_and(|p| p.extension().is_some_and(|e| e.eq_ignore_ascii_case("csv")));
    let inputs: Vec<(String, Vec<u8>)> = if let Some(u) = url.as_deref().filter(|u| is_url(u)) {
        let mut chain = fetch_chain(u)?;
        if cli.leaf_only {
            chain.truncate(1);
        }
        chain
            .into_iter()
            .enumerate()
            .map(|(i, c)| (i.to_string(), c))
            .collect()
    } else if is_csv {
        read_csv(cli.path.as_ref().unwrap(), cli.column.as_deref())?
    } else {
        vec![(String::new(), read_input(&cli.path)?)]
    };
    let multi = is_csv || url.as_deref().is_some_and(is_url);
    check_inputs(&inputs, multi, &cli, lo, hi, threads, &mut out)
}

/// Downloads the CCADB "All Certificate PEMs" report for certificates valid from `year`.
fn fetch_ccadb_year(year: u64) -> Result<Vec<(String, Vec<u8>)>, String> {
    let url = format!(
        "https://ccadb.my.salesforce-sites.com/ccadb/AllCertificatePEMsCSVFormat?NotBeforeYear={year}"
    );
    let mut resp = ureq::get(&url)
        .call()
        .map_err(|e| format!("download failed: {e}"))?;
    let body = resp
        .body_mut()
        .with_config()
        .limit(1 << 30)
        .read_to_vec()
        .map_err(|e| format!("download failed: {e}"))?;
    let rdr = csv::ReaderBuilder::new().from_reader(body.as_slice());
    parse_csv(rdr, None)
}

/// Checks each input and prints results; returns true if any private key was found.
/// Input and enrichment errors take precedence over findings in the exit status.
fn check_inputs(
    inputs: &[(String, Vec<u8>)],
    multi: bool,
    cli: &Cli,
    lo: u64,
    hi: u64,
    threads: usize,
    out: &mut impl Write,
) -> Result<bool, String> {
    let mut any_found = false;
    let mut failures = 0;
    let mut ct_lookup = None;
    let output_error = |e| format!("cannot write results: {e}");
    for (name_tag, data) in inputs.iter() {
        let prefix = if multi {
            format!("[{name_tag}] ")
        } else {
            String::new()
        };
        let result = parse_spki(data).and_then(|(spki, label)| {
            check_key(&spki, lo, hi, threads).map(|result| (spki, label, result))
        });
        let write_result = match result {
            Ok((spki, label, KeyCheck::Supported(name, Some(k)))) => {
                any_found = true;
                writeln!(
                    out,
                    "{prefix}VULNERABLE: {label}: {name} private key is {k} (0x{k:x})"
                )
                .map_err(output_error)?;
                if cli.ct_details {
                    // Initialize lazily so clean keys never read CT credentials or query
                    // the service, and enrichment failures cannot hide this finding.
                    let result = match ct_lookup.get_or_insert_with(ct::Lookup::new) {
                        Ok(lookup) => lookup.details(data, &spki),
                        Err(e) => Err(e.clone()),
                    };
                    match result {
                        Ok((query, details)) => {
                            ct::write_details(out, &prefix, &query, details)
                                .map_err(output_error)?;
                        }
                        Err(e) => {
                            eprintln!("error: {prefix}CT lookup: {e}");
                            failures += 1;
                        }
                    }
                }
                Ok(())
            }
            Ok((_, label, KeyCheck::Supported(name, None))) => {
                if !cli.quiet {
                    writeln!(
                        out,
                        "{prefix}OK: {label}: {name} private key not in range {lo}-{hi} ({threads} threads)"
                    )
                } else {
                    Ok(())
                }
            }
            Ok((_, _, KeyCheck::Unsupported(reason))) => {
                if !cli.quiet {
                    writeln!(out, "{prefix}SKIP: {reason}")
                } else {
                    Ok(())
                }
            }
            Err(e) => {
                eprintln!("error: {prefix}{e}");
                failures += 1;
                Ok(())
            }
        };
        write_result.map_err(output_error)?;
    }
    if failures > 0 {
        return Err(format!("{failures} input(s) could not be fully processed"));
    }
    Ok(any_found)
}

#[derive(Debug, PartialEq)]
enum KeyCheck {
    Supported(&'static str, Option<u64>),
    Unsupported(String),
}

/// Returns the curve name and the private key if one in range matches.
fn check_key(
    spki: &SubjectPublicKeyInfoOwned,
    lo: u64,
    hi: u64,
    threads: usize,
) -> Result<KeyCheck, String> {
    if spki.algorithm.oid != OID_EC {
        return Ok(KeyCheck::Unsupported(format!(
            "not an EC public key (algorithm OID {})",
            spki.algorithm.oid
        )));
    }
    let curve: ObjectIdentifier = spki
        .algorithm
        .parameters
        .as_ref()
        .ok_or("missing EC curve parameters (implicit curves unsupported)")?
        .decode_as()
        .map_err(|_| "unsupported EC parameters (only named curves are supported)")?;
    let point = spki
        .subject_public_key
        .as_bytes()
        .ok_or("malformed public key bit string")?;

    if let Some(curve) = curves::CURVES
        .iter()
        .find(|candidate| candidate.oid == curve)
    {
        return curves::search(curve, point, lo, hi, threads)
            .map(|hit| KeyCheck::Supported(curve.name, hit));
    }

    let found = AtomicU64::new(0);
    let done = AtomicBool::new(false);
    let name = match curve {
        c if c == OID_P256 => {
            search_curve!(p256, point, lo, hi, threads, &found, &done)?;
            "P-256 (secp256r1)"
        }
        c if c == OID_P384 => {
            search_curve!(p384, point, lo, hi, threads, &found, &done)?;
            "P-384 (secp384r1)"
        }
        c if c == OID_P521 => {
            search_curve!(p521, point, lo, hi, threads, &found, &done)?;
            "P-521 (secp521r1)"
        }
        c if c == OID_K256 => {
            search_curve!(k256, point, lo, hi, threads, &found, &done)?;
            "secp256k1"
        }
        other => {
            return Ok(KeyCheck::Unsupported(format!(
                "unsupported curve OID {other}"
            )));
        }
    };
    let hit = done
        .load(Ordering::SeqCst)
        .then(|| found.load(Ordering::SeqCst));
    Ok(KeyCheck::Supported(name, hit))
}

fn main() -> ExitCode {
    match run() {
        Ok(true) => ExitCode::from(1),
        Ok(false) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("error: {e}");
            ExitCode::from(2)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use der::Encode;

    // Self-signed fixture with private scalar 1; expiry is intentionally irrelevant.
    pub(crate) const TEST_CERT: &str = "-----BEGIN CERTIFICATE-----
MIIBIDCBx6ADAgECAgkAkiUNcG4tpGYwCgYIKoZIzj0EAwIwFjEUMBIGA1UEAxML
bG93a2V5LXRlc3QwHhcNMjYxMDIwMDE0NTM0WhcNMjYxMDIyMDE0NTM0WjAWMRQw
EgYDVQQDEwtsb3drZXktdGVzdDBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABGsX
0fLhLEJH+Lzm5WOkQPJ3A32BLeszoPShOUXYmMKWT+NC4v4af5uO5+tKfA+eFivO
M1drMV7Oy7ZAaDe/UfUwCgYIKoZIzj0EAwIDSAAwRQIhAOkjflZQLH7dm9kcurXL
sJyR09Wh0yXr7WYkcopKzy0MAiBIJqutak0nf1RYV2kL7bIcLS6QKbWQlSIt23hC
BQXfGg==
-----END CERTIFICATE-----";

    pub(crate) fn ec_spki(curve: ObjectIdentifier, point: &[u8]) -> SubjectPublicKeyInfoOwned {
        SubjectPublicKeyInfoOwned {
            algorithm: spki::AlgorithmIdentifierOwned {
                oid: OID_EC,
                parameters: Some(der::asn1::Any::from_der(&curve.to_der().unwrap()).unwrap()),
            },
            subject_public_key: der::asn1::BitString::from_bytes(point).unwrap(),
        }
    }

    fn p256_spki(value: u64) -> SubjectPublicKeyInfoOwned {
        let point = p256::ProjectivePoint::GENERATOR * p256::Scalar::from(value);
        let key = p256::PublicKey::from_affine(point.to_affine()).unwrap();
        ec_spki(OID_P256, &key.to_sec1_bytes())
    }

    #[test]
    fn ranges_validate_bounds() {
        assert_eq!(parse_range(" 4 - 9 ").unwrap(), (4, 9));
        assert_eq!(parse_range("5").unwrap(), (0, 5));
        assert_eq!(parse_range(&u64::MAX.to_string()).unwrap(), (0, u64::MAX));
        for invalid in ["", "-1", "4-3", "1-2-3", "18446744073709551616"] {
            assert!(parse_range(invalid).is_err(), "{invalid}");
        }
    }

    #[test]
    fn parses_ccadb_years_and_open_ranges() {
        for (input, expected) in [
            ("2020", (2020, 2020)),
            ("2005-2010", (2005, 2010)),
            ("-2010", (1999, 2010)),
            ("2015-", (2015, 2026)),
            (" 2005 - 2010 ", (2005, 2010)),
            ("1999", (1999, 1999)),
            ("2026-", (2026, 2026)),
        ] {
            assert_eq!(parse_years(input, 2026).unwrap(), expected, "{input}");
        }
        for invalid in [
            "",
            "-",
            "2000-1999",
            "1998",
            "-1998",
            "2027",
            "2027-",
            "2000-2027",
            "2000-2001-2002",
            "year",
            "18446744073709551616",
        ] {
            assert!(parse_years(invalid, 2026).is_err(), "{invalid}");
        }
    }

    #[test]
    fn year_option_requires_ccadb_and_accepts_leading_hyphen() {
        assert!(Cli::try_parse_from(["lowkey-check", "--year", "2020"]).is_err());
        for years in ["2020", "2005-2010", "-2010", "2015-"] {
            let cli =
                Cli::try_parse_from(["lowkey-check", "--check-ccadb", "--year", years]).unwrap();
            assert_eq!(cli.year.as_deref(), Some(years));
        }
    }
    #[test]
    fn chunks_cover_range_without_overflow() {
        for (lo, hi, workers) in [(1, 10, 3), (1, u64::MAX, 2), (u64::MAX - 8, u64::MAX, 5)] {
            let mut next = lo;
            for index in 0..workers {
                let (start, end) = range_chunk(lo, hi, workers, index);
                assert_eq!(start, next);
                assert!(start <= end && end <= hi);
                if index + 1 == workers {
                    assert_eq!(end, hi);
                } else {
                    next = end + 1;
                }
            }
        }
    }

    #[test]
    fn searches_all_supported_curves() {
        macro_rules! check_curve {
            ($krate:ident, $oid:expr) => {{
                let point = $krate::ProjectivePoint::GENERATOR * $krate::Scalar::from(7u64);
                let key = $krate::PublicKey::from_affine(point.to_affine()).unwrap();
                let spki = ec_spki($oid, &key.to_sec1_bytes());
                for threads in [1, 3, 20] {
                    assert!(matches!(
                        check_key(&spki, 0, 7, threads).unwrap(),
                        KeyCheck::Supported(_, Some(7))
                    ));
                    assert!(matches!(
                        check_key(&spki, 8, 10, threads).unwrap(),
                        KeyCheck::Supported(_, None)
                    ));
                }
            }};
        }
        check_curve!(p256, OID_P256);
        check_curve!(p384, OID_P384);
        check_curve!(p521, OID_P521);
        check_curve!(k256, OID_K256);
    }

    #[test]
    fn search_handles_zero_and_maximum_scalar() {
        assert!(matches!(
            check_key(&p256_spki(1), 0, 0, 1).unwrap(),
            KeyCheck::Supported(_, None)
        ));
        assert!(matches!(
            check_key(&p256_spki(u64::MAX), u64::MAX - 3, u64::MAX, 3).unwrap(),
            KeyCheck::Supported(_, Some(u64::MAX))
        ));
    }

    #[test]
    fn parses_pem_and_der_spki() {
        let spki = p256_spki(7);
        let der = spki.to_der().unwrap();
        assert_eq!(parse_spki(&der).unwrap().0, spki);
        let pem =
            pem_rfc7468::encode_string("PUBLIC KEY", pem_rfc7468::LineEnding::LF, &der).unwrap();
        assert_eq!(parse_spki(pem.as_bytes()).unwrap().0, spki);
        assert!(parse_spki(b"not a key").is_err());
    }

    #[test]
    fn parses_pem_and_der_certificates() {
        let (_, der) = pem_rfc7468::decode_vec(TEST_CERT.as_bytes()).unwrap();
        for input in [TEST_CERT.as_bytes(), der.as_slice()] {
            let (spki, label) = parse_spki(input).unwrap();
            assert_eq!(spki, p256_spki(1));
            assert!(label.contains("lowkey-test"));
        }
    }

    #[test]
    fn parses_legacy_ccadb_certificate() {
        // SecureNet CA Class B from CCADB's 1999 report uses +1000 validity offsets.
        let pem = include_bytes!("../tests/fixtures/securenet-class-b.pem");
        let der = decode_input(pem).unwrap();
        assert!(matches!(
            Certificate::from_der(&der).unwrap_err().kind(),
            der::ErrorKind::Value {
                tag: der::Tag::UtcTime
            }
        ));
        for input in [pem.as_slice(), der.as_slice()] {
            let (spki, label) = parse_spki(input).unwrap();
            assert_eq!(
                spki.algorithm.oid,
                ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.1")
            );
            assert!(label.contains("SecureNet CA Class B"));
            assert!(matches!(
                check_key(&spki, 0, 0, 1).unwrap(),
                KeyCheck::Unsupported(_)
            ));
        }
    }

    #[test]
    fn legacy_certificate_parsing_rejects_invalid_input() {
        let der = decode_input(include_bytes!("../tests/fixtures/securenet-class-b.pem")).unwrap();
        let mut trailing = der.clone();
        trailing.push(0);
        assert!(parse_spki(&trailing).is_err());
        assert!(parse_spki(&der[..der.len() - 1]).is_err());

        for time in [b"990630000000+1000", b"091015235900+1000"] {
            let mut invalid = der.clone();
            let start = invalid.windows(time.len()).position(|w| w == time).unwrap();
            invalid[start + 13..start + 17].copy_from_slice(b"9960");
            assert!(parse_spki(&invalid).is_err());
        }
    }

    #[test]
    fn accepts_ccadb_irregular_base64_wrapping() {
        let (_, cert_der) = pem_rfc7468::decode_vec(TEST_CERT.as_bytes()).unwrap();
        for (label, der) in [
            ("CERTIFICATE", cert_der),
            ("PUBLIC KEY", p256_spki(7).to_der().unwrap()),
        ] {
            let base64 = openssl::base64::encode_block(&der);
            let mut pem = format!("-----BEGIN {label}-----\n{}\n", &base64[..65]);
            for chunk in base64.as_bytes()[65..].chunks(64) {
                pem.push_str(std::str::from_utf8(chunk).unwrap());
                pem.push('\n');
            }
            pem.push_str(&format!("-----END {label}-----"));
            assert!(pem_rfc7468::decode_vec(pem.as_bytes()).is_err());
            assert_eq!(decode_input(pem.as_bytes()).unwrap(), der);
            assert_eq!(
                parse_spki(pem.as_bytes()).unwrap().0,
                parse_spki(&der).unwrap().0
            );

            let mut writer = csv::Writer::from_writer(Vec::new());
            writer.write_record(["X.509 Certificate (PEM)"]).unwrap();
            writer.write_record([&pem]).unwrap();
            let csv = writer.into_inner().unwrap();
            let rows = parse_csv(csv::Reader::from_reader(csv.as_slice()), None).unwrap();
            assert_eq!(decode_input(&rows[0].1).unwrap(), der);
        }
    }

    #[test]
    fn accepts_pem_body_whitespace_and_line_endings() {
        let (_, der) = pem_rfc7468::decode_vec(TEST_CERT.as_bytes()).unwrap();
        let base64 = openssl::base64::encode_block(&der);
        for ending in ["\n", "\r\n", "\r"] {
            for width in [1, 37, 64, 65, base64.len()] {
                let mut pem = format!("-----BEGIN CERTIFICATE-----{ending}");
                for chunk in base64.as_bytes().chunks(width) {
                    pem.push_str("\t ");
                    pem.push_str(std::str::from_utf8(chunk).unwrap());
                    pem.push_str(" \t");
                    pem.push_str(ending);
                }
                pem.push_str(&format!("-----END CERTIFICATE-----{ending}"));
                assert_eq!(decode_input(pem.as_bytes()).unwrap(), der);
            }
        }
    }

    #[test]
    fn pem_normalization_does_not_hide_invalid_input() {
        for invalid in [
            TEST_CERT.replace("END CERTIFICATE", "END PUBLIC KEY"),
            TEST_CERT.replace("-----END CERTIFICATE-----", ""),
            TEST_CERT.replace("MIIBID", "MI!BID"),
            format!("{TEST_CERT}\n{TEST_CERT}"),
            format!("{TEST_CERT}\nunexpected trailing data"),
            "-----BEGIN CERTIFICATE-----\n-----END CERTIFICATE-----".to_string(),
            TEST_CERT.replace("CERTIFICATE", "PRIVATE KEY"),
        ] {
            assert!(parse_spki(invalid.as_bytes()).is_err(), "{invalid}");
        }
    }

    #[test]
    fn fetches_local_tls_certificates_over_ipv4_and_ipv6() {
        use rustls_pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer};
        use std::io::ErrorKind;
        use std::net::TcpListener;
        use std::time::Instant;

        let key = "-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAGhRANCAARrF9Hy4SxCR/i85uVjpEDydwN9gS3r
M6D0oTlF2JjClk/jQuL+Gn+bjufrSnwPnhYrzjNXazFezsu2QGg3v1H1
-----END PRIVATE KEY-----";
        let (_, key_der) = pem_rfc7468::decode_vec(key.as_bytes()).unwrap();
        let (_, cert_der) = pem_rfc7468::decode_vec(TEST_CERT.as_bytes()).unwrap();
        let config = rustls::ServerConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(
            vec![CertificateDer::from(cert_der.clone())],
            PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key_der)),
        )
        .unwrap();
        let config = Arc::new(config);
        for host in ["127.0.0.1", "::1"] {
            for scheme in ["https", "tls"] {
                let listener = match TcpListener::bind((host, 0)) {
                    Ok(listener) => listener,
                    Err(e) if host == "::1" && e.kind() == ErrorKind::AddrNotAvailable => {
                        eprintln!("IPv6 loopback unavailable: {e}");
                        continue;
                    }
                    Err(e) => panic!("cannot bind loopback: {e}"),
                };
                let address = listener.local_addr().unwrap();
                listener.set_nonblocking(true).unwrap();
                let config = config.clone();
                let server = thread::spawn(move || {
                    let deadline = Instant::now() + Duration::from_secs(5);
                    let mut socket = loop {
                        match listener.accept() {
                            Ok((socket, _)) => break socket,
                            Err(e) if e.kind() == ErrorKind::WouldBlock => {
                                assert!(Instant::now() < deadline, "client never connected");
                                thread::sleep(Duration::from_millis(10));
                            }
                            Err(e) => panic!("cannot accept connection: {e}"),
                        }
                    };
                    socket.set_nonblocking(false).unwrap();
                    socket
                        .set_read_timeout(Some(Duration::from_secs(5)))
                        .unwrap();
                    socket
                        .set_write_timeout(Some(Duration::from_secs(5)))
                        .unwrap();
                    let mut conn = rustls::ServerConnection::new(config).unwrap();
                    while conn.is_handshaking() {
                        conn.complete_io(&mut socket).unwrap();
                    }
                });
                let chain = fetch_chain(&format!("{scheme}://{address}"));
                server.join().unwrap();
                assert_eq!(chain.unwrap(), vec![cert_der.clone()]);
            }
        }
    }

    #[test]
    fn csv_prefers_key_data_and_rejects_bad_rows() {
        let csv = b"Certificate Serial Number, Certificate , Public Key \n123,cert,key\n";
        let rows = parse_csv(csv::Reader::from_reader(csv.as_slice()), None).unwrap();
        assert_eq!(rows[0].1, b"key");
        let rows = parse_csv(
            csv::Reader::from_reader(csv.as_slice()),
            Some(" CERTIFICATE "),
        )
        .unwrap();
        assert_eq!(rows[0].1, b"cert");
        let short = b"Name,PEM\nonly-name\n";
        assert!(parse_csv(csv::Reader::from_reader(short.as_slice()), None).is_err());
        let metadata = b"Certificate Serial Number\n123\n";
        assert!(parse_csv(csv::Reader::from_reader(metadata.as_slice()), None).is_err());
        let empty = b"PEM\n";
        assert!(
            parse_csv(csv::Reader::from_reader(empty.as_slice()), None)
                .unwrap()
                .is_empty()
        );
    }

    #[test]
    fn batch_errors_are_not_successful_skips() {
        let cli = Cli::try_parse_from(["lowkey-check", "--quiet"]).unwrap();
        let rows = vec![
            ("broken".into(), b"invalid".to_vec()),
            ("valid".into(), p256_spki(1).to_der().unwrap()),
        ];
        let mut output = Vec::new();
        assert!(check_inputs(&rows, true, &cli, 1, 1, 1, &mut output).is_err());
        assert!(
            String::from_utf8(output)
                .unwrap()
                .contains("[valid] VULNERABLE")
        );
    }

    #[test]
    fn unsupported_keys_skip_even_for_single_input() {
        let mut spki = p256_spki(1);
        spki.algorithm.oid = ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.1");
        let cli = Cli::try_parse_from(["lowkey-check"]).unwrap();
        let mut output = Vec::new();
        assert!(
            !check_inputs(
                &[(String::new(), spki.to_der().unwrap())],
                false,
                &cli,
                1,
                1,
                1,
                &mut output
            )
            .unwrap()
        );
        assert!(String::from_utf8(output).unwrap().starts_with("SKIP:"));
        assert!(check_key(&ec_spki(OID_P256, &[0]), 1, 1, 1).is_err());
    }

    #[test]
    fn output_errors_are_reported() {
        struct FailingWriter;
        impl Write for FailingWriter {
            fn write(&mut self, _: &[u8]) -> std::io::Result<usize> {
                Err(std::io::Error::other("output failed"))
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }
        let cli = Cli::try_parse_from(["lowkey-check"]).unwrap();
        let rows = vec![(String::new(), p256_spki(1).to_der().unwrap())];
        let error = check_inputs(&rows, false, &cli, 1, 1, 1, &mut FailingWriter).unwrap_err();
        assert!(error.contains("cannot write results"));
    }

    #[test]
    fn rejects_zero_threads() {
        assert!(Cli::try_parse_from(["lowkey-check", "--threads", "0"]).is_err());
    }

    #[test]
    fn calendar_year_changes_on_january_first() {
        assert_eq!(year_from_unix_seconds(0), 1970);
        assert_eq!(year_from_unix_seconds(1_767_225_599), 2025);
        assert_eq!(year_from_unix_seconds(1_767_225_600), 2026);
        assert_eq!(year_from_unix_seconds(951_782_400), 2000);
    }
}
