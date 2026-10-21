//! Opt-in CT enrichment: queries disclose fingerprints, never recovered scalars.
//! Returned index metadata is not a verified certificate inclusion proof.

use std::collections::{HashMap, HashSet};
use std::io::Write;
use std::time::Duration;

use der::{Decode, Encode};
use serde::Deserialize;
use spki::SubjectPublicKeyInfoOwned;
use url::Url;
use x509_cert::Certificate;

const ENDPOINT: &str = "https://api.ctlogs.dev/";
const BODY_LIMIT: u64 = 8 * 1024 * 1024;
const PAGE_LIMIT: usize = 10;

#[derive(Debug, Deserialize)]
pub(crate) struct CertificateDetails {
    id: String,
    // Search rows and full records use different names for equivalent fields.
    #[serde(alias = "issuer")]
    issuer_dn: Option<String>,
    #[serde(alias = "match")]
    subject_cn: Option<String>,
    subject_dn: Option<String>,
    san_dns: Option<Vec<String>>,
    not_before: Option<String>,
    not_after: Option<String>,
    serial_hex: Option<String>,
    pubkey_sha256: Option<String>,
    sightings: Option<Vec<Sighting>>,
}

#[derive(Debug, Deserialize)]
struct Sighting {
    log_url: String,
    operator: String,
    entry_idx: u64,
    sct_ts: String,
    is_precert: bool,
}

#[derive(Deserialize)]
struct Page {
    rows: Vec<CertificateDetails>,
    has_next: bool,
    next_cursor: String,
    truncated: Option<bool>,
}

#[derive(Debug)]
pub(crate) struct Details {
    certificates: Vec<CertificateDetails>,
    truncated: bool,
}

#[derive(Clone, Debug, Hash, Eq, PartialEq)]
pub(crate) enum Query {
    Certificate(String),
    Spki(String),
}

impl Query {
    fn kind(&self) -> &'static str {
        match self {
            Self::Certificate(_) => "certificate",
            Self::Spki(_) => "SPKI",
        }
    }

    fn hash(&self) -> &str {
        match self {
            Self::Certificate(hash) | Self::Spki(hash) => hash,
        }
    }
}

pub(crate) struct Lookup {
    agent: ureq::Agent,
    endpoint: Url,
    api_key: Option<String>,
    // Repeated inputs must not retry the same failure or consume extra API quota.
    cache: HashMap<Query, Result<Details, String>>,
}

impl Lookup {
    pub(crate) fn new() -> Result<Self, String> {
        let key = match std::env::var("CTLOGS_API_KEY") {
            Ok(key) if !key.is_empty() && key.bytes().all(|b| b.is_ascii_graphic()) => Some(key),
            Ok(_) => return Err("CTLOGS_API_KEY must be a non-empty ASCII token".into()),
            Err(std::env::VarError::NotPresent) => None,
            Err(std::env::VarError::NotUnicode(_)) => {
                return Err("CTLOGS_API_KEY is not valid Unicode".into());
            }
        };
        Ok(Self::at(
            Url::parse(ENDPOINT).expect("valid ctlogs.dev endpoint"),
            key,
        ))
    }

    fn at(endpoint: Url, api_key: Option<String>) -> Self {
        // Production uses HTTPS; an injectable endpoint permits offline HTTP tests.
        // Redirects are disabled to keep credentials and fingerprints on this service.
        let agent = ureq::Agent::config_builder()
            .https_only(endpoint.scheme() == "https")
            .http_status_as_error(false)
            .max_redirects(0)
            .timeout_global(Some(Duration::from_secs(30)))
            .build()
            .into();
        Self {
            agent,
            endpoint,
            api_key,
            cache: HashMap::new(),
        }
    }

    pub(crate) fn details(
        &mut self,
        input: &[u8],
        spki: &SubjectPublicKeyInfoOwned,
    ) -> Result<(Query, &Details), String> {
        let der = crate::decode_input(input)?;
        // Exact certificate lookup is anonymous; key-reuse searches require Pro.
        let query = if Certificate::from_der(&der).is_ok() {
            Query::Certificate(sha256(&der))
        } else {
            let der = spki
                .to_der()
                .map_err(|e| format!("cannot encode public key for CT lookup: {e}"))?;
            Query::Spki(sha256(&der))
        };
        let result = self
            .cache
            .entry(query.clone())
            .or_insert_with(|| fetch(&self.agent, &self.endpoint, self.api_key.as_deref(), &query));
        match result {
            Ok(details) => Ok((query, details)),
            Err(e) => Err(e.clone()),
        }
    }
}

fn sha256(data: &[u8]) -> String {
    openssl::sha::sha256(data)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn request(
    agent: &ureq::Agent,
    url: &Url,
    api_key: Option<&str>,
    allow_not_found: bool,
) -> Result<Option<Vec<u8>>, String> {
    let mut request = agent.get(url.as_str()).header("Accept", "application/json");
    if let Some(key) = api_key {
        request = request.header("Authorization", format!("Bearer {key}"));
    }
    let mut response = request
        .call()
        .map_err(|e| format!("ctlogs.dev request failed: {e}"))?;
    match response.status().as_u16() {
        200 => {}
        // An absent certificate record does not invalidate the weak-key finding.
        404 if allow_not_found => return Ok(None),
        401 => return Err("ctlogs.dev rejected CTLOGS_API_KEY (HTTP 401)".into()),
        403 => {
            return Err(
                "ctlogs.dev denied access; SPKI searches require a Pro API key (HTTP 403)".into(),
            );
        }
        429 => return Err("ctlogs.dev rate limit exceeded (HTTP 429); try again later".into()),
        _ => return Err(format!("ctlogs.dev returned HTTP {}", response.status())),
    }
    response
        .body_mut()
        .with_config()
        .limit(BODY_LIMIT)
        .read_to_vec()
        .map(Some)
        .map_err(|e| format!("cannot read ctlogs.dev response: {e}"))
}

fn fetch(
    agent: &ureq::Agent,
    endpoint: &Url,
    api_key: Option<&str>,
    query: &Query,
) -> Result<Details, String> {
    if matches!(query, Query::Spki(_)) && api_key.is_none() {
        return Err(
            "bare public-key CT searches require a ctlogs.dev Pro key in CTLOGS_API_KEY; \
             use a certificate input for anonymous fingerprint lookup"
                .into(),
        );
    }
    let mut url = endpoint.clone();
    url.path_segments_mut()
        .map_err(|_| "invalid CT API endpoint")?
        .extend([
            "v1",
            if matches!(query, Query::Certificate(_)) {
                "cert"
            } else {
                "spki"
            },
            query.hash(),
        ]);
    let mut certificates = Vec::new();
    let mut truncated = false;
    let mut cursors = HashSet::new();
    for page_index in 0..PAGE_LIMIT {
        let body = request(agent, &url, api_key, matches!(query, Query::Certificate(_)))?;
        let Some(body) = body else {
            break;
        };
        if matches!(query, Query::Certificate(_)) {
            let cert: CertificateDetails = serde_json::from_slice(&body)
                .map_err(|e| format!("invalid ctlogs.dev certificate JSON: {e}"))?;
            certificates.push(cert);
            break;
        }
        let page: Page = serde_json::from_slice(&body)
            .map_err(|e| format!("invalid ctlogs.dev search JSON: {e}"))?;
        certificates.extend(page.rows);
        truncated |= page.truncated.unwrap_or(false);
        if !page.has_next {
            break;
        }
        // Cursors are opaque; reject loops rather than repeatedly billing a page.
        if page.next_cursor.is_empty() || !cursors.insert(page.next_cursor.clone()) {
            return Err("ctlogs.dev returned an empty or repeated pagination cursor".into());
        }
        if page_index + 1 == PAGE_LIMIT {
            truncated = true;
        }
        url.query_pairs_mut()
            .clear()
            .append_pair("after", &page.next_cursor);
    }
    if certificates
        .iter()
        .any(|cert| cert.id.is_empty() || !cert.id.bytes().all(|b| b.is_ascii_hexdigit()))
    {
        return Err("ctlogs.dev response contains an invalid certificate ID".into());
    }
    certificates.sort_by(|a, b| a.id.cmp(&b.id));
    certificates.dedup_by(|a, b| a.id == b.id);
    Ok(Details {
        certificates,
        truncated,
    })
}

pub(crate) fn write_details(
    out: &mut impl Write,
    prefix: &str,
    query: &Query,
    details: &Details,
) -> std::io::Result<()> {
    writeln!(
        out,
        "{prefix}CT: {} indexed certificate(s) for {} SHA-256 {}",
        details.certificates.len(),
        query.kind(),
        query.hash()
    )?;
    if details.truncated {
        writeln!(
            out,
            "{prefix}CT: results incomplete (provider or 10-page limit)"
        )?;
    }
    for cert in &details.certificates {
        writeln!(out, "{prefix}CT: https://ctlogs.dev/cert/{}", cert.id)?;
        // Debug formatting escapes terminal control characters in remote metadata.
        for (label, value) in [
            ("issuer", &cert.issuer_dn),
            ("subject", &cert.subject_dn),
            ("common name", &cert.subject_cn),
            ("not before", &cert.not_before),
            ("not after", &cert.not_after),
            ("serial", &cert.serial_hex),
            ("SPKI SHA-256", &cert.pubkey_sha256),
        ] {
            if let Some(value) = value {
                writeln!(out, "{prefix}CT: {label}={value:?}")?;
            }
        }
        if let Some(names) = &cert.san_dns {
            writeln!(out, "{prefix}CT: DNS names={names:?}")?;
        }
        if let Some(sightings) = &cert.sightings {
            for sighting in sightings {
                writeln!(
                    out,
                    "{prefix}CT: log={:?} operator={:?} entry={} timestamp={:?} precertificate={}",
                    sighting.log_url,
                    sighting.operator,
                    sighting.entry_idx,
                    sighting.sct_ts,
                    sighting.is_precert
                )?;
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{BufRead, BufReader};
    use std::net::TcpListener;
    use std::sync::mpsc;
    use std::thread;

    fn server(
        responses: Vec<(&str, &str)>,
        api_key: Option<&str>,
    ) -> (Lookup, mpsc::Receiver<String>, thread::JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let endpoint = Url::parse(&format!("http://{}/", listener.local_addr().unwrap())).unwrap();
        let (tx, rx) = mpsc::channel();
        let responses: Vec<_> = responses.into_iter().map(|(status, body)| format!(
            "HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        )).collect();
        let handle = thread::spawn(move || {
            for response in responses {
                let deadline = std::time::Instant::now() + Duration::from_secs(5);
                let mut socket = loop {
                    match listener.accept() {
                        Ok((socket, _)) => break socket,
                        Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                            assert!(
                                std::time::Instant::now() < deadline,
                                "client never connected"
                            );
                            thread::sleep(Duration::from_millis(10));
                        }
                        Err(e) => panic!("cannot accept CT request: {e}"),
                    }
                };
                socket.set_nonblocking(false).unwrap();
                socket
                    .set_read_timeout(Some(Duration::from_secs(5)))
                    .unwrap();
                socket
                    .set_write_timeout(Some(Duration::from_secs(5)))
                    .unwrap();
                let mut reader = BufReader::new(&socket);
                let mut request = String::new();
                loop {
                    let mut line = String::new();
                    reader.read_line(&mut line).unwrap();
                    if line == "\r\n" || line.is_empty() {
                        break;
                    }
                    request.push_str(&line);
                }
                // Some tests intentionally discard the captured request.
                let _ = tx.send(request);
                match socket.write_all(response.as_bytes()) {
                    Ok(()) => {}
                    Err(e)
                        if matches!(
                            e.kind(),
                            std::io::ErrorKind::BrokenPipe | std::io::ErrorKind::ConnectionReset
                        ) => {}
                    Err(e) => panic!("cannot write CT response: {e}"),
                }
            }
        });
        (
            Lookup::at(endpoint, api_key.map(str::to_string)),
            rx,
            handle,
        )
    }

    fn spki() -> SubjectPublicKeyInfoOwned {
        let key =
            p256::PublicKey::from_affine(p256::ProjectivePoint::GENERATOR.to_affine()).unwrap();
        crate::tests::ec_spki(crate::OID_P256, &key.to_sec1_bytes())
    }

    #[test]
    fn paginates_spki_search_and_caches_duplicate_keys() {
        let (mut lookup, requests, handle) = server(
            vec![
                (
                    "200 OK",
                    r#"{"rows":[{"id":"ab","issuer":"Test CA","match":"example.test","not_before":"2026-01-01","not_after":"2027-01-01","serial_hex":"ab"}],"has_next":true,"next_cursor":"opaque+cursor/=="}"#,
                ),
                (
                    "200 OK",
                    r#"{"rows":[{"id":"ab"},{"id":"cd","issuer":"Other CA"}],"has_next":false,"next_cursor":""}"#,
                ),
            ],
            Some("test-token"),
        );
        let key = spki();
        let der = key.to_der().unwrap();
        let (query, details) = lookup.details(&der, &key).unwrap();
        assert_eq!(query, Query::Spki(sha256(&der)));
        assert_eq!(details.certificates.len(), 2);
        assert!(!details.truncated);
        let mut output = Vec::new();
        write_details(&mut output, "[test] ", &query, details).unwrap();
        assert!(
            String::from_utf8(output)
                .unwrap()
                .contains("https://ctlogs.dev/cert/ab")
        );
        assert_eq!(lookup.details(&der, &key).unwrap().1.certificates.len(), 2);
        handle.join().unwrap();
        let request = requests.recv().unwrap();
        assert!(request.contains(&format!("/v1/spki/{}", sha256(&der))));
        assert!(
            request
                .to_lowercase()
                .contains("authorization: bearer test-token")
        );
        assert!(!request.contains("key="));
        let request = requests.recv().unwrap();
        assert!(request.contains("after=opaque%2Bcursor%2F%3D%3D"));
    }

    #[test]
    fn fetches_full_certificate_details_anonymously() {
        let (mut lookup, requests, handle) = server(
            vec![(
                "200 OK",
                r#"{"id":"ab","issuer_dn":"CN=Test CA","subject_cn":"example.test","san_dns":["example.test"],"serial_hex":"12","sightings":[{"log_url":"https://log.example/","operator":"Test","entry_idx":7,"sct_ts":"2026-01-01T00:00:00Z","is_precert":false}]}"#,
            )],
            None,
        );
        let cert = crate::tests::TEST_CERT.as_bytes();
        let key = crate::parse_spki(cert).unwrap().0;
        let (query, details) = lookup.details(cert, &key).unwrap();
        let mut output = Vec::new();
        write_details(&mut output, "", &query, details).unwrap();
        let output = String::from_utf8(output).unwrap();
        assert!(output.contains("DNS names=[\"example.test\"]"));
        assert!(output.contains("entry=7"));
        assert!(output.contains("precertificate=false"));
        handle.join().unwrap();
        let request = requests.recv().unwrap();
        let hash = sha256(&crate::decode_input(cert).unwrap());
        assert!(request.contains(&format!("/v1/cert/{hash}")));
        assert!(!request.to_lowercase().contains("authorization"));
    }

    #[test]
    fn treats_certificate_404_as_no_indexed_record() {
        let (mut lookup, _, handle) =
            server(vec![("404 Not Found", r#"{"error":"not found"}"#)], None);
        let cert = crate::tests::TEST_CERT.as_bytes();
        let (query, details) = lookup
            .details(cert, &crate::parse_spki(cert).unwrap().0)
            .unwrap();
        assert!(details.certificates.is_empty());
        let mut output = Vec::new();
        write_details(&mut output, "", &query, details).unwrap();
        assert!(
            String::from_utf8(output)
                .unwrap()
                .contains("0 indexed certificate(s)")
        );
        handle.join().unwrap();
    }

    #[test]
    fn requires_key_for_spki_without_network_access() {
        let mut lookup = Lookup::at(Url::parse("http://127.0.0.1:1/").unwrap(), None);
        let key = spki();
        let error = lookup.details(&key.to_der().unwrap(), &key).unwrap_err();
        assert!(error.contains("Pro key"));
    }

    #[test]
    fn rejects_http_json_and_pagination_errors_and_caches_failures() {
        for (status, body, expected) in [
            ("503 Service Unavailable", "busy", "HTTP 503"),
            ("429 Too Many Requests", "busy", "rate limit"),
            ("403 Forbidden", "denied", "Pro API key"),
            ("401 Unauthorized", "denied", "rejected CTLOGS_API_KEY"),
            ("302 Found", "", "HTTP 302"),
            (
                "200 OK",
                "<html>error</html>",
                "invalid ctlogs.dev search JSON",
            ),
            ("200 OK", "{}", "invalid ctlogs.dev search JSON"),
            (
                "200 OK",
                r#"{"rows":[{"id":"../bad"}],"has_next":false,"next_cursor":""}"#,
                "invalid certificate ID",
            ),
            (
                "200 OK",
                r#"{"rows":[],"has_next":true,"next_cursor":""}"#,
                "pagination cursor",
            ),
        ] {
            let (mut lookup, _, handle) = server(vec![(status, body)], Some("test-token"));
            let key = spki();
            let der = key.to_der().unwrap();
            let first = lookup.details(&der, &key).unwrap_err();
            assert!(first.contains(expected), "{first}");
            assert_eq!(lookup.details(&der, &key).unwrap_err(), first);
            handle.join().unwrap();
        }
    }

    #[test]
    fn reports_provider_truncation_and_escapes_metadata() {
        let (mut lookup, _, handle) = server(
            vec![(
                "200 OK",
                r#"{"rows":[{"id":"ab","match":"\u001b[31m\nforged output"}],"has_next":false,"next_cursor":"","truncated":true}"#,
            )],
            Some("test-token"),
        );
        let key = spki();
        let (query, details) = lookup.details(&key.to_der().unwrap(), &key).unwrap();
        let mut output = Vec::new();
        write_details(&mut output, "", &query, details).unwrap();
        let output = String::from_utf8(output).unwrap();
        assert!(output.contains("results incomplete"));
        assert!(!output.contains('\u{1b}'));
        assert!(output.contains("\\u{1b}[31m\\nforged output"));
        handle.join().unwrap();
    }

    #[test]
    fn bounds_pagination_and_rejects_repeated_cursors() {
        let pages: Vec<_> = (0..PAGE_LIMIT)
            .map(|index| {
                format!(r#"{{"rows":[{{"id":"ab"}}],"has_next":true,"next_cursor":"page{index}"}}"#)
            })
            .collect();
        let responses = pages.iter().map(|body| ("200 OK", body.as_str())).collect();
        let (mut lookup, _, handle) = server(responses, Some("test-token"));
        let key = spki();
        let der = key.to_der().unwrap();
        let (_, details) = lookup.details(&der, &key).unwrap();
        assert!(details.truncated);
        assert_eq!(details.certificates.len(), 1);
        handle.join().unwrap();

        let page = r#"{"rows":[],"has_next":true,"next_cursor":"same"}"#;
        let (mut lookup, _, handle) =
            server(vec![("200 OK", page), ("200 OK", page)], Some("test-token"));
        assert!(
            lookup
                .details(&der, &key)
                .unwrap_err()
                .contains("repeated pagination cursor")
        );
        handle.join().unwrap();
    }

    #[test]
    fn rejects_oversized_responses() {
        let body = " ".repeat(BODY_LIMIT as usize + 1);
        let (mut lookup, _, handle) = server(vec![("200 OK", &body)], Some("test-token"));
        let key = spki();
        let error = lookup.details(&key.to_der().unwrap(), &key).unwrap_err();
        assert!(error.contains("cannot read ctlogs.dev response"), "{error}");
        handle.join().unwrap();
    }
}
