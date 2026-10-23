use std::io::Write;
use std::process::{Command, Output, Stdio};

use der::{Decode, Encode, asn1::ObjectIdentifier};
use num_bigint::BigUint;
use spki::SubjectPublicKeyInfoOwned;

fn public_key(oid: &str, scalar: u64) -> Vec<u8> {
    let references: serde_json::Value =
        serde_json::from_str(include_str!("fixtures/ec-vectors.json")).unwrap();
    let curve = references["curves"]
        .as_array()
        .unwrap()
        .iter()
        .find(|curve| curve["oid"].as_str() == Some(oid))
        .unwrap();
    let vector = curve["vectors"]
        .as_array()
        .unwrap()
        .iter()
        .find(|vector| vector["scalar"].as_u64() == Some(scalar))
        .unwrap();
    let hex = vector["uncompressed"].as_str().unwrap();
    let point: Vec<u8> = (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
        .collect();
    let curve_oid = ObjectIdentifier::new(oid).unwrap().to_der().unwrap();
    SubjectPublicKeyInfoOwned {
        algorithm: spki::AlgorithmIdentifierOwned {
            oid: ObjectIdentifier::new_unwrap("1.2.840.10045.2.1"),
            parameters: Some(der::asn1::Any::from_der(&curve_oid).unwrap()),
        },
        subject_public_key: der::asn1::BitString::from_bytes(&point).unwrap(),
    }
    .to_der()
    .unwrap()
}

fn run(input: &[u8], args: &[&str]) -> Output {
    let mut child = Command::new(env!("CARGO_BIN_EXE_lowkey-check"))
        .args(args)
        // Keep tests offline and missing-key behavior independent of developer credentials.
        .env_remove("CTLOGS_API_KEY")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child.stdin.take().unwrap().write_all(input).unwrap();
    child.wait_with_output().unwrap()
}

fn rsa_public_key(modulus: &BigUint) -> Vec<u8> {
    #[derive(der::Sequence)]
    struct RsaKey<'a> {
        modulus: der::asn1::UintRef<'a>,
        exponent: der::asn1::UintRef<'a>,
    }
    let modulus = modulus.to_bytes_be();
    let key = RsaKey {
        modulus: der::asn1::UintRef::new(&modulus).unwrap(),
        exponent: der::asn1::UintRef::new(&[17]).unwrap(),
    }
    .to_der()
    .unwrap();
    SubjectPublicKeyInfoOwned {
        algorithm: spki::AlgorithmIdentifierOwned {
            oid: ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.1"),
            parameters: None,
        },
        subject_public_key: der::asn1::BitString::from_bytes(&key).unwrap(),
    }
    .to_der()
    .unwrap()
}

fn run_rsa_csv(moduli: &[u64], args: &[&str]) -> Output {
    use std::sync::atomic::{AtomicU64, Ordering};
    static NEXT_FILE: AtomicU64 = AtomicU64::new(0);
    let path = std::env::temp_dir().join(format!(
        "lowkey-check-rsa-{}-{}.csv",
        std::process::id(),
        NEXT_FILE.fetch_add(1, Ordering::Relaxed)
    ));
    let file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&path)
        .unwrap();
    let mut csv = csv::Writer::from_writer(file);
    csv.write_record(["Certificate Name", "Public Key"])
        .unwrap();
    for (i, modulus) in moduli.iter().enumerate() {
        let pem = pem_rfc7468::encode_string(
            "PUBLIC KEY",
            pem_rfc7468::LineEnding::LF,
            &rsa_public_key(&BigUint::from(*modulus)),
        )
        .unwrap();
        csv.write_record([format!("rsa-{i}"), pem]).unwrap();
    }
    drop(csv.into_inner().unwrap());
    let mut args = args.to_vec();
    args.push(path.to_str().unwrap());
    let output = run(b"", &args);
    std::fs::remove_file(path).unwrap();
    output
}

#[test]
fn checks_legacy_and_brainpool_spki_from_stdin() {
    for (oid, name) in [
        ("1.2.840.10045.3.1.1", "P-192"),
        ("1.3.132.0.33", "P-224"),
        ("1.3.36.3.3.2.8.1.1.13", "brainpoolP512r1"),
        ("1.3.36.3.3.2.8.1.1.14", "brainpoolP512t1"),
    ] {
        let output = run(
            &public_key(oid, 7),
            &["--range", "7-7", "--threads", "1", "-"],
        );
        assert_eq!(output.status.code(), Some(1), "{output:?}");
        let stdout = String::from_utf8_lossy(&output.stdout);
        assert!(stdout.contains(name), "{stdout}");
        assert!(stdout.contains("private key is 7"), "{stdout}");
        assert!(!stdout.contains("CT:"));
        assert!(output.stderr.is_empty(), "{output:?}");
    }
}

#[test]
fn ct_lookup_failure_preserves_finding_and_is_visible_in_quiet_mode() {
    let output = run(
        &public_key("1.3.132.0.33", 7),
        &[
            "--range",
            "7-7",
            "--threads",
            "1",
            "--ct-details",
            "--quiet",
            "-",
        ],
    );
    assert_eq!(output.status.code(), Some(2), "{output:?}");
    assert!(String::from_utf8_lossy(&output.stdout).contains("VULNERABLE:"));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("CT lookup:"), "{stderr}");
    assert!(stderr.contains("Pro key"), "{stderr}");
}

#[test]
fn ct_flag_does_not_look_up_keys_without_findings() {
    let output = run(
        &public_key("1.3.36.3.3.2.8.1.1.7", 7),
        &["--range", "8-9", "--threads", "1", "--ct-details", "-"],
    );
    assert_eq!(output.status.code(), Some(0), "{output:?}");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("OK:"));
    assert!(!stdout.contains("CT:"));
    assert!(output.stderr.is_empty());
}

#[test]
fn rejects_invalid_ccadb_years_before_network_access() {
    for args in [
        vec!["--year", "2020"],
        vec!["--check-ccadb", "--year", "2010-2005"],
        vec!["--check-ccadb", "--year", "-"],
        vec!["--check-ccadb", "--year", "1998"],
    ] {
        let output = run(b"", &args);
        assert_eq!(output.status.code(), Some(2), "{output:?}");
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(!stderr.contains("Downloading"), "{stderr}");
    }
}

#[test]
fn rsa_fermat_obeys_exact_budget_and_reports_verified_factors() {
    // ceil(sqrt(101 * 151)) = 124; the first success is a = 126.
    let key = rsa_public_key(&BigUint::from(101u64 * 151));
    for (budget, expected) in [("0", 0), ("2", 0), ("3", 1)] {
        let output = run(&key, &["--fermat-steps", budget, "-"]);
        assert_eq!(output.status.code(), Some(expected), "{output:?}");
        let stdout = String::from_utf8_lossy(&output.stdout);
        if expected == 1 {
            assert!(stdout.contains("bounded Fermat"), "{stdout}");
            assert!(stdout.contains("factor = 101 "), "{stdout}");
            assert!(stdout.contains("cofactor = 151 "), "{stdout}");
        } else {
            assert!(stdout.contains("OK:"), "{stdout}");
            if budget == "0" {
                assert!(stdout.contains("Fermat: disabled"), "{stdout}");
            } else {
                assert!(stdout.contains("no factor within 2 candidates"), "{stdout}");
            }
        }
        assert!(output.stderr.is_empty(), "{output:?}");
    }
    let output = run(&key, &["--quiet", "-"]);
    assert_eq!(output.status.code(), Some(1), "{output:?}");
    assert!(String::from_utf8_lossy(&output.stdout).contains("VULNERABLE:"));
}

#[test]
fn rsa_shared_factor_check_deduplicates_without_missing_affected_rows() {
    let n = 101 * 1_000_003;
    let output = run_rsa_csv(&[n, n], &["--fermat-steps", "0", "--quiet"]);
    assert_eq!(output.status.code(), Some(0), "{output:?}");
    assert!(output.stdout.is_empty(), "{output:?}");
    assert!(output.stderr.is_empty(), "{output:?}");

    let output = run_rsa_csv(
        &[n, n, 101 * 1_000_033],
        &["--fermat-steps", "0", "--quiet"],
    );
    assert_eq!(output.status.code(), Some(1), "{output:?}");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert_eq!(stdout.matches("batch GCD").count(), 3, "{stdout}");
    for tag in ["[row 2 rsa-0]", "[row 3 rsa-1]", "[row 4 rsa-2]"] {
        assert!(stdout.contains(tag), "{stdout}");
    }
    assert_eq!(stdout.matches("factor = 101 ").count(), 3, "{stdout}");
    assert!(output.stderr.is_empty(), "{output:?}");
}

#[test]
fn rsa_batch_handles_different_peers_sharing_both_factors() {
    let output = run_rsa_csv(
        &[101 * 113, 101 * 131, 113 * 131],
        &["--fermat-steps", "0", "--quiet"],
    );
    assert_eq!(output.status.code(), Some(1), "{output:?}");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert_eq!(stdout.matches("batch GCD").count(), 3, "{stdout}");
    assert!(output.stderr.is_empty(), "{output:?}");
}

#[test]
fn roca_fingerprint_is_not_described_as_recovered_private_key() {
    // A synthetic member of <65537>; real affected-key references are tested by rsa.rs.
    let key = rsa_public_key(&BigUint::from(65_537u32).pow(9));
    let output = run(&key, &["--fermat-steps", "0", "--quiet", "-"]);
    assert_eq!(output.status.code(), Some(1), "{output:?}");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("SUSPECT:"), "{stdout}");
    assert!(stdout.contains("ROCA fingerprint match"), "{stdout}");
    assert!(!stdout.contains("VULNERABLE:"), "{stdout}");
    assert!(stdout.contains("does not recover"), "{stdout}");
    assert!(output.stderr.is_empty(), "{output:?}");
}

#[test]
fn rsa_ct_errors_preserve_factor_and_fingerprint_findings() {
    for (modulus, budget, status) in [
        (BigUint::from(101u32 * 113), "1", "VULNERABLE:"),
        (BigUint::from(65_537u32).pow(9), "0", "SUSPECT:"),
    ] {
        let output = run(
            &rsa_public_key(&modulus),
            &["--fermat-steps", budget, "--ct-details", "--quiet", "-"],
        );
        assert_eq!(output.status.code(), Some(2), "{output:?}");
        assert!(String::from_utf8_lossy(&output.stdout).contains(status));
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(stderr.contains("CT lookup:"), "{stderr}");
        assert!(stderr.contains("Pro key"), "{stderr}");
    }
}

#[test]
fn rsa_without_findings_does_not_attempt_ct_lookup() {
    let output = run(
        &rsa_public_key(&BigUint::from(101u64 * 1_000_003)),
        &["--ct-details", "--quiet", "-"],
    );
    assert_eq!(output.status.code(), Some(0), "{output:?}");
    assert!(output.stdout.is_empty(), "{output:?}");
    assert!(output.stderr.is_empty(), "{output:?}");
}

#[test]
fn malformed_rsa_is_an_error_not_an_unsupported_algorithm() {
    let mut spki =
        SubjectPublicKeyInfoOwned::from_der(&rsa_public_key(&BigUint::from(101u32 * 113))).unwrap();
    // A negative ASN.1 modulus must never be reinterpreted as an unsigned number.
    spki.subject_public_key =
        der::asn1::BitString::from_bytes(&[0x30, 6, 2, 1, 0x80, 2, 1, 17]).unwrap();
    let output = run(&spki.to_der().unwrap(), &["--quiet", "-"]);
    assert_eq!(output.status.code(), Some(2), "{output:?}");
    assert!(output.stdout.is_empty(), "{output:?}");
    assert!(String::from_utf8_lossy(&output.stderr).contains("RSA"));
}

fn full_width_p256_key(dense: bool) -> (Vec<u8>, BigUint) {
    use p256::elliptic_curve::group::Group as _;
    let mut point = p256::ProjectivePoint::GENERATOR;
    for _ in 0..255 {
        point = point.double();
    }
    let mut scalar = BigUint::from(1u8) << 255;
    if dense {
        point -= p256::ProjectivePoint::GENERATOR;
        scalar -= 1u8;
    }
    let public = p256::PublicKey::from_affine(point.to_affine()).unwrap();
    let mut spki =
        SubjectPublicKeyInfoOwned::from_der(&public_key("1.2.840.10045.3.1.7", 1)).unwrap();
    spki.subject_public_key = der::asn1::BitString::from_bytes(&public.to_sec1_bytes()).unwrap();
    (spki.to_der().unwrap(), scalar)
}

#[test]
fn structured_ec_search_recovers_full_width_zero_and_one_patterns() {
    for (pattern, dense) in [
        ("zeros", false),
        ("ones", true),
        ("zero-run", false),
        ("one-run", true),
    ] {
        let (key, scalar) = full_width_p256_key(dense);
        let output = run(
            &key,
            &[
                "--ec-pattern",
                pattern,
                "--pattern-bits",
                "255",
                "--max-candidates",
                "256",
                "--threads",
                "3",
                "-",
            ],
        );
        assert_eq!(output.status.code(), Some(1), "{pattern}: {output:?}");
        let stdout = String::from_utf8_lossy(&output.stdout);
        assert!(
            stdout.contains(&format!("private key is {scalar} (0x{scalar:x})")),
            "{stdout}"
        );
        assert!(stdout.contains("256-bit scalars"), "{stdout}");
        assert!(stdout.find("SEARCH:").unwrap() < stdout.find("VULNERABLE:").unwrap());
        if pattern == "zero-run" {
            assert!(
                stdout.contains("2 distinct zero-run candidates"),
                "{stdout}"
            );
        } else if pattern == "one-run" {
            assert!(stdout.contains("1 distinct one-run candidates"), "{stdout}");
        } else if pattern == "zeros" {
            assert!(stdout.contains("256 distinct zeros candidates"), "{stdout}");
        }
        assert!(output.stderr.is_empty(), "{output:?}");
    }
}

#[test]
fn pattern_budget_refuses_entire_space_even_if_first_candidate_would_match() {
    for (pattern, bits, budget) in [("zero-run", "255", "1"), ("zeros", "128", "1000")] {
        let output = run(
            &public_key("1.2.840.10045.3.1.7", 1),
            &[
                "--ec-pattern",
                pattern,
                "--pattern-bits",
                bits,
                "--max-candidates",
                budget,
                "--quiet",
                "--ct-details",
                "-",
            ],
        );
        assert_eq!(output.status.code(), Some(2), "{output:?}");
        assert!(output.stdout.is_empty(), "{output:?}");
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(stderr.contains("candidates exceed"), "{stderr}");
        assert!(
            stderr.contains("P-256 (secp256r1) (256-bit scalars)"),
            "{stderr}"
        );
        assert!(
            stderr.contains("no pattern candidates were searched"),
            "{stderr}"
        );
        assert!(!stderr.contains("CT lookup"), "{stderr}");
    }
}

#[test]
fn structured_search_requires_explicit_valid_configuration() {
    for args in [
        vec!["--ec-pattern", "zeros"],
        vec!["--ec-pattern", "zeros", "--pattern-bits", "255"],
        vec!["--pattern-bits", "255"],
        vec!["--max-candidates", "256"],
        vec![
            "--ec-pattern",
            "zeros",
            "--pattern-bits",
            "0",
            "--max-candidates",
            "256",
        ],
        vec![
            "--ec-pattern",
            "zeros",
            "--pattern-bits",
            "255",
            "--max-candidates",
            "0",
        ],
        vec![
            "--ec-pattern",
            "zeros",
            "--pattern-bits",
            "255",
            "--max-candidates",
            "256",
            "--range",
            "1-1",
        ],
    ] {
        let output = run(b"", &args);
        assert_eq!(output.status.code(), Some(2), "{args:?}: {output:?}");
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(stderr.contains("--help"), "{args:?}: {stderr}");
        assert!(!stderr.contains("neither a valid"), "{stderr}");
    }
}

#[test]
fn complete_pattern_nonfinding_does_not_trigger_ct_lookup() {
    let output = run(
        &public_key("1.2.840.10045.3.1.7", 7),
        &[
            "--ec-pattern",
            "zero-run",
            "--pattern-bits",
            "255",
            "--max-candidates",
            "2",
            "--ct-details",
            "-",
        ],
    );
    assert_eq!(output.status.code(), Some(0), "{output:?}");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("OK:"), "{stdout}");
    assert!(
        stdout.contains("not found among 2 distinct zero-run candidates"),
        "{stdout}"
    );
    assert!(!stdout.contains("VULNERABLE"), "{stdout}");
    assert!(output.stderr.is_empty(), "{output:?}");
}

#[test]
fn structured_full_width_finding_survives_ct_error_in_quiet_mode() {
    let (key, scalar) = full_width_p256_key(false);
    let output = run(
        &key,
        &[
            "--ec-pattern",
            "zero-run",
            "--pattern-bits",
            "255",
            "--max-candidates",
            "2",
            "--quiet",
            "--ct-details",
            "-",
        ],
    );
    assert_eq!(output.status.code(), Some(2), "{output:?}");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains(&format!("private key is {scalar}")),
        "{stdout}"
    );
    assert!(!stdout.contains("SEARCH:"), "{stdout}");
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("Pro key"),
        "{output:?}"
    );
}

#[test]
fn pattern_threshold_errors_identify_curve_width_and_requested_bits() {
    for (oid, name, width) in [
        ("1.2.840.10045.3.1.7", "P-256", 256),
        ("1.3.132.0.34", "P-384", 384),
        ("1.3.132.0.35", "P-521", 521),
        ("1.3.36.3.3.2.8.1.1.1", "brainpoolP160r1", 160),
    ] {
        let bits = (width + 1).to_string();
        let output = run(
            &public_key(oid, 1),
            &[
                "--ec-pattern",
                "zero-run",
                "--pattern-bits",
                &bits,
                "--max-candidates",
                "2",
                "--quiet",
                "-",
            ],
        );
        assert_eq!(output.status.code(), Some(2), "{output:?}");
        assert!(output.stdout.is_empty(), "{output:?}");
        let stderr = String::from_utf8_lossy(&output.stderr);
        for expected in [
            name.to_string(),
            format!("{width}-bit scalars"),
            format!("--pattern-bits {bits}"),
            format!("pattern bits must be in 1..={width}"),
        ] {
            assert!(stderr.contains(&expected), "{stderr}");
        }
    }
}

#[test]
fn width_filter_selects_all_supported_curves_for_range_searches() {
    let references: serde_json::Value =
        serde_json::from_str(include_str!("fixtures/ec-vectors.json")).unwrap();
    for curve in references["curves"].as_array().unwrap() {
        let oid = curve["oid"].as_str().unwrap();
        let width = curve["bits"].as_u64().unwrap().to_string();
        let output = run(
            &public_key(oid, 7),
            &[
                "--filter-bits",
                &width,
                "--range",
                "7-7",
                "--threads",
                "1",
                "-",
            ],
        );
        assert_eq!(output.status.code(), Some(1), "{oid}: {output:?}");
        assert!(
            String::from_utf8_lossy(&output.stdout).contains("private key is 7"),
            "{output:?}"
        );
        assert!(output.stderr.is_empty(), "{output:?}");
    }
    for (oid, filter) in [("1.3.132.0.34", "256"), ("1.2.840.10045.3.1.7", "384")] {
        let output = run(
            &public_key(oid, 7),
            &[
                "--filter-bits",
                filter,
                "--range",
                "7-7",
                "--ct-details",
                "-",
            ],
        );
        assert_eq!(output.status.code(), Some(0), "{output:?}");
        let stdout = String::from_utf8_lossy(&output.stdout);
        assert!(stdout.starts_with("SKIP:"), "{stdout}");
        assert!(stdout.contains("excluded by --filter-bits"), "{stdout}");
        assert!(!stdout.contains("OK:"), "{stdout}");
        assert!(output.stderr.is_empty(), "{output:?}");
    }
}

#[test]
fn width_filter_accepts_lists_and_repeated_options_and_rejects_invalid_values() {
    for args in [
        vec!["--filter-bits", "256,384"],
        vec!["--filter-bits", "256", "--filter-bits", "384"],
    ] {
        for oid in ["1.2.840.10045.3.1.7", "1.3.132.0.34"] {
            let mut args = args.clone();
            args.extend(["--range", "1-1", "--quiet", "-"]);
            let output = run(&public_key(oid, 1), &args);
            assert_eq!(output.status.code(), Some(1), "{args:?}: {output:?}");
            assert!(output.stderr.is_empty(), "{output:?}");
        }
    }
    for value in ["0", "-1", "abc", "256,0", "256,,384", "65536"] {
        let output = run(b"", &["--filter-bits", value]);
        assert_eq!(output.status.code(), Some(2), "{value}: {output:?}");
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(stderr.contains("--help"), "{value}: {stderr}");
        assert!(!stderr.contains("neither a valid"), "{stderr}");
    }
}

#[test]
fn excluded_width_skips_pattern_validation_search_and_ct_lookup() {
    for quiet in [false, true] {
        let mut args = vec![
            "--filter-bits",
            "384",
            "--ec-pattern",
            "zero-run",
            "--pattern-bits",
            "383",
            "--max-candidates",
            "1",
            "--ct-details",
            "-",
        ];
        if quiet {
            args.push("--quiet");
        }
        let output = run(&public_key("1.2.840.10045.3.1.7", 1), &args);
        assert_eq!(output.status.code(), Some(0), "{output:?}");
        if quiet {
            assert!(output.stdout.is_empty(), "{output:?}");
        } else {
            let stdout = String::from_utf8_lossy(&output.stdout);
            assert!(stdout.starts_with("SKIP:"), "{stdout}");
            assert!(stdout.contains("P-256"), "{stdout}");
            assert!(stdout.contains("256-bit scalars"), "{stdout}");
            assert!(!stdout.contains("SEARCH:"), "{stdout}");
        }
        assert!(output.stderr.is_empty(), "{output:?}");
    }
}

#[test]
fn width_filter_preserves_malformed_key_errors() {
    let mut spki =
        SubjectPublicKeyInfoOwned::from_der(&public_key("1.2.840.10045.3.1.7", 1)).unwrap();
    spki.subject_public_key = der::asn1::BitString::from_bytes(&[0]).unwrap();
    let output = run(
        &spki.to_der().unwrap(),
        &["--filter-bits", "384", "--quiet", "-"],
    );
    assert_eq!(output.status.code(), Some(2), "{output:?}");
    assert!(output.stdout.is_empty(), "{output:?}");
    assert!(!output.stderr.is_empty(), "{output:?}");
}
