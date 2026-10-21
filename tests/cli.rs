use std::io::Write;
use std::process::{Command, Output, Stdio};

use openssl::asn1::Asn1Object;
use openssl::bn::{BigNum, BigNumContext};
use openssl::ec::{EcGroup, EcKey, EcPoint};
use openssl::pkey::PKey;

fn public_key(oid: &str, scalar: u64) -> Vec<u8> {
    let nid = Asn1Object::from_str(oid).unwrap().nid();
    let group = EcGroup::from_curve_name(nid).unwrap();
    let mut ctx = BigNumContext::new().unwrap();
    let scalar = BigNum::from_slice(&scalar.to_be_bytes()).unwrap();
    let mut point = EcPoint::new(&group).unwrap();
    point.mul_generator2(&group, &scalar, &mut ctx).unwrap();
    let key = EcKey::from_public_key(&group, &point).unwrap();
    PKey::from_ec_key(key).unwrap().public_key_to_der().unwrap()
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
