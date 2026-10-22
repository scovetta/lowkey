//! Variable-time RSA public-data inspection. No private-key operations.

use std::collections::HashMap;
use std::sync::OnceLock;

use der::{
    Decode, Sequence,
    asn1::{ObjectIdentifier, OctetStringRef, UintRef},
};
use num_bigint::BigUint;
use num_integer::Integer;
use num_traits::{One, ToPrimitive};
use spki::{AlgorithmIdentifierRef, SubjectPublicKeyInfoOwned};

const RSA_ENCRYPTION: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.1");
const RSA_OAEP: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.7");
const MGF1: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.8");
const P_SPECIFIED: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.9");
const RSA_PSS: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.10");
const SHA1: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.14.3.2.26");

/// Recognizes rsaEncryption, RSASSA-PSS, and RSAES-OAEP, irrespective of validity.
pub fn is_rsa(spki: &SubjectPublicKeyInfoOwned) -> bool {
    matches!(spki.algorithm.oid, RSA_ENCRYPTION | RSA_PSS | RSA_OAEP)
}

#[derive(Debug)]
pub struct PublicKey {
    pub modulus: BigUint,
}

#[derive(Sequence)]
struct RsaPublicKey<'a> {
    modulus: UintRef<'a>,
    exponent: UintRef<'a>,
}

#[derive(Sequence)]
struct PssParams<'a> {
    #[asn1(context_specific = "0", tag_mode = "EXPLICIT", optional = "true")]
    hash: Option<AlgorithmIdentifierRef<'a>>,
    #[asn1(context_specific = "1", tag_mode = "EXPLICIT", optional = "true")]
    mask: Option<AlgorithmIdentifierRef<'a>>,
    #[asn1(context_specific = "2", tag_mode = "EXPLICIT", optional = "true")]
    salt: Option<UintRef<'a>>,
    #[asn1(context_specific = "3", tag_mode = "EXPLICIT", optional = "true")]
    trailer: Option<UintRef<'a>>,
}

#[derive(Sequence)]
struct OaepParams<'a> {
    #[asn1(context_specific = "0", tag_mode = "EXPLICIT", optional = "true")]
    hash: Option<AlgorithmIdentifierRef<'a>>,
    #[asn1(context_specific = "1", tag_mode = "EXPLICIT", optional = "true")]
    mask: Option<AlgorithmIdentifierRef<'a>>,
    #[asn1(context_specific = "2", tag_mode = "EXPLICIT", optional = "true")]
    source: Option<AlgorithmIdentifierRef<'a>>,
}

fn der_error(error: der::Error) -> String {
    format!("invalid RSA DER: {error}")
}

// RFC 8017 Appendix A.2: accept the standard fixed-output SHA algorithms.
// Unknown parameter grammars are rejected, not presumed valid.
fn check_hash(hash: AlgorithmIdentifierRef<'_>) -> Result<bool, String> {
    let oid = hash.oid.to_string();
    let sha2_or_sha3 = [
        "2.16.840.1.101.3.4.2.1",
        "2.16.840.1.101.3.4.2.2",
        "2.16.840.1.101.3.4.2.3",
        "2.16.840.1.101.3.4.2.4",
        "2.16.840.1.101.3.4.2.5",
        "2.16.840.1.101.3.4.2.6",
        "2.16.840.1.101.3.4.2.7",
        "2.16.840.1.101.3.4.2.8",
        "2.16.840.1.101.3.4.2.9",
        "2.16.840.1.101.3.4.2.10",
    ];
    if hash.oid != SHA1 && !sha2_or_sha3.contains(&oid.as_str()) {
        return Err(format!("unsupported RSA parameter hash algorithm {oid}"));
    }
    let sha3 = sha2_or_sha3[6..].contains(&oid.as_str());
    if hash.parameters.is_some_and(|p| !p.is_null() || sha3) {
        return Err("RSA hash parameters must be absent or NULL (SHA-3 requires absent)".into());
    }
    Ok(hash.oid == SHA1)
}

fn check_mask(mask: AlgorithmIdentifierRef<'_>) -> Result<bool, String> {
    if mask.oid != MGF1 {
        return Err("unsupported RSA mask generation algorithm (expected MGF1)".into());
    }
    let hash = mask
        .parameters
        .ok_or("RSA MGF1 parameters must contain a hash AlgorithmIdentifier")?
        .decode_as::<AlgorithmIdentifierRef<'_>>()
        .map_err(der_error)?;
    check_hash(hash)
}

fn check_parameters(spki: &SubjectPublicKeyInfoOwned) -> Result<(), String> {
    let Some(params) = spki.algorithm.parameters.as_ref() else {
        // RFC 4055 permits absent PSS/OAEP parameters in a public key.
        return Ok(());
    };
    if spki.algorithm.oid == RSA_ENCRYPTION {
        if !params.is_null() {
            return Err("rsaEncryption parameters must be absent or NULL".into());
        }
    } else if spki.algorithm.oid == RSA_PSS {
        let p: PssParams<'_> = params.decode_as().map_err(der_error)?;
        if p.hash.map(check_hash).transpose()?.unwrap_or(false)
            || p.mask.map(check_mask).transpose()?.unwrap_or(false)
            || p.salt.is_some_and(|v| v.as_bytes() == [20])
        {
            return Err("RSA-PSS DER must omit explicitly encoded DEFAULT values".into());
        }
        // The only defined trailer is 1, which DER requires to be omitted.
        if p.trailer.is_some() {
            return Err("RSA-PSS trailerField must be omitted (default 1)".into());
        }
    } else {
        let p: OaepParams<'_> = params.decode_as().map_err(der_error)?;
        if p.hash.map(check_hash).transpose()?.unwrap_or(false)
            || p.mask.map(check_mask).transpose()?.unwrap_or(false)
        {
            return Err("RSA-OAEP DER must omit explicitly encoded DEFAULT values".into());
        }
        if let Some(source) = p.source {
            if source.oid != P_SPECIFIED {
                return Err("unsupported RSA-OAEP source algorithm (expected pSpecified)".into());
            }
            let label: &OctetStringRef = source
                .parameters
                .ok_or("RSA-OAEP pSpecified requires an OCTET STRING label")?
                .decode_as()
                .map_err(der_error)?;
            if label.as_bytes().is_empty() {
                return Err("RSA-OAEP DER must omit the default empty pSpecified label".into());
            }
        }
    }
    Ok(())
}

impl PublicKey {
    /// Strictly decodes the aligned PKCS#1 public key and its algorithm parameters.
    /// Restrictions are inspected for well-formedness, not used to verify signatures.
    pub fn from_spki(spki: &SubjectPublicKeyInfoOwned) -> Result<Self, String> {
        if !is_rsa(spki) {
            return Err("not an RSA public key".into());
        }
        check_parameters(spki)?;
        let bytes = spki
            .subject_public_key
            .as_bytes()
            .ok_or("RSA public key BIT STRING is not byte-aligned")?;
        let key = RsaPublicKey::from_der(bytes).map_err(der_error)?;
        let modulus = BigUint::from_bytes_be(key.modulus.as_bytes());
        let exponent = BigUint::from_bytes_be(key.exponent.as_bytes());
        if modulus <= BigUint::from(3u8) || modulus.is_even() {
            return Err("RSA modulus must be odd and greater than 3".into());
        }
        if exponent < BigUint::from(3u8) || exponent.is_even() || exponent >= modulus {
            return Err("RSA exponent must be odd, at least 3, and less than the modulus".into());
        }
        Ok(Self { modulus })
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Factors {
    pub factor: BigUint,
    pub cofactor: BigUint,
}

fn checked_factors(n: &BigUint, factor: BigUint) -> Option<Factors> {
    if factor <= BigUint::one() || &factor >= n {
        return None;
    }
    let (cofactor, remainder) = n.div_rem(&factor);
    if remainder != BigUint::default() || &factor * &cofactor != *n {
        return None;
    }
    let (factor, cofactor) = if factor <= cofactor {
        (factor, cofactor)
    } else {
        (cofactor, factor)
    };
    Some(Factors { factor, cofactor })
}

/// Checks exactly `steps` consecutive Fermat candidates, starting at ceil(sqrt(n)).
/// Zero disables all work, including perfect-square and even-number recovery.
/// Even inputs use a direct factor of 2 when enabled.
pub fn fermat_factor(n: &BigUint, steps: u64) -> Result<Option<Factors>, String> {
    if n <= &BigUint::one() {
        return Err("RSA modulus must be greater than 1".into());
    }
    if steps == 0 {
        return Ok(None);
    }
    if n.is_even() {
        return Ok(checked_factors(n, BigUint::from(2u8)));
    }
    let mut a = n.sqrt();
    if &a * &a < *n {
        a += 1u8;
    }
    let mut b_squared = &a * &a - n;
    for _ in 0..steps {
        // Squares modulo 16 are 0, 1, 4, or 9.
        if matches!((&b_squared % 16u8).to_u8(), Some(0 | 1 | 4 | 9)) {
            let b = b_squared.sqrt();
            if &b * &b == b_squared
                && let Some(factors) = checked_factors(n, &a - b)
            {
                return Ok(Some(factors));
            }
        }
        b_squared += (&a << 1usize) + 1u8;
        a += 1u8;
    }
    Ok(None)
}

const ROCA_PRIMES: [u32; 38] = [
    3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61, 67, 71, 73, 79, 83, 89, 97,
    101, 103, 107, 109, 113, 127, 131, 137, 139, 149, 151, 157, 163, 167,
];

/// CROCS-MUNI ROCA joint subgroup fingerprint, not factorization.
///
/// Source: <https://github.com/crocs-muni/roca/blob/master/roca/detect.py>,
/// `DlogFprint.fprint` (the current detector), over the primorial through 167.
/// Small subgroup logarithms are generated mathematically. Generalized CRT
/// compatibility requires one exponent to work for every prime, unlike the
/// original independent per-prime detector. This is equivalent to membership
/// in <65537> modulo 167#, but still a fingerprint, not proof of vulnerability.
pub fn roca_fingerprint(n: &BigUint) -> bool {
    static LOGS: OnceLock<Vec<(Vec<Option<u32>>, u32)>> = OnceLock::new();
    if n <= &BigUint::from(2u8) || n.is_even() {
        return false;
    }
    let logs = LOGS.get_or_init(|| {
        ROCA_PRIMES
            .iter()
            .map(|&prime| {
                let mut logarithms = vec![None; prime as usize];
                let mut value = 1;
                let mut order = 0;
                loop {
                    logarithms[value as usize] = Some(order);
                    order += 1;
                    value = (value * (65537 % prime)) % prime;
                    if value == 1 {
                        break;
                    }
                }
                (logarithms, order)
            })
            .collect()
    });
    let mut congruences: Vec<(u32, u32)> = Vec::with_capacity(ROCA_PRIMES.len());
    for (&prime, (logarithms, order)) in ROCA_PRIMES.iter().zip(logs) {
        let Some(exponent) = logarithms[(n % prime).to_usize().expect("small remainder")] else {
            return false;
        };
        for &(other_exponent, other_order) in &congruences {
            let common = order.gcd(&other_order);
            if exponent % common != other_exponent % common {
                return false;
            }
        }
        congruences.push((exponent, *order));
    }
    true
}

/// Batch GCD using a balanced product tree and a squared-modulus remainder tree.
/// Duplicate numeric moduli alone are not evidence of factor recovery.
/// Ambiguous full-modulus GCDs use pruned tree descent, not a pairwise scan.
/// Adversarial containment sets can still require visiting many intersecting
/// subtrees; no proper factor is claimed when only full-modulus overlaps exist.
pub fn batch_shared_factors(moduli: &[BigUint]) -> Result<Vec<Option<Factors>>, String> {
    let mut indices = HashMap::new();
    let mut unique = Vec::new();
    let mut original = Vec::with_capacity(moduli.len());
    for n in moduli {
        if n <= &BigUint::one() {
            return Err("RSA batch modulus must be greater than 1".into());
        }
        let next = unique.len();
        let index = *indices.entry(n.clone()).or_insert_with(|| {
            unique.push(n.clone());
            next
        });
        original.push(index);
    }
    if unique.is_empty() {
        return Ok(Vec::new());
    }
    let mut tree = vec![unique];
    while tree.last().expect("nonempty tree").len() > 1 {
        let next = tree
            .last()
            .expect("nonempty tree")
            .chunks(2)
            .map(|pair| {
                if pair.len() == 2 {
                    &pair[0] * &pair[1]
                } else {
                    pair[0].clone()
                }
            })
            .collect();
        tree.push(next);
    }
    let mut remainders = tree.last().expect("nonempty tree").clone();
    for level in (0..tree.len() - 1).rev() {
        remainders = tree[level]
            .iter()
            .enumerate()
            .map(|(index, product)| &remainders[index / 2] % (product * product))
            .collect();
    }
    let results: Vec<_> = tree[0]
        .iter()
        .zip(remainders)
        .enumerate()
        .map(|(index, (n, remainder))| {
            let gcd = n.gcd(&(remainder / n));
            if &gcd == n {
                // Different peers may supply different factors. Descend only
                // intersecting product subtrees, excluding the target itself.
                isolate_factor(&tree, tree.len() - 1, 0, index, n)
                    .and_then(|factor| checked_factors(n, factor))
            } else {
                checked_factors(n, gcd)
            }
        })
        .collect();
    Ok(original.into_iter().map(|i| results[i].clone()).collect())
}

fn isolate_factor(
    tree: &[Vec<BigUint>],
    level: usize,
    index: usize,
    target: usize,
    n: &BigUint,
) -> Option<BigUint> {
    if level == 0 && index == target {
        return None;
    }
    let gcd = n.gcd(&tree[level][index]);
    if gcd.is_one() {
        return None;
    }
    if &gcd < n {
        return Some(gcd);
    }
    if level == 0 {
        // A distinct multiple of n does not expose a proper factor of n.
        return None;
    }
    let left = index * 2;
    isolate_factor(tree, level - 1, left, target, n).or_else(|| {
        if left + 1 < tree[level - 1].len() {
            isolate_factor(tree, level - 1, left + 1, target, n)
        } else {
            None
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use der::{Encode, asn1::BitString};

    fn b(value: u64) -> BigUint {
        BigUint::from(value)
    }

    fn spki(
        key_der: &[u8],
        oid: ObjectIdentifier,
        params: Option<&[u8]>,
    ) -> SubjectPublicKeyInfoOwned {
        SubjectPublicKeyInfoOwned {
            algorithm: spki::AlgorithmIdentifierOwned {
                oid,
                parameters: params.map(|p| der::asn1::Any::from_der(p).unwrap()),
            },
            subject_public_key: BitString::from_bytes(key_der).unwrap(),
        }
    }

    fn valid_key() -> Vec<u8> {
        RsaPublicKey {
            modulus: UintRef::new(&[143]).unwrap(),
            exponent: UintRef::new(&[7]).unwrap(),
        }
        .to_der()
        .unwrap()
    }

    #[test]
    fn strict_public_key_decoding() {
        let key = valid_key();
        for oid in [RSA_ENCRYPTION, RSA_PSS, RSA_OAEP] {
            for params in [None, Some(&[0x30, 0][..])] {
                let s = spki(&key, oid, params);
                assert!(is_rsa(&s));
                assert_eq!(
                    PublicKey::from_spki(&s).is_ok(),
                    oid != RSA_ENCRYPTION || params.is_none()
                );
            }
        }
        assert_eq!(
            PublicKey::from_spki(&spki(&key, RSA_ENCRYPTION, Some(&[5, 0])))
                .unwrap()
                .modulus,
            b(143)
        );
        let mut unaligned = spki(&key, RSA_ENCRYPTION, None);
        unaligned.subject_public_key = BitString::new(1, [0u8]).unwrap();
        assert!(PublicKey::from_spki(&unaligned).is_err());
        let mut trailing = key.clone();
        trailing.push(0);
        let malformed = [
            trailing,
            vec![0x30, 6, 2, 1, 0x8f, 2, 1, 7],  // negative
            vec![0x30, 7, 2, 2, 0, 15, 2, 1, 7], // nonminimal
            vec![0x30, 6, 2, 1, 0, 2, 1, 7],
            vec![0x30, 6, 2, 1, 1, 2, 1, 7],
            vec![0x30, 6, 2, 1, 3, 2, 1, 7],
            vec![0x30, 6, 2, 1, 14, 2, 1, 7],
            vec![0x30, 6, 2, 1, 15, 2, 1, 1],
            vec![0x30, 6, 2, 1, 15, 2, 1, 0],
            vec![0x30, 6, 2, 1, 15, 2, 1, 2],
            vec![0x30, 6, 2, 1, 15, 2, 1, 0x87], // negative exponent
            vec![0x30, 7, 2, 1, 15, 2, 2, 0, 7], // nonminimal exponent
            vec![0x30, 6, 2, 1, 15, 2, 1, 15],
            vec![0x30, 6, 2, 1, 15, 2, 1, 17],
            vec![0x30, 9, 2, 1, 15, 2, 1, 7, 2, 1, 3],
            vec![0x30, 0x81, 6, 2, 1, 15, 2, 1, 7], // nonminimal length
        ];
        for bytes in malformed {
            assert!(
                PublicKey::from_spki(&spki(&bytes, RSA_ENCRYPTION, None)).is_err(),
                "{bytes:x?}"
            );
        }
        let other = spki(&key, SHA1, None);
        assert!(!is_rsa(&other));
        assert!(PublicKey::from_spki(&other).is_err());
    }

    #[test]
    fn restricted_parameters_are_validated() {
        let key = valid_key();
        let sha256 = AlgorithmIdentifierRef {
            oid: ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.2.1"),
            parameters: Some(der::asn1::AnyRef::NULL),
        };
        let hash_der = sha256.to_der().unwrap();
        let mask = AlgorithmIdentifierRef {
            oid: MGF1,
            parameters: Some(der::asn1::AnyRef::from_der(&hash_der).unwrap()),
        };
        let params = PssParams {
            hash: Some(sha256),
            mask: Some(mask),
            salt: Some(UintRef::new(&[32]).unwrap()),
            trailer: None,
        }
        .to_der()
        .unwrap();
        assert!(PublicKey::from_spki(&spki(&key, RSA_PSS, Some(&params))).is_ok());
        for oid in [RSA_PSS, RSA_OAEP] {
            for invalid in [
                vec![5, 0],                                           // not a sequence
                vec![0x30, 2, 5, 0],                                  // unexpected field
                vec![0x30, 5, 0xa3, 3, 2, 1, 2],                      // invalid trailer / OAEP tag
                vec![0x30, 5, 0xa2, 3, 2, 1, 0xff], // negative salt / wrong source
                vec![0x30, 5, 0xa0, 3, 2, 1, 1],    // malformed hash
                vec![0x30, 2, 0xa4, 0],             // unknown context-specific field
                vec![0x30, 10, 0xa2, 3, 2, 1, 32, 0xa2, 3, 2, 1, 33], // duplicate
                vec![0x30, 5, 0x82, 3, 2, 1, 32],   // implicit, not explicit
            ] {
                assert!(PublicKey::from_spki(&spki(&key, oid, Some(&invalid))).is_err());
            }
        }
        let default_salt = [0x30, 5, 0xa2, 3, 2, 1, 20];
        assert!(PublicKey::from_spki(&spki(&key, RSA_PSS, Some(&default_salt))).is_err());
        let label = der::asn1::AnyRef::new(der::Tag::OctetString, b"label").unwrap();
        let oaep = OaepParams {
            hash: Some(sha256),
            mask: Some(mask),
            source: Some(AlgorithmIdentifierRef {
                oid: P_SPECIFIED,
                parameters: Some(label),
            }),
        }
        .to_der()
        .unwrap();
        assert!(PublicKey::from_spki(&spki(&key, RSA_OAEP, Some(&oaep))).is_ok());
    }

    #[test]
    fn fermat_exact_budget_and_factors() {
        // 3 * 101: ceil(sqrt(303)) = 18, successful a = 52 (candidate 35).
        assert_eq!(fermat_factor(&b(303), 34).unwrap(), None);
        assert_eq!(
            fermat_factor(&b(303), 35).unwrap(),
            Some(Factors {
                factor: b(3),
                cofactor: b(101)
            })
        );
        assert_eq!(fermat_factor(&b(49), 0).unwrap(), None);
        assert_eq!(
            fermat_factor(&b(49), 1).unwrap(),
            Some(Factors {
                factor: b(7),
                cofactor: b(7)
            })
        );
        assert_eq!(fermat_factor(&b(6), 0).unwrap(), None);
        assert_eq!(
            fermat_factor(&b(6), 1).unwrap(),
            Some(Factors {
                factor: b(2),
                cofactor: b(3)
            })
        );
        for prime in [2, 3, 5, 7, 101] {
            assert_eq!(fermat_factor(&b(prime), 100).unwrap(), None);
        }
        for invalid in [0, 1] {
            assert!(fermat_factor(&b(invalid), 0).is_err());
        }
        for p in [3, 5, 17, 101, 997] {
            for q in [3, 7, 19, 103, 1009] {
                let n = b(p * q);
                let found = fermat_factor(&n, 1000).unwrap().unwrap();
                assert!(found.factor > b(1) && found.factor < n);
                assert_eq!(&found.factor * &found.cofactor, n);
            }
        }
        let p = (BigUint::one() << 1024usize) + b(643);
        let q = &p + b(2);
        assert_eq!(
            fermat_factor(&(&p * &q), 1).unwrap(),
            Some(Factors {
                factor: p,
                cofactor: q
            })
        );
    }

    #[test]
    fn roca_real_public_keys_and_original_detector_false_positive() {
        // Official CROCS-MUNI public samples and independent labels:
        // https://github.com/crocs-muni/roca/blob/master/roca/tests/test_fingerprint.py
        // https://github.com/crocs-muni/roca/tree/master/roca/tests/data
        let samples = [
            (
                true,
                concat!(
                    "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEBqcWmh9uPsqMPgt/43aFU",
                    "wpHvJ7BLJeGFuKsgxMal9gSFn+We3lSgr3wOcoiACtcZO7cxpb8eEXDXocZpMNQe",
                    "o+sh3t97ivXUKpHDT3IEW5bv1XyxgjAd3MJpZ+VQjpq4iZhtV+g33+cPmfw3xJj0",
                    "PBfDubBkz3BEQ9egM+A6ghaXqr8w+ynufTOzdnllqJBY47OXVL06HAB9KKI7DPp5",
                    "+dcRrG5MS093sGNLHs1oWRrwPH1TtipfLZEWPU70+PJoMa5GHthexfeIxRI//BLI",
                    "dCD9z+odG0pSw1IYJPs5mDSHObYqmG2OdrIom8Lri8BtE4FHhRuDoHGD0hBVn5Bj",
                    "IQIDAQAB"
                ),
            ),
            (
                false,
                concat!(
                    "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAuifwOO3sz3yHUO4Kg67/",
                    "ovYtMvzj6X8lf25wimtdIjoAkq/hxe44vaNkNxsCtTi+oVmw0ZGUwxpU4P5q64Ll",
                    "A6gxwF5cYj7L7G3FXjm0ICduZkp/jicOGU/I5kYjnyjjPgt9aozfVVfC3bqJ3WYN",
                    "Xw4oxb11HemqvRvQcC+4PY13JMsvkz/sXUFFSjcILQuGONNuAoTtlfJ81SsmlSpQ",
                    "lHfsefYk/SDoZQSagP0b5dAU6QikK0CjuP//Y7+ihtzZBKisWjia84H2U35U7cjb",
                    "KYw2AzLlytjUr0fB/7aeuk4eRmqMVQwCYDtvUpdQlJtM3YrbRw0wUvMEtxXgc0CG",
                    "VQIDAQAB"
                ),
            ),
        ];
        use base64ct::Encoding;
        for (expected, encoded) in samples {
            let der = base64ct::Base64::decode_vec(encoded).unwrap();
            let key =
                PublicKey::from_spki(&SubjectPublicKeyInfoOwned::from_der(&der).unwrap()).unwrap();
            assert_eq!(roca_fingerprint(&key.modulus), expected);
        }
        for invalid in [0, 1, 2, 3] {
            assert!(!roca_fingerprint(&b(invalid)));
        }
        // The first "fake_mods" vector in upstream test_fingerprint.py:
        // original per-prime detector positive, modern joint detector negative.
        let fake = BigUint::parse_bytes(
            b"72414128973967872688332736535017614208620368242015797102796086827882754006260204061799547004983731426777596445658889886861027045033760014948048067467947960318205453778973975867532910489227970143091184725760290172935872752222320334100097730483600892686353719855397381316384244147860260153198611313067061116317",
            10,
        ).unwrap();
        for prime in ROCA_PRIMES {
            let residue = (&fake % prime).to_u32().unwrap();
            let mut candidate = 1;
            let mut found = false;
            for _ in 0..prime {
                found |= residue == candidate;
                candidate = candidate * (65537 % prime) % prime;
            }
            assert!(found);
        }
        assert!(!roca_fingerprint(&fake));
    }

    fn check_batch(values: &[u64], expected: &[bool]) {
        let moduli: Vec<_> = values.iter().copied().map(b).collect();
        let results = batch_shared_factors(&moduli).unwrap();
        assert_eq!(results.len(), values.len());
        for ((n, result), expected) in moduli.iter().zip(results).zip(expected) {
            assert_eq!(
                result.is_some(),
                *expected,
                "modulus {n}, inputs {values:?}"
            );
            if let Some(factors) = result {
                assert!(factors.factor > b(1) && &factors.factor < n);
                assert_eq!(&factors.factor * &factors.cofactor, *n);
            }
        }
    }

    #[test]
    fn batch_duplicates_ambiguity_and_containment() {
        check_batch(&[], &[]);
        check_batch(&[15], &[false]);
        check_batch(&[15, 15, 15], &[false, false, false]);
        check_batch(&[15, 21, 35], &[true, true, true]);
        check_batch(&[15, 15, 21], &[true, true, true]);
        check_batch(&[15, 105], &[false, true]);
        check_batch(&[15, 105, 165], &[false, true, true]);
        check_batch(&[15, 105, 21], &[true, true, true]);
        check_batch(&[15, 77, 221], &[false, false, false]);
        check_batch(&[4, 8, 16], &[false, true, true]);
        assert!(batch_shared_factors(&[b(0)]).is_err());
        assert!(batch_shared_factors(&[b(15), b(1)]).is_err());
    }

    #[test]
    fn batch_exhaustive_and_randomized_pairwise_oracle() {
        fn compare(values: &[u64]) {
            let expected: Vec<_> = values
                .iter()
                .map(|&n| {
                    values.iter().any(|&other| {
                        let gcd = n.gcd(&other);
                        other != n && gcd > 1 && gcd < n
                    })
                })
                .collect();
            check_batch(values, &expected);
        }
        // For squarefree semiprimes, proper aggregate GCD iff a proper
        // pairwise GCD exists (including the gcd == n triangle case).
        let semiprimes = [15, 21, 33, 35, 55, 77];
        for a in semiprimes {
            for c in semiprimes {
                for d in semiprimes {
                    compare(&[a, c, d]);
                }
            }
        }
        let primes = [3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41];
        let mut state = 0x6a09_e667_f3bc_c909u64;
        for _ in 0..100 {
            let mut values = Vec::new();
            for _ in 0..40 {
                state = state.wrapping_mul(6364136223846793005).wrapping_add(1);
                let i = state as usize % primes.len();
                let j = (i + 1 + (state >> 32) as usize % (primes.len() - 1)) % primes.len();
                values.push(primes[i] * primes[j]);
            }
            compare(&values);
        }
    }

    #[test]
    fn batch_scale_sanity() {
        let primes: Vec<_> = (1009u64..)
            .filter(|&n| (2..=n.isqrt()).all(|d| n % d != 0))
            .take(2048)
            .collect();
        let moduli: Vec<_> = primes
            .as_chunks::<2>()
            .0
            .iter()
            .map(|&[p, q]| b(p) * b(q))
            .collect();
        let results = batch_shared_factors(&moduli).unwrap();
        assert_eq!(results.len(), 1024);
        assert!(results.iter().all(Option::is_none));
    }
}
