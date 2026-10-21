//! OpenSSL arithmetic for legacy NIST and Brainpool curves.
//! The original four curves keep their RustCrypto implementations in `main`.

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::thread;

use der::asn1::ObjectIdentifier;
use openssl::asn1::Asn1Object;
use openssl::bn::{BigNum, BigNumContext};
use openssl::ec::{EcGroup, EcKey, EcPoint};
use openssl::error::ErrorStack;

pub(crate) struct Curve {
    pub(crate) oid: ObjectIdentifier,
    pub(crate) name: &'static str,
}

/// The r1/t1 variants have distinct OIDs and generators, despite sharing a size.
pub(crate) const CURVES: &[Curve] = &[
    Curve {
        oid: ObjectIdentifier::new_unwrap("1.2.840.10045.3.1.1"),
        name: "P-192 (secp192r1)",
    },
    Curve {
        oid: ObjectIdentifier::new_unwrap("1.3.132.0.33"),
        name: "P-224 (secp224r1)",
    },
    Curve {
        oid: ObjectIdentifier::new_unwrap("1.3.36.3.3.2.8.1.1.1"),
        name: "brainpoolP160r1",
    },
    Curve {
        oid: ObjectIdentifier::new_unwrap("1.3.36.3.3.2.8.1.1.2"),
        name: "brainpoolP160t1",
    },
    Curve {
        oid: ObjectIdentifier::new_unwrap("1.3.36.3.3.2.8.1.1.3"),
        name: "brainpoolP192r1",
    },
    Curve {
        oid: ObjectIdentifier::new_unwrap("1.3.36.3.3.2.8.1.1.4"),
        name: "brainpoolP192t1",
    },
    Curve {
        oid: ObjectIdentifier::new_unwrap("1.3.36.3.3.2.8.1.1.5"),
        name: "brainpoolP224r1",
    },
    Curve {
        oid: ObjectIdentifier::new_unwrap("1.3.36.3.3.2.8.1.1.6"),
        name: "brainpoolP224t1",
    },
    Curve {
        oid: ObjectIdentifier::new_unwrap("1.3.36.3.3.2.8.1.1.7"),
        name: "brainpoolP256r1",
    },
    Curve {
        oid: ObjectIdentifier::new_unwrap("1.3.36.3.3.2.8.1.1.8"),
        name: "brainpoolP256t1",
    },
    Curve {
        oid: ObjectIdentifier::new_unwrap("1.3.36.3.3.2.8.1.1.9"),
        name: "brainpoolP320r1",
    },
    Curve {
        oid: ObjectIdentifier::new_unwrap("1.3.36.3.3.2.8.1.1.10"),
        name: "brainpoolP320t1",
    },
    Curve {
        oid: ObjectIdentifier::new_unwrap("1.3.36.3.3.2.8.1.1.11"),
        name: "brainpoolP384r1",
    },
    Curve {
        oid: ObjectIdentifier::new_unwrap("1.3.36.3.3.2.8.1.1.12"),
        name: "brainpoolP384t1",
    },
    Curve {
        oid: ObjectIdentifier::new_unwrap("1.3.36.3.3.2.8.1.1.13"),
        name: "brainpoolP512r1",
    },
    Curve {
        oid: ObjectIdentifier::new_unwrap("1.3.36.3.3.2.8.1.1.14"),
        name: "brainpoolP512t1",
    },
];

fn group(curve: &Curve) -> Result<EcGroup, ErrorStack> {
    let nid = Asn1Object::from_str(&curve.oid.to_string())?.nid();
    EcGroup::from_curve_name(nid)
}

/// Tests Q = dG over an inclusive scalar range, with one multiplication per worker
/// followed by repeated additions of G.
pub(crate) fn search(
    curve: &Curve,
    point: &[u8],
    lo: u64,
    hi: u64,
    threads: usize,
) -> Result<Option<u64>, String> {
    let search = || -> Result<Option<u64>, ErrorStack> {
        let group = group(curve)?;
        let mut ctx = BigNumContext::new()?;
        let target = EcPoint::from_bytes(&group, point, &mut ctx)?;
        EcKey::from_public_key(&group, &target)?.check_key()?;

        let lo = lo.max(1);
        if lo > hi {
            return Ok(None);
        }
        let workers = (threads as u64).min(hi - lo + 1);
        let found = AtomicU64::new(0);
        let done = AtomicBool::new(false);
        thread::scope(|scope| -> Result<(), ErrorStack> {
            let mut handles = Vec::new();
            for index in 0..workers {
                let (start, end) = crate::range_chunk(lo, hi, workers, index);
                let (group, target, found, done) = (&group, &target, &found, &done);
                handles.push(scope.spawn(move || -> Result<(), ErrorStack> {
                    // OpenSSL mutates scratch contexts; each worker must own its context.
                    let mut ctx = BigNumContext::new()?;
                    let scalar = BigNum::from_slice(&start.to_be_bytes())?;
                    let mut current = EcPoint::new(group)?;
                    current.mul_generator2(group, &scalar, &mut ctx)?;
                    let mut next = EcPoint::new(group)?;
                    let generator = group.generator_opt().ok_or_else(ErrorStack::get)?;
                    for candidate in start..=end {
                        if done.load(Ordering::Relaxed) {
                            break;
                        }
                        if current.eq(group, target, &mut ctx)? {
                            found.store(candidate, Ordering::SeqCst);
                            done.store(true, Ordering::SeqCst);
                            break;
                        }
                        if candidate != end {
                            next.add(group, &current, generator, &mut ctx)?;
                            // Reuse two point buffers instead of allocating per candidate.
                            std::mem::swap(&mut current, &mut next);
                        }
                    }
                    Ok(())
                }));
            }
            for handle in handles {
                handle.join().expect("curve worker panicked")?;
            }
            Ok(())
        })?;
        Ok(done
            .load(Ordering::SeqCst)
            .then(|| found.load(Ordering::SeqCst)))
    };
    search().map_err(|e| format!("cannot check {} public key: {e}", curve.name))
}

#[cfg(test)]
mod tests {
    use super::*;
    use der::Encode;
    use openssl::ec::PointConversionForm;

    fn point(curve: &Curve, scalar: u64, form: PointConversionForm) -> Vec<u8> {
        let group = group(curve).unwrap();
        let mut ctx = BigNumContext::new().unwrap();
        let scalar = BigNum::from_slice(&scalar.to_be_bytes()).unwrap();
        let mut point = EcPoint::new(&group).unwrap();
        point.mul_generator2(&group, &scalar, &mut ctx).unwrap();
        point.to_bytes(&group, form, &mut ctx).unwrap()
    }

    #[test]
    fn searches_every_added_curve_and_point_encoding() {
        assert_eq!(CURVES.len(), 16);
        for curve in CURVES {
            for form in [
                PointConversionForm::COMPRESSED,
                PointConversionForm::UNCOMPRESSED,
            ] {
                let point = point(curve, 7, form);
                let spki = crate::tests::ec_spki(curve.oid, &point);
                let parsed = crate::parse_spki(&spki.to_der().unwrap()).unwrap().0;
                assert_eq!(
                    crate::check_key(&parsed, 7, 7, 3).unwrap(),
                    crate::KeyCheck::Supported(curve.name, Some(7))
                );
                for threads in [1, 3, 20] {
                    assert_eq!(
                        search(curve, &point, 0, 7, threads).unwrap(),
                        Some(7),
                        "{}",
                        curve.name
                    );
                    assert_eq!(search(curve, &point, 8, 10, threads).unwrap(), None);
                }
            }
        }
    }

    #[test]
    fn rejects_invalid_points_and_excludes_zero() {
        for curve in CURVES {
            assert!(search(curve, &[0], 0, 7, 1).is_err(), "{}", curve.name);
            assert!(search(curve, &[4, 1, 2], 1, 7, 1).is_err());
            let point = point(curve, 1, PointConversionForm::UNCOMPRESSED);
            assert_eq!(search(curve, &point, 0, 0, 1).unwrap(), None);
            assert_eq!(search(curve, &point, 1, 1, 1).unwrap(), Some(1));
        }
    }

    #[test]
    fn searches_ranges_at_u64_maximum() {
        for curve in CURVES {
            let point = point(curve, u64::MAX, PointConversionForm::UNCOMPRESSED);
            assert_eq!(
                search(curve, &point, u64::MAX - 3, u64::MAX, 3).unwrap(),
                Some(u64::MAX),
                "{}",
                curve.name
            );
        }
    }
}
