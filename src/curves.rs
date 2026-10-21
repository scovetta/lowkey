//! RFC 5639 Brainpool arithmetic for public-key inspection, not signing or key generation.
//! All registered groups have prime order and cofactor one. Operations are variable-time.

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::thread;

use crypto_bigint::{
    Odd, U192, U256, U320, U384, U512, Uint,
    modular::{FixedMontyForm, FixedMontyParams},
};
use der::asn1::ObjectIdentifier;

mod params;
pub(crate) use params::CURVES;

pub(crate) struct Curve {
    pub(crate) oid: ObjectIdentifier,
    pub(crate) name: &'static str,
    bits: usize,
    p: &'static str,
    a: &'static str,
    b: &'static str,
    gx: &'static str,
    gy: &'static str,
    #[cfg(test)]
    order: &'static str,
}

type Field<const L: usize> = FixedMontyForm<L>;

#[derive(Clone, Copy)]
struct Affine<const L: usize> {
    x: Field<L>,
    y: Field<L>,
}

#[derive(Clone, Copy)]
struct Jacobian<const L: usize> {
    x: Field<L>,
    y: Field<L>,
    z: Field<L>,
}

struct Group<const L: usize> {
    modulus: Uint<L>,
    params: FixedMontyParams<L>,
    a: Field<L>,
    b: Field<L>,
    generator: Affine<L>,
    zero: Field<L>,
    one: Field<L>,
    width: usize,
}

// Use the smallest word-aligned integer that holds the field on both 32/64-bit targets.
macro_rules! with_group {
    ($curve:expr, |$group:ident| $body:expr) => {{
        let curve = $curve;
        match curve.bits {
            160 | 192 => {
                let $group = Group::<{ U192::LIMBS }>::new(curve);
                $body
            }
            224 | 256 => {
                let $group = Group::<{ U256::LIMBS }>::new(curve);
                $body
            }
            320 => {
                let $group = Group::<{ U320::LIMBS }>::new(curve);
                $body
            }
            384 => {
                let $group = Group::<{ U384::LIMBS }>::new(curve);
                $body
            }
            512 => {
                let $group = Group::<{ U512::LIMBS }>::new(curve);
                $body
            }
            _ => unreachable!("unregistered Brainpool field size"),
        }
    }};
}

fn integer<const L: usize>(hex: &str) -> Uint<L> {
    // Only compile-time domain parameters and checked-in test vectors reach this helper.
    Uint::from_be_hex(&format!("{hex:0>width$}", width = Uint::<L>::BYTES * 2))
}

impl<const L: usize> Group<L> {
    fn new(curve: &Curve) -> Self {
        let modulus = integer(curve.p);
        let params = FixedMontyParams::new_vartime(
            Odd::new(modulus).expect("RFC 5639 field modulus is odd"),
        );
        let field = |hex| Field::new(&integer(hex), &params);
        Self {
            modulus,
            params,
            a: field(curve.a),
            b: field(curve.b),
            generator: Affine {
                x: field(curve.gx),
                y: field(curve.gy),
            },
            zero: Field::zero(&params),
            one: Field::one(&params),
            width: curve.bits / 8,
        }
    }

    fn infinity(&self) -> Jacobian<L> {
        Jacobian {
            x: self.zero,
            y: self.one,
            z: self.zero,
        }
    }

    fn project(&self, point: Affine<L>) -> Jacobian<L> {
        Jacobian {
            x: point.x,
            y: point.y,
            z: self.one,
        }
    }

    fn coordinate(&self, bytes: &[u8]) -> Result<Field<L>, String> {
        let mut padded = [0; 64];
        padded[64 - bytes.len()..].copy_from_slice(bytes);
        let value = Uint::from_be_slice(&padded[64 - Uint::<L>::BYTES..]);
        if value >= self.modulus {
            return Err("EC coordinate is outside the prime field".into());
        }
        Ok(Field::new(&value, &self.params))
    }

    fn rhs(&self, x: Field<L>) -> Field<L> {
        x.square() * x + self.a * x + self.b
    }

    fn decode(&self, bytes: &[u8]) -> Result<Affine<L>, String> {
        let point = match bytes.first().copied() {
            Some(prefix @ (2 | 3)) if bytes.len() == 1 + self.width => {
                let x = self.coordinate(&bytes[1..])?;
                let rhs = self.rhs(x);
                // Every RFC 5639 field has p = 3 mod 4; verify the root before using it.
                let exponent = self.modulus.wrapping_add(&Uint::ONE).shr_vartime(2);
                let mut y = rhs.pow_vartime(&exponent);
                if y.square() != rhs {
                    return Err("compressed EC point has no square root".into());
                }
                let odd = prefix == 3;
                if y.retrieve().bit_vartime(0) != odd {
                    y = -y;
                }
                if y.retrieve().bit_vartime(0) != odd {
                    return Err("compressed EC point has invalid parity".into());
                }
                Affine { x, y }
            }
            Some(4) if bytes.len() == 1 + 2 * self.width => Affine {
                x: self.coordinate(&bytes[1..1 + self.width])?,
                y: self.coordinate(&bytes[1 + self.width..])?,
            },
            _ => return Err("invalid SEC1 point encoding, length, or point at infinity".into()),
        };
        if point.y.square() != self.rhs(point.x) {
            return Err("EC point is not on the named curve".into());
        }
        // Cofactor one means every non-infinity point on these curves is in the subgroup.
        Ok(point)
    }

    fn double(&self, point: Jacobian<L>) -> Jacobian<L> {
        if point.z == self.zero || point.y == self.zero {
            return self.infinity();
        }
        // General short-Weierstrass Jacobian doubling (EFD dbl-2009-l).
        let xx = point.x.square();
        let yy = point.y.square();
        let yyyy = yy.square();
        let zz = point.z.square();
        let s = ((point.x + yy).square() - xx - yyyy).double();
        let m = xx.double() + xx + self.a * zz.square();
        let x = m.square() - s.double();
        let y = m * (s - x) - yyyy.double().double().double();
        let z = (point.y * point.z).double();
        Jacobian { x, y, z }
    }

    fn add(&self, point: Jacobian<L>, affine: Affine<L>) -> Jacobian<L> {
        if point.z == self.zero {
            return self.project(affine);
        }
        // Mixed Jacobian/affine addition (EFD madd); handle equal and inverse points.
        let zz = point.z.square();
        let u = affine.x * zz;
        let s = affine.y * point.z * zz;
        let h = u - point.x;
        let r = s - point.y;
        if h == self.zero {
            return if r == self.zero {
                self.double(point)
            } else {
                self.infinity()
            };
        }
        let hh = h.square();
        let hhh = h * hh;
        let v = point.x * hh;
        let x = r.square() - hhh - v.double();
        let y = r * (v - x) - point.y * hhh;
        let z = point.z * h;
        Jacobian { x, y, z }
    }

    fn multiply(&self, point: Affine<L>, scalar: &Uint<L>) -> Jacobian<L> {
        let mut result = self.infinity();
        for bit in (0..scalar.bits_vartime()).rev() {
            result = self.double(result);
            if scalar.bit_vartime(bit) {
                result = self.add(result, point);
            }
        }
        result
    }

    fn matches(&self, point: Jacobian<L>, target: Affine<L>) -> bool {
        if point.z == self.zero {
            return false;
        }
        let zz = point.z.square();
        point.x == target.x * zz && point.y == target.y * zz * point.z
    }

    fn search(
        &self,
        bytes: &[u8],
        lo: u64,
        hi: u64,
        threads: usize,
    ) -> Result<Option<u64>, String> {
        let target = self.decode(bytes)?;
        if threads == 0 {
            return Err("thread count must be positive".into());
        }
        let lo = lo.max(1);
        if lo > hi {
            return Ok(None);
        }
        let workers = (threads as u64).min(hi - lo + 1);
        let found = AtomicU64::new(0);
        let done = AtomicBool::new(false);
        thread::scope(|scope| {
            for index in 0..workers {
                let (start, end) = crate::range_chunk(lo, hi, workers, index);
                let (found, done) = (&found, &done);
                scope.spawn(move || {
                    let mut point = self.multiply(self.generator, &Uint::from_u64(start));
                    for candidate in start..=end {
                        if done.load(Ordering::Relaxed) {
                            break;
                        }
                        if self.matches(point, target) {
                            found.store(candidate, Ordering::SeqCst);
                            done.store(true, Ordering::SeqCst);
                            break;
                        }
                        if candidate != end {
                            point = self.add(point, self.generator);
                        }
                    }
                });
            }
        });
        Ok(done
            .load(Ordering::SeqCst)
            .then(|| found.load(Ordering::SeqCst)))
    }
}

pub(crate) fn search(
    curve: &Curve,
    point: &[u8],
    lo: u64,
    hi: u64,
    threads: usize,
) -> Result<Option<u64>, String> {
    with_group!(curve, |group| group.search(point, lo, hi, threads))
        .map_err(|e| format!("cannot check {} public key: {e}", curve.name))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde::Deserialize;

    #[derive(Deserialize)]
    struct References {
        curves: Vec<ReferenceCurve>,
    }

    #[derive(Deserialize)]
    struct ReferenceCurve {
        oid: String,
        name: String,
        bits: usize,
        p: String,
        a: String,
        b: String,
        gx: String,
        gy: String,
        order: String,
        cofactor: u64,
        vectors: Vec<Vector>,
        order_minus_one: String,
    }

    #[derive(Deserialize)]
    struct Vector {
        scalar: u64,
        compressed: String,
        uncompressed: String,
    }

    fn references() -> Vec<ReferenceCurve> {
        // Generated independently with OpenSSL; never derive expectations from this backend.
        serde_json::from_str::<References>(include_str!("../tests/fixtures/ec-vectors.json"))
            .unwrap()
            .curves
    }

    fn bytes(hex: &str) -> Vec<u8> {
        (0..hex.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
            .collect()
    }

    #[test]
    fn all_twenty_curves_match_independent_reference_keys() {
        let references = references();
        assert_eq!(references.len(), 20);
        assert_eq!(CURVES.len(), 14);
        for reference in references {
            let oid = ObjectIdentifier::new(&reference.oid).unwrap();
            for point in [vec![], vec![0], vec![2], vec![4, 1, 2]] {
                let spki = crate::tests::ec_spki(oid, &point);
                assert!(
                    crate::check_key(&spki, 0, 0, 1).is_err(),
                    "{}",
                    reference.name
                );
            }
            for coordinate in [0, 1] {
                let mut point = bytes(&reference.vectors[0].uncompressed);
                let width = reference.bits.div_ceil(8);
                let start = 1 + coordinate * width;
                point[start..start + width].copy_from_slice(&bytes(&reference.p));
                let spki = crate::tests::ec_spki(oid, &point);
                assert!(
                    crate::check_key(&spki, 0, 0, 1).is_err(),
                    "{}",
                    reference.name
                );
            }
            for vector in &reference.vectors {
                for encoded in [&vector.compressed, &vector.uncompressed] {
                    let spki = crate::tests::ec_spki(oid, &bytes(encoded));
                    let result = crate::check_key(&spki, vector.scalar, vector.scalar, 1).unwrap();
                    let crate::KeyCheck::Supported(name, Some(found)) = result else {
                        panic!("{} scalar {}: {result:?}", reference.name, vector.scalar);
                    };
                    assert_eq!(name, reference.name);
                    assert_eq!(found, vector.scalar);
                    if vector.scalar == u64::MAX {
                        assert_eq!(
                            crate::check_key(&spki, u64::MAX - 3, u64::MAX, 3).unwrap(),
                            crate::KeyCheck::Supported(name, Some(u64::MAX))
                        );
                    }
                }
            }
        }
    }

    #[test]
    fn brainpool_parameters_and_group_law_match_reference() {
        let references = references();
        for curve in CURVES {
            let reference = references
                .iter()
                .find(|reference| reference.oid == curve.oid.to_string())
                .unwrap();
            assert_eq!(curve.bits, reference.bits);
            assert_eq!(curve.name, reference.name);
            assert_eq!(reference.cofactor, 1);
            with_group!(curve, |group| {
                for (published, expected) in [
                    (curve.p, reference.p.as_str()),
                    (curve.a, reference.a.as_str()),
                    (curve.b, reference.b.as_str()),
                    (curve.gx, reference.gx.as_str()),
                    (curve.gy, reference.gy.as_str()),
                    (curve.order, reference.order.as_str()),
                ] {
                    assert!(
                        published
                            .trim_start_matches('0')
                            .eq_ignore_ascii_case(expected.trim_start_matches('0')),
                        "{} domain parameter differs: {published} != {expected}",
                        curve.name
                    );
                }
                assert_eq!(group.modulus.as_words()[0] & 3, 3);
                assert_eq!(group.generator.y.square(), group.rhs(group.generator.x));
                let order = integer(curve.order);
                let infinity = group.infinity();
                assert_eq!(group.multiply(group.generator, &Uint::ZERO).z, group.zero);
                assert_eq!(group.multiply(group.generator, &order).z, group.zero);
                assert!(group.matches(
                    group.multiply(group.generator, &order.wrapping_add(&Uint::ONE)),
                    group.generator
                ));
                let inverse = group.decode(&bytes(&reference.order_minus_one)).unwrap();
                assert!(group.matches(
                    group.multiply(group.generator, &order.wrapping_sub(&Uint::ONE)),
                    inverse
                ));
                assert_eq!(
                    group.add(group.project(group.generator), inverse).z,
                    group.zero
                );
                assert!(group.matches(group.add(infinity, group.generator), group.generator));
                assert_eq!(group.double(infinity).z, group.zero);
                assert!(
                    group.matches(
                        group.add(group.project(group.generator), group.generator),
                        group
                            .decode(&bytes(&reference.vectors[1].uncompressed))
                            .unwrap()
                    )
                );
                let scale = Field::new(&Uint::from_u64(7), &group.params);
                let scaled = Jacobian {
                    x: group.generator.x * scale.square(),
                    y: group.generator.y * scale.square() * scale,
                    z: scale,
                };
                assert!(group.matches(scaled, group.generator));
                assert!(
                    group.matches(
                        group.add(scaled, group.generator),
                        group
                            .decode(&bytes(&reference.vectors[1].uncompressed))
                            .unwrap()
                    )
                );
            });
        }
    }

    #[test]
    fn brainpool_search_covers_ranges_and_threads() {
        let references = references();
        for curve in CURVES {
            let reference = references
                .iter()
                .find(|reference| reference.oid == curve.oid.to_string())
                .unwrap();
            for encoding in [
                &reference.vectors[3].compressed,
                &reference.vectors[3].uncompressed,
            ] {
                let point = bytes(encoding);
                for threads in [1, 3, 20] {
                    assert_eq!(search(curve, &point, 0, 7, threads).unwrap(), Some(7));
                    assert_eq!(search(curve, &point, 8, 10, threads).unwrap(), None);
                }
                assert_eq!(search(curve, &point, 0, 0, 1).unwrap(), None);
                assert_eq!(search(curve, &point, 7, 7, 20).unwrap(), Some(7));
                assert_eq!(
                    search(curve, &point, 1, 7, 0).unwrap_err(),
                    format!(
                        "cannot check {} public key: thread count must be positive",
                        curve.name
                    )
                );
            }
            let maximum = reference
                .vectors
                .iter()
                .find(|v| v.scalar == u64::MAX)
                .unwrap();
            assert_eq!(
                search(
                    curve,
                    &bytes(&maximum.uncompressed),
                    u64::MAX - 3,
                    u64::MAX,
                    3
                )
                .unwrap(),
                Some(u64::MAX)
            );
        }
    }

    #[test]
    fn brainpool_rejects_noncanonical_and_off_curve_points() {
        for curve in CURVES {
            with_group!(curve, |group| {
                let generator = bytes(&format!("04{}{}", curve.gx, curve.gy));
                assert!(group.decode(&generator).is_ok());
                for invalid in [vec![], vec![0], vec![2], vec![4, 1, 2]] {
                    assert!(group.decode(&invalid).is_err());
                }
                let mut extra = generator.clone();
                extra.push(0);
                assert!(group.decode(&extra).is_err());
                assert!(group.decode(&generator[..generator.len() - 1]).is_err());
                for prefix in [0, 1, 5, 6, 7, 255] {
                    let mut invalid = generator.clone();
                    invalid[0] = prefix;
                    assert!(group.decode(&invalid).is_err());
                }
                for coordinate in [0, 1] {
                    let mut invalid = generator.clone();
                    let start = 1 + coordinate * group.width;
                    invalid[start..start + group.width].copy_from_slice(&bytes(curve.p));
                    assert!(group.decode(&invalid).is_err());
                }
                let mut off_curve = generator.clone();
                off_curve[1 + group.width..].fill(0);
                assert!(group.decode(&off_curve).is_err());
                assert!(search(curve, &off_curve, 0, 0, 1).is_err());
                // RFC 5639 requires B to be a nonsquare, including for the t1 variants.
                let mut compressed = vec![0; group.width + 1];
                compressed[0] = 2;
                assert!(group.decode(&compressed).is_err());
                compressed[1..].copy_from_slice(&bytes(curve.p));
                assert!(group.decode(&compressed).is_err());
                let mut opposite = vec![2 + u8::from(!group.generator.y.retrieve().bit_vartime(0))];
                opposite.extend_from_slice(&bytes(curve.gx));
                let opposite = group.decode(&opposite).unwrap();
                assert!(!group.matches(group.project(group.generator), opposite));
            });
        }
    }

    #[test]
    #[ignore = "manual release-mode throughput measurement"]
    fn brainpool_search_throughput() {
        let references = references();
        for name in ["brainpoolP160r1", "brainpoolP256r1", "brainpoolP512r1"] {
            let curve = CURVES.iter().find(|curve| curve.name == name).unwrap();
            let reference = references.iter().find(|curve| curve.name == name).unwrap();
            let target = bytes(
                &reference
                    .vectors
                    .iter()
                    .find(|v| v.scalar == u64::MAX)
                    .unwrap()
                    .uncompressed,
            );
            let start = std::time::Instant::now();
            assert_eq!(search(curve, &target, 1, 20_000, 1).unwrap(), None);
            eprintln!("{name}: 20,000 candidates in {:?}", start.elapsed());
        }
    }
}
