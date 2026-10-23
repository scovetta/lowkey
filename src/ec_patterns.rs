//! Full-width, variable-time public-key comparisons for explicitly bounded pattern searches.

use std::collections::HashMap;

use der::asn1::ObjectIdentifier;
use num_bigint::BigUint;
use spki::SubjectPublicKeyInfoOwned;

use crate::{KeyCheck, curves, patterns};

pub(crate) type Plans = HashMap<(ObjectIdentifier, String, usize), patterns::Plan>;

pub(crate) enum Prepared<'a> {
    Unsupported(String),
    Supported(Key<'a>),
}

pub(crate) enum CurveInfo {
    Unsupported(String),
    Supported {
        name: &'static str,
        oid: ObjectIdentifier,
        order: BigUint,
    },
}

pub(crate) struct Key<'a> {
    pub(crate) name: &'static str,
    pub(crate) plan: patterns::Plan,
    oid: ObjectIdentifier,
    point: &'a [u8],
}

macro_rules! order {
    ($krate:ident, $curve:ident) => {{
        use $krate::elliptic_curve::Curve;
        BigUint::from_bytes_be(<$krate::$curve as Curve>::ORDER.to_be_bytes().as_ref())
    }};
    ($krate:ident, $curve:ident, legacy) => {{
        use $krate::elliptic_curve::{Curve, bigint::Encoding};
        BigUint::from_bytes_be(<$krate::$curve as Curve>::ORDER.to_be_bytes().as_ref())
    }};
}

fn subgroup_order(oid: ObjectIdentifier) -> Option<BigUint> {
    if let Some(curve) = curves::CURVES.iter().find(|curve| curve.oid == oid) {
        return Some(curves::order(curve));
    }
    Some(match oid {
        crate::OID_P192 => order!(p192, NistP192, legacy),
        crate::OID_P224 => order!(p224, NistP224, legacy),
        crate::OID_P256 => order!(p256, NistP256),
        crate::OID_P384 => order!(p384, NistP384),
        crate::OID_P521 => order!(p521, NistP521),
        crate::OID_K256 => order!(k256, Secp256k1),
        _ => return None,
    })
}

pub(crate) fn curve_info(spki: &SubjectPublicKeyInfoOwned) -> Result<CurveInfo, String> {
    // An empty range still performs the existing strict point/curve validation.
    let name = match crate::check_key(spki, 0, 0, 1)? {
        KeyCheck::Supported(name, _) => name,
        KeyCheck::Unsupported(reason) => return Ok(CurveInfo::Unsupported(reason)),
    };
    let oid = spki
        .algorithm
        .parameters
        .as_ref()
        .ok_or("missing named curve")?
        .decode_as()
        .map_err(|e| format!("invalid named curve: {e}"))?;
    let order = subgroup_order(oid).ok_or("missing supported curve order")?;
    Ok(CurveInfo::Supported { name, oid, order })
}

pub(crate) fn prepare<'a>(
    spki: &'a SubjectPublicKeyInfoOwned,
    pattern: patterns::Pattern,
    bits: usize,
    plans: &mut Plans,
) -> Result<Prepared<'a>, String> {
    let (name, oid, order) = match curve_info(spki)? {
        CurveInfo::Supported { name, oid, order } => (name, oid, order),
        CurveInfo::Unsupported(reason) => return Ok(Prepared::Unsupported(reason)),
    };
    let cache_key = (oid, pattern.to_string(), bits);
    let plan = if let Some(plan) = plans.get(&cache_key) {
        plan.clone()
    } else {
        let width = order.bits();
        let plan = patterns::Plan::new(order, pattern, bits)
            .map_err(|e| format!("{name} ({width}-bit scalars): --pattern-bits {bits}: {e}"))?;
        plans.insert(cache_key, plan.clone());
        plan
    };
    let point = spki
        .subject_public_key
        .as_bytes()
        .ok_or("malformed public key bit string")?;
    Ok(Prepared::Supported(Key {
        name,
        plan,
        oid,
        point,
    }))
}

macro_rules! search {
    ($krate:ident, $public_key:ty, $key:expr, $budget:expr, $threads:expr) => {{
        use $krate::ProjectivePoint;
        use $krate::elliptic_curve::group::Group;
        let key = $key;
        let target = <$public_key>::from_sec1_bytes(key.point)
            .map_err(|e| format!("invalid EC public key point: {e}"))?
            .to_projective();
        let mut weights = Vec::with_capacity(key.plan.width);
        let mut current = ProjectivePoint::GENERATOR;
        let mut all_ones = ProjectivePoint::IDENTITY;
        for _ in 0..key.plan.width {
            weights.push(current);
            all_ones += current;
            current = Group::double(&current);
        }
        key.plan.search($budget, $threads, |candidate| {
            let ones: u32 = candidate.iter_u64_digits().map(u64::count_ones).sum();
            let dense = ones as usize > key.plan.width / 2;
            let mut point = if dense {
                all_ones
            } else {
                ProjectivePoint::IDENTITY
            };
            for (i, weight) in weights.iter().enumerate() {
                if candidate.bit(i as u64) != dense {
                    if dense {
                        point -= *weight;
                    } else {
                        point += *weight;
                    }
                }
            }
            point == target
        })
    }};
}

impl Key<'_> {
    pub(crate) fn search(&self, budget: u64, threads: usize) -> Result<Option<BigUint>, String> {
        // Refuse oversized spaces before constructing any point tables.
        if self.plan.count > BigUint::from(budget) {
            return Err(format!(
                "{} ({}-bit scalars): {} candidates exceed the explicit --max-candidates budget {budget}; no pattern candidates were searched",
                self.name, self.plan.width, self.plan.count
            ));
        }

        if let Some(curve) = curves::CURVES.iter().find(|curve| curve.oid == self.oid) {
            return curves::search_pattern(curve, self.point, &self.plan, budget, threads);
        }
        match self.oid {
            crate::OID_P192 => search!(
                p192,
                p192::elliptic_curve::PublicKey<p192::NistP192>,
                self,
                budget,
                threads
            ),
            crate::OID_P224 => search!(p224, p224::PublicKey, self, budget, threads),
            crate::OID_P256 => search!(p256, p256::PublicKey, self, budget, threads),
            crate::OID_P384 => search!(p384, p384::PublicKey, self, budget, threads),
            crate::OID_P521 => search!(p521, p521::PublicKey, self, budget, threads),
            crate::OID_K256 => search!(k256, k256::PublicKey, self, budget, threads),
            _ => Err("unsupported pattern-search curve".into()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn all_subgroup_orders_match_independent_parameters() {
        let references: serde_json::Value =
            serde_json::from_str(include_str!("../tests/fixtures/ec-vectors.json")).unwrap();
        for curve in references["curves"].as_array().unwrap() {
            let oid = ObjectIdentifier::new(curve["oid"].as_str().unwrap()).unwrap();
            let expected =
                BigUint::parse_bytes(curve["order"].as_str().unwrap().as_bytes(), 16).unwrap();
            assert_eq!(subgroup_order(oid).unwrap(), expected);
            assert_eq!(expected.bits(), curve["bits"].as_u64().unwrap());
        }
    }

    #[test]
    fn rustcrypto_searches_full_width_sparse_and_dense_scalars() {
        macro_rules! check {
            ($krate:ident, $public_key:ty, $oid:expr, $encoding:ident, $encode:ident) => {{
                use $krate::elliptic_curve::{group::Group, sec1::$encoding};
                let width = subgroup_order($oid).unwrap().bits() as usize;
                let mut high = $krate::ProjectivePoint::GENERATOR;
                for _ in 1..width {
                    high = Group::double(&high);
                }
                for (pattern, point, expected, count) in [
                    (
                        patterns::Pattern::ZeroRun,
                        high,
                        BigUint::from(1u8) << (width - 1),
                        2u64,
                    ),
                    (
                        patterns::Pattern::OneRun,
                        high - $krate::ProjectivePoint::GENERATOR,
                        (BigUint::from(1u8) << (width - 1)) - 1u8,
                        1u64,
                    ),
                ] {
                    let public = <$public_key>::from_affine(point.to_affine()).unwrap();
                    let encoded = $encoding::$encode(&public, true);
                    let spki = crate::tests::ec_spki($oid, encoded.as_bytes());
                    let Prepared::Supported(key) =
                        prepare(&spki, pattern, width - 1, &mut Plans::new()).unwrap()
                    else {
                        panic!("supported curve skipped");
                    };
                    assert_eq!(key.plan.width, width);
                    assert_eq!(key.plan.count, BigUint::from(count));
                    for threads in [1, 3] {
                        assert_eq!(key.search(count, threads).unwrap(), Some(expected.clone()));
                    }
                    assert!(expected.bits() > 64);
                }
            }};
        }
        check!(
            p192,
            p192::elliptic_curve::PublicKey<p192::NistP192>,
            crate::OID_P192,
            ToEncodedPoint,
            to_encoded_point
        );
        check!(
            p224,
            p224::PublicKey,
            crate::OID_P224,
            ToEncodedPoint,
            to_encoded_point
        );
        check!(
            p256,
            p256::PublicKey,
            crate::OID_P256,
            ToSec1Point,
            to_sec1_point
        );
        check!(
            p384,
            p384::PublicKey,
            crate::OID_P384,
            ToSec1Point,
            to_sec1_point
        );
        check!(
            p521,
            p521::PublicKey,
            crate::OID_P521,
            ToSec1Point,
            to_sec1_point
        );
        check!(
            k256,
            k256::PublicKey,
            crate::OID_K256,
            ToSec1Point,
            to_sec1_point
        );
    }
}
