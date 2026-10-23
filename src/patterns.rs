//! Exact, bounded scalar-pattern searches.
//!
//! The width is always `order.bits()`, not the field size or a byte-rounded
//! width. Leading zeros inside that width participate in every pattern. The
//! domain is precisely `1..order`; zero and the order itself are excluded.

use std::fmt;
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, Ordering};

use num_bigint::BigUint;
use num_traits::{One, ToPrimitive, Zero};

#[derive(Clone, Copy, Debug, PartialEq, Eq, clap::ValueEnum)]
pub(crate) enum Pattern {
    ZeroRun,
    OneRun,
    Zeros,
    Ones,
}

impl fmt::Display for Pattern {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::ZeroRun => "zero-run",
            Self::OneRun => "one-run",
            Self::Zeros => "zeros",
            Self::Ones => "ones",
        })
    }
}

impl Pattern {
    fn advance(self, state: usize, bit: bool, threshold: usize) -> usize {
        if state == threshold {
            return threshold;
        }
        let target = matches!(self, Self::OneRun | Self::Ones);
        if bit == target {
            state + 1
        } else if matches!(self, Self::ZeroRun | Self::OneRun) {
            0
        } else {
            state
        }
    }

    fn accepts_zero(self) -> bool {
        matches!(self, Self::ZeroRun | Self::Zeros)
    }
}

#[derive(Clone, Debug)]
pub(crate) struct Plan {
    pub(crate) count: BigUint,
    pub(crate) width: usize,
    upper: BigUint,
    pattern: Pattern,
    threshold: usize,
}

impl Plan {
    pub(crate) fn new(order: BigUint, pattern: Pattern, bits: usize) -> Result<Self, String> {
        if order.is_zero() {
            return Err("subgroup order must be positive".into());
        }
        let width = usize::try_from(order.bits())
            .map_err(|_| "subgroup order bit width does not fit usize")?;
        if bits == 0 || bits > width {
            return Err(format!("pattern bits must be in 1..={width}"));
        }
        let upper = order - BigUint::one();

        // A state is the capped match count/current run. Acceptance is
        // absorbing, so overlapping runs never count a scalar twice. The two
        // rows distinguish prefixes below the upper bound from tight ones.
        let mut loose = vec![BigUint::zero(); bits + 1];
        let mut tight = vec![BigUint::zero(); bits + 1];
        tight[0] = BigUint::one();
        for position in (0..width).rev() {
            let upper_bit = upper.bit(position as u64);
            let mut next_loose = vec![BigUint::zero(); bits + 1];
            let mut next_tight = vec![BigUint::zero(); bits + 1];
            for state in 0..=bits {
                for bit in [false, true] {
                    let next = pattern.advance(state, bit, bits);
                    next_loose[next] += &loose[state];
                    if !bit || upper_bit {
                        if bit == upper_bit {
                            next_tight[next] += &tight[state];
                        } else {
                            next_loose[next] += &tight[state];
                        }
                    }
                }
            }
            loose = next_loose;
            tight = next_tight;
        }
        let mut count = &loose[bits] + &tight[bits];
        if pattern.accepts_zero() {
            count -= BigUint::one();
        }
        Ok(Self {
            count,
            width,
            upper,
            pattern,
            threshold: bits,
        })
    }

    /// Increasing, distinct scalars, without collecting candidates or scanning
    /// the integer domain. DFS retains one mutable scalar and O(width) frames.
    pub(crate) fn iter(&self) -> impl Iterator<Item = BigUint> + Send + '_ {
        Candidates {
            plan: self,
            value: BigUint::zero(),
            stack: vec![Frame {
                state: 0,
                tight: true,
                next_bit: 0,
            }],
        }
    }

    /// Refuse an incomplete search before invoking `test` even once.
    pub(crate) fn search<F>(
        &self,
        max_candidates: u64,
        threads: usize,
        test: F,
    ) -> Result<Option<BigUint>, String>
    where
        F: Fn(&BigUint) -> bool + Sync,
    {
        if max_candidates == 0 {
            return Err("maximum candidate budget must be positive".into());
        }
        if threads == 0 {
            return Err("thread count must be positive".into());
        }
        if self.count > BigUint::from(max_candidates) {
            return Err(format!(
                "pattern has {} candidates, exceeding maximum candidate budget {max_candidates}",
                self.count
            ));
        }
        if self.count.is_zero() {
            return Ok(None);
        }
        let count = self
            .count
            .to_u64()
            .expect("count checked against u64 budget");
        let workers = threads.min(usize::try_from(count).unwrap_or(usize::MAX));
        let candidates = Mutex::new(self.iter());
        let cancelled = AtomicBool::new(false);
        let found = Mutex::new(None);
        std::thread::scope(|scope| {
            for _ in 0..workers {
                let candidates = &candidates;
                let cancelled = &cancelled;
                let found = &found;
                let test = &test;
                scope.spawn(move || {
                    loop {
                        if cancelled.load(Ordering::Relaxed) {
                            break;
                        }
                        let candidate = {
                            let mut iter = candidates.lock().expect("candidate iterator poisoned");
                            if cancelled.load(Ordering::Relaxed) {
                                break;
                            }
                            iter.next()
                        };
                        let Some(candidate) = candidate else {
                            break;
                        };
                        // Point comparisons run outside the iterator lock.
                        if test(&candidate) {
                            cancelled.store(true, Ordering::Relaxed);
                            let mut result = found.lock().expect("search result poisoned");
                            if result.is_none() {
                                *result = Some(candidate);
                            }
                            break;
                        }
                    }
                });
            }
        });
        Ok(found.into_inner().expect("search result poisoned"))
    }
}

struct Frame {
    state: usize,
    tight: bool,
    next_bit: u8,
}

struct Candidates<'a> {
    plan: &'a Plan,
    value: BigUint,
    stack: Vec<Frame>,
}

impl Iterator for Candidates<'_> {
    type Item = BigUint;

    fn next(&mut self) -> Option<Self::Item> {
        while !self.stack.is_empty() {
            let depth = self.stack.len() - 1;
            if depth == self.plan.width {
                let frame = self.stack.pop().expect("leaf exists");
                if frame.state == self.plan.threshold && !self.value.is_zero() {
                    return Some(self.value.clone());
                }
                continue;
            }
            let position = self.plan.width - depth - 1;
            let frame = self.stack.last_mut().expect("frame exists");
            let upper_bit = self.plan.upper.bit(position as u64);
            let max_bit = if frame.tight && !upper_bit { 0 } else { 1 };
            if frame.next_bit > max_bit {
                self.stack.pop();
                continue;
            }
            let bit = frame.next_bit != 0;
            frame.next_bit += 1;
            let state = self
                .plan
                .pattern
                .advance(frame.state, bit, self.plan.threshold);
            // For both counters and runs, even an all-target suffix cannot
            // accept if the current state plus its length is too small.
            if state < self.plan.threshold && position < self.plan.threshold - state {
                continue;
            }
            let tight = frame.tight && bit == upper_bit;
            self.value.set_bit(position as u64, bit);
            self.stack.push(Frame {
                state,
                tight,
                next_bit: 0,
            });
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::AtomicUsize;

    const PATTERNS: [Pattern; 4] = [
        Pattern::ZeroRun,
        Pattern::OneRun,
        Pattern::Zeros,
        Pattern::Ones,
    ];

    fn oracle(value: u64, width: usize, pattern: Pattern, threshold: usize) -> bool {
        let target = matches!(pattern, Pattern::Ones | Pattern::OneRun);
        let digits: Vec<bool> = (0..width)
            .rev()
            .map(|position| value & (1 << position) != 0)
            .collect();
        match pattern {
            Pattern::Zeros | Pattern::Ones => {
                digits.iter().filter(|&&bit| bit == target).count() >= threshold
            }
            Pattern::ZeroRun | Pattern::OneRun => digits
                .windows(threshold)
                .any(|window| window.iter().all(|&bit| bit == target)),
        }
    }

    fn binomial(n: usize, k: usize) -> BigUint {
        let mut result = BigUint::one();
        for i in 0..k {
            result *= BigUint::from(n - i);
            result /= BigUint::from(i + 1);
        }
        result
    }

    #[test]
    fn exhaustive_small_domains_match_independent_oracle() {
        for order in 1_u64..=129 {
            let width = (u64::BITS - order.leading_zeros()) as usize;
            for pattern in PATTERNS {
                for threshold in 1..=width {
                    let plan = Plan::new(BigUint::from(order), pattern, threshold).unwrap();
                    let expected: Vec<_> = (1..order)
                        .filter(|&value| oracle(value, width, pattern, threshold))
                        .map(BigUint::from)
                        .collect();
                    let actual: Vec<_> = plan.iter().collect();
                    assert_eq!(plan.width, width);
                    assert_eq!(
                        plan.count,
                        BigUint::from(expected.len()),
                        "{order}, {pattern}, {threshold}"
                    );
                    assert_eq!(actual, expected, "{order}, {pattern}, {threshold}");
                    assert!(actual.windows(2).all(|pair| pair[0] < pair[1]));
                    assert_eq!(plan.iter().collect::<Vec<_>>(), actual);
                }
            }
        }
    }

    #[test]
    fn endpoints_leading_zeros_and_overlapping_runs() {
        let plan = Plan::new(BigUint::from(16_u32), Pattern::ZeroRun, 4).unwrap();
        assert_eq!(plan.width, 5);
        assert_eq!(plan.iter().collect::<Vec<_>>(), vec![BigUint::one()]);
        let plan = Plan::new(BigUint::from(16_u32), Pattern::OneRun, 4).unwrap();
        assert_eq!(plan.iter().collect::<Vec<_>>(), vec![BigUint::from(15_u32)]);
        let plan = Plan::new(BigUint::from(32_u32), Pattern::OneRun, 2).unwrap();
        assert_eq!(
            plan.iter().filter(|k| *k == BigUint::from(31_u32)).count(),
            1
        );
        for pattern in PATTERNS {
            let plan = Plan::new(BigUint::from(31_u32), pattern, 1).unwrap();
            assert!(
                plan.iter()
                    .all(|k| !k.is_zero() && k < BigUint::from(31_u32))
            );
        }
    }

    #[test]
    fn rejects_invalid_parameters() {
        for pattern in PATTERNS {
            assert!(Plan::new(BigUint::zero(), pattern, 1).is_err());
            assert!(Plan::new(BigUint::from(17_u32), pattern, 0).is_err());
            assert!(Plan::new(BigUint::from(17_u32), pattern, 6).is_err());
        }
        let plan = Plan::new(BigUint::from(17_u32), Pattern::Ones, 1).unwrap();
        assert!(plan.search(0, 1, |_| panic!("invalid budget")).is_err());
        assert!(plan.search(100, 0, |_| panic!("invalid threads")).is_err());
    }

    #[test]
    fn exact_budget_guard_and_complete_nonfinding_search() {
        let plan = Plan::new(BigUint::from(97_u32), Pattern::Zeros, 3).unwrap();
        let count = plan.count.to_u64().unwrap();
        assert!(
            plan.search(count - 1, 4, |_| panic!("over budget"))
                .is_err()
        );
        let calls = AtomicUsize::new(0);
        assert_eq!(
            plan.search(count, 4, |_| {
                calls.fetch_add(1, Ordering::Relaxed);
                false
            })
            .unwrap(),
            None
        );
        assert_eq!(calls.load(Ordering::Relaxed), count as usize);
        let empty = Plan::new(BigUint::one(), Pattern::Zeros, 1).unwrap();
        assert!(empty.count.is_zero());
        assert_eq!(empty.search(1, 100, |_| panic!("empty")).unwrap(), None);
        assert!(empty.search(0, 1, |_| panic!("empty")).is_err());
        assert!(empty.search(1, 0, |_| panic!("empty")).is_err());
    }

    #[test]
    fn parallel_search_finds_actual_full_width_scalar() {
        let order = BigUint::one() << 256_usize;
        let target = BigUint::one() << 255_usize;
        let plan = Plan::new(order, Pattern::Zeros, 255).unwrap();
        assert_eq!(
            plan.search(plan.count.to_u64().unwrap(), 4, |k| k == &target)
                .unwrap(),
            Some(target)
        );
        let small = Plan::new(BigUint::from(97_u32), Pattern::OneRun, 3).unwrap();
        let last = small.iter().last().unwrap();
        assert_eq!(small.search(100, 4, |k| k == &last).unwrap(), Some(last));
    }

    #[test]
    fn large_counts_and_enumeration_do_not_scan_scalar_domain() {
        let order = BigUint::one() << 256_usize;
        let zeros = Plan::new(order.clone(), Pattern::Zeros, 255).unwrap();
        // order.bits() is 257: its leading zero permits at most two ones.
        assert_eq!(zeros.width, 257);
        assert_eq!(zeros.count, binomial(256, 1) + binomial(256, 2));
        let values: Vec<_> = zeros.iter().collect();
        assert_eq!(BigUint::from(values.len()), zeros.count);
        assert_eq!(
            values.last().unwrap(),
            &((BigUint::from(3_u32)) << 254_usize)
        );
        let ones = Plan::new(order, Pattern::Ones, 255).unwrap();
        assert_eq!(ones.count, binomial(256, 255) + binomial(256, 256));
        assert_eq!(ones.iter().count(), 257);
        assert!(ones.iter().all(|k| k.bits() >= 255));

        // Width 256, excluding all-ones order and excluding scalar zero.
        let order = (BigUint::one() << 256_usize) - BigUint::one();
        let zeros = Plan::new(order.clone(), Pattern::Zeros, 255).unwrap();
        assert_eq!(zeros.width, 256);
        assert_eq!(zeros.count, binomial(256, 1));
        assert_eq!(zeros.iter().count(), 256);
        let ones = Plan::new(order, Pattern::Ones, 255).unwrap();
        assert_eq!(ones.count, binomial(256, 255));
        assert_eq!(ones.iter().count(), 256);
    }

    #[test]
    fn p521_width_excludes_byte_padding() {
        let order = (BigUint::one() << 521_usize) - BigUint::one();
        for pattern in [Pattern::Zeros, Pattern::ZeroRun] {
            let plan = Plan::new(order.clone(), pattern, 521).unwrap();
            assert_eq!(plan.width, 521);
            assert!(plan.count.is_zero());
            assert_eq!(plan.iter().next(), None);
            assert!(Plan::new(order.clone(), pattern, 522).is_err());
        }
        let zeros = Plan::new(order.clone(), Pattern::Zeros, 520).unwrap();
        assert_eq!(zeros.count, BigUint::from(521_u32));
        assert_eq!(zeros.iter().count(), 521);
        let ones = Plan::new(order, Pattern::Ones, 520).unwrap();
        assert_eq!(ones.count, BigUint::from(521_u32));
        assert_eq!(ones.iter().count(), 521);
    }

    #[test]
    fn huge_exact_count_refuses_before_callback() {
        let order = (BigUint::one() << 521_usize) - BigUint::one();
        let plan = Plan::new(order.clone(), Pattern::Ones, 1).unwrap();
        assert_eq!(plan.count, order - BigUint::one());
        assert!(
            plan.search(u64::MAX, 4, |_| panic!("must not search"))
                .is_err()
        );
    }
}
