//! Module for note splitting in the PCW-1 protocol.
//!
//! This module implements the bounded note splitting logic as per §5, including deterministic
//! N choice (§5.3), prefix-clamp construction (§5.5), and Fisher-Yates permutation (§5.6).
//! It ensures a total amount `t` is split into `N` notes within `[v_min, v_max]`, with
//! deterministic and reproducible results based on a scope {Z, H_I}.

use crate::errors::PcwError;
use crate::scope::Scope;
use crate::utils::{le32, sha256};
use std::cmp::{max, min};

/// Bounded note splitting per §5: Deterministic N, prefix-clamp, Fisher-Yates perm.
pub fn bounded_split(scope: &Scope, t: u64, v_min: u64, v_max: u64) -> Result<Vec<u64>, PcwError> {
    if v_min == 0 || v_max < v_min {
        return Err(PcwError::Other("Invalid bounds §5.1".to_string()));
    }
    let n_min = (t + v_max - 1) / v_max; // ceil(t / v_max)
    let n_max = t / v_min; // floor(t / v_min)
    if n_min > n_max {
        return Err(PcwError::InfeasibleSplit);
    }
    let seed_split = sha256(&[&scope.z[..], &scope.h_i[..], b"split"].concat());
    let seed_perm = sha256(&[&seed_split[..], b"permute"].concat());
    let mut ctr = 0u32;
    let n = choose_n(&seed_split, &mut ctr, n_min, n_max)?;
    let mut a = prefix_clamp(t, v_min, v_max, n, &seed_split, &mut ctr)?;
    fisher_yates(&mut a, &seed_perm)?;
    Ok(a)
}

/// PRNG next_u64: H(seed || LE32(ctr)) first 8 bytes BE (§5.2).
fn next_u64(seed: &[u8; 32], ctr: &mut u32) -> u64 {
    let mut pre = seed.to_vec();
    pre.extend_from_slice(&le32(*ctr));
    let r = sha256(&pre);
    let mut bytes = [0u8; 8];
    bytes.copy_from_slice(&r[0..8]);
    u64::from_be_bytes(bytes)
}

/// Unbiased draw in [0, range-1] with rejection (§5.4).
fn draw_uniform(seed: &[u8; 32], ctr: &mut u32, range: u64) -> Result<u64, PcwError> {
    if range == 0 {
        return Err(PcwError::Other("Range 0 §5.4".to_string()));
    }
    if range > (u64::MAX / 2) {
        return Err(PcwError::Other(
            "Range too large for rejection sampling".to_string(),
        ));
    }
    let m = 1u64 << 64;
    let lim = (m / range) * range;
    loop {
        let u = next_u64(seed, ctr);
        *ctr += 1;
        if u < lim {
            return Ok(u % range);
        }
    }
}

/// Deterministic N choice: interior-biased jitter (§5.3).
fn choose_n(seed: &[u8; 32], ctr: &mut u32, n_min: u64, n_max: u64) -> Result<u64, PcwError> {
    let span = n_max - n_min;
    if span == 0 {
        return Ok(n_min);
    }
    let mid = (n_min + n_max) / 2;
    let delta = span / 4;
    let r = draw_uniform(seed, ctr, 2 * delta + 1)?;
    let j = r as i64 - delta as i64;
    let n0 = (mid as i64 + j) as u64;
    Ok(max(n_min, min(n0, n_max)))
}

/// Prefix-clamped construction (§5.5).
fn prefix_clamp(
    t: u64,
    v_min: u64,
    v_max: u64,
    n: u64,
    seed: &[u8; 32],
    ctr: &mut u32,
) -> Result<Vec<u64>, PcwError> {
    let mut a = vec![0u64; n as usize];
    let mut rem = t;
    for i in 0..(n - 1) as usize {
        let slots = (n - 1 - i as u64) as u64;
        let low = max(v_min, rem.saturating_sub(v_max * slots));
        let high = min(v_max, rem - v_min * slots);
        if low > high {
            return Err(PcwError::Other(
                "Invariant violation in prefix-clamp §5.7".to_string(),
            ));
        }
        let r = draw_uniform(seed, ctr, high - low + 1)?;
        a[i] = low + r;
        rem -= a[i];
    }
    a[(n - 1) as usize] = rem;
    if rem < v_min || rem > v_max {
        return Err(PcwError::Other("Last note out of bounds §5.7".to_string()));
    }
    Ok(a)
}

/// Fisher-Yates shuffle (§5.6).
fn fisher_yates(a: &mut [u64], seed_perm: &[u8; 32]) -> Result<(), PcwError> {
    let mut ctr = 0u32;
    for j in (1..a.len()).rev() {
        let r = draw_uniform(seed_perm, &mut ctr, (j + 1) as u64)?;
        a.swap(j, r as usize);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    #[test]
    fn test_bounded_split_basic() -> Result<(), PcwError> {
        let scope = Scope::new([0u8; 32], [0u8; 32]);
        let split = bounded_split(&scope, 1000, 100, 500)?;
        assert_eq!(split.iter().sum::<u64>(), 1000);
        assert!(split.iter().all(|&x| 100 <= x && x <= 500));
        Ok(())
    }

    #[test]
    fn test_bounded_split_min_n() -> Result<(), PcwError> {
        let scope = Scope::new([0u8; 32], [0u8; 32]);
        let split = bounded_split(&scope, 100, 100, 100)?; // Should result in N=1
        assert_eq!(split, vec![100]);
        Ok(())
    }

    #[test]
    fn test_bounded_split_invalid_bounds() {
        let scope = Scope::new([0u8; 32], [0u8; 32]);
        let result = bounded_split(&scope, 1000, 0, 500); // v_min = 0
        assert!(result.is_err());
        let result = bounded_split(&scope, 1000, 500, 100); // v_max < v_min
        assert!(result.is_err());
    }

    proptest! {
        #[test]
        fn prop_split_sum_bounds(
            t in 1000u64..100000,
            v_min in 1u64..100,
            v_max in 100u64..1000,
            |(t, v_min, v_max)| (t, v_min, v_max).prop_filter("feasible", |(t, v_min, v_max)| *v_min <= *v_max && *t >= *v_min && (*t / *v_min) >= (*t + *v_max - 1) / *v_max)
        ) {
            let scope = Scope::new([0; 32], [0; 32]);
            let a = bounded_split(&scope, *t, *v_min, *v_max).unwrap();
            prop_assert_eq!(a.iter().sum::<u64>(), *t);
            prop_assert!(a.iter().all(|&x| *v_min <= x && x <= *v_max));
            prop_assert!(a.len() >= ((*t + *v_max - 1) / *v_max) as usize && a.len() <= (*t / *v_min) as usize);
        }
    }
}
