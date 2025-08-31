use async_trait::async_trait;
use crate::errors::PcwError;
use crate::scope::Scope;
use crate::utils::{le32, sha256};
use chrono::prelude::*;
use serde::{Deserialize, Serialize};
use tokio::time::{sleep, Duration};
use std::cmp::min;

/// BroadcastPolicy per §9.3: Fields for strategy, spacing, etc.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct BroadcastPolicy {
    pub authority: String, // "either"
    pub strategy_default: String, // "paced" | "all_at_once" | "bursts"
    pub min_spacing_ms: u64,
    pub max_spacing_ms: u64,
    pub burst_size: u64,
    pub burst_gap_ms: u64,
    pub window_start: Option<String>, // ISO UTC
    pub window_end: Option<String>,
    pub rebroadcast_interval_s: u64,
    pub hold_time_max_s: u64,
    pub confirm_depth: u64,
}

/// Deterministic pacing schedule from S_pace (§9.5).
pub fn pacing_schedule(scope: &Scope, n: usize, policy: &BroadcastPolicy) -> Vec<Duration> {
    let s_pace = sha256(&[&scope.z[..], &scope.h_i[..], b"pace"].concat());
    let mut ctr = 0u32;
    let mut schedule = vec![Duration::ZERO; n];
    let now = Utc::now();
    let start = policy.window_start.as_ref().map(|s| Utc::parse_from_rfc3339(s).unwrap_or(now)).unwrap_or(now);
    match policy.strategy_default.as_str() {
        "all_at_once" => {
            let d = (start - now).to_std().unwrap_or(Duration::ZERO);
            for schedule_d in &mut schedule {
                *schedule_d = d;
            }
        }
        "paced" => {
            schedule[0] = (start - now).to_std().unwrap_or(Duration::ZERO);
            for i in 1..n {
                let delta_ms = draw_uniform(&s_pace, &mut ctr, policy.max_spacing_ms - policy.min_spacing_ms + 1)? + policy.min_spacing_ms;
                schedule[i] = schedule[i-1] + Duration::from_millis(delta_ms);
            }
            if let Some(end_str) = &policy.window_end {
                let end = Utc::parse_from_rfc3339(end_str).unwrap_or(now);
                let end_d = (end - now).to_std().unwrap_or(Duration::ZERO);
                for d in &mut schedule {
                    if *d > end_d {
                        *d = end_d;
                    }
                }
            }
        }
        "bursts" => {
            let beta = policy.burst_size as usize;
            let num_bursts = (n + beta - 1) / beta;
            let mut batch_times = vec![Duration::ZERO; num_bursts];
            batch_times[0] = (start - now).to_std().unwrap_or(Duration::ZERO);
            for k in 1..num_bursts {
                batch_times[k] = batch_times[k-1] + Duration::from_millis(policy.burst_gap_ms);
            }
            for b in 0..num_bursts {
                let start_idx = b * beta;
                let end_idx = min(start_idx + beta, n);
                for idx in start_idx..end_idx {
                    let intra = draw_uniform(&s_pace, &mut ctr, policy.min_spacing_ms + 1)?;
                    schedule[idx] = batch_times[b] + Duration::from_millis(intra);
                }
            }
            if let Some(end_str) = &policy.window_end {
                let end = Utc::parse_from_rfc3339(end_str).unwrap_or(now);
                let end_d = (end - now).to_std().unwrap_or(Duration::ZERO);
                for d in &mut schedule {
                    if *d > end_d {
                        *d = end_d;
                    }
                }
            }
        }
        _ => vec![],
    }
}

/// PRNG next_u64: H(s_pace || LE32(ctr)) first 8 bytes BE (§9.5, similar to §5.2).
fn next_u64(s_pace: &[u8; 32], ctr: &mut u32) -> u64 {
    let mut pre = s_pace.to_vec();
    pre.extend_from_slice(&le32(*ctr));
    *ctr += 1;
    let r = sha256(&pre);
    let mut bytes = [0; 8];
    bytes.copy_from_slice(&r[0..8]);
    u64::from_be_bytes(bytes)
}

/// Unbiased draw in [0, range-1] with rejection (§9.5, §5.4).
fn draw_uniform(s_pace: &[u8; 32], ctr: &mut u32, range: u64) -> Result<u64, PcwError> {
    if range == 0 {
        return Err(PcwError::Other("Range 0 §9.5".to_string()));
    }
    let m = 1u64 << 64;
    let lim = (m / range) * range;
    loop {
        let u = next_u64(s_pace, ctr);
        if u < lim {
            return Ok(u % range);
        }
    }
}

#[async_trait]
pub trait Broadcaster {
    async fn submit(&self, tx_bytes: &[u8]) -> Result<(), PcwError>;
    async fn rebroadcast(&self, tx_bytes: &[u8], interval: Duration) -> Result<(), PcwError> {
        loop {
            self.submit(tx_bytes).await?;
            sleep(interval).await;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    // Tests for schedule determinism, bounds, bursts intra/gap
}
