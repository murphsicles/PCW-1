use async_trait::async_trait;
use crate::errors::PcwError;
use crate::scope::Scope;
use crate::utils::sha256;
use chrono::prelude::*;
use serde::{Deserialize, Serialize};
use tokio::time::{sleep, Duration};

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
            for d in &mut schedule {
                *d = (start - now).to_std().unwrap_or(Duration::ZERO);
            }
        }
        "paced" => {
            schedule[0] = (start - now).to_std().unwrap_or(Duration::ZERO);
            for i in 1..n {
                let delta = draw_uniform(&s_pace, &mut ctr, policy.max_spacing_ms - policy.min_spacing_ms + 1).unwrap() + policy.min_spacing_ms;
                schedule[i] = schedule[i-1] + Duration::from_millis(delta);
            }
            // Cap to window_end if set
        }
        "bursts" => {
            // Partition into bursts, derive batch_times with gaps, intra offsets
        }
        _ => panic!("Invalid strategy"),
    }
    schedule
}

fn draw_uniform(s_pace: &[u8; 32], ctr: &mut u32, range: u64) -> Result<u64, PcwError> {
    // Similar to split::draw_uniform
    // ...
}

/// Async trait for pluggable broadcaster (§9).
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
    // Tests for schedule determinism, bounds
}
