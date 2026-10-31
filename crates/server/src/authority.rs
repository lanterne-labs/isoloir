//! The authority (SPEC §10): replays the log through the auditor, then
//! publishes the tallies that are due for the polls it can decrypt: those
//! encrypted under its key, and tlock polls once their round's beacon is
//! out. It decrypts nothing from a log it could not verify.

use crate::ingest::{kinds, tag, Transport};
use crate::source::LogSource;
use isoloir_core::canonical;
use isoloir_core::grumpkin::Scalar;
use isoloir_decrypt::tlock::DrandTlock;
use isoloir_proto::audit::Auditor;
use isoloir_proto::body::{Beacon, Encryption};
use isoloir_proto::judge::{Checkers, Passports, Proofs};
use isoloir_proto::policy;
use isoloir_proto::sig::Event;
use isoloir_proto::tally;
use std::collections::HashSet;
use std::sync::Arc;

/// Where the authority's keys are.
pub struct Keys {
    pub pk: String,
    pub sk: Scalar,
    pub sign_seed: [u8; 32],
}

/// Where tallies go: the relays, or the ingest's submissions (an authority
/// beside the ingest).
pub enum Output {
    Relays { transport: Arc<dyn Transport>, nostr_sk: [u8; 32] },
    Store(crate::store::Store),
}

pub struct Service {
    source: Box<dyn LogSource>,
    auditor: Auditor<'static>,
    keys: Option<Keys>,
    drand: Option<String>,
    output: Output,
    published: HashSet<(u32, u64)>,
    tag: Option<String>,
    rng: rand::rngs::StdRng,
}

impl Service {
    /// `drand`: the base URL of a drand HTTP API (tlock polls), e.g.
    /// https://api.drand.sh.
    pub fn new(
        source: Box<dyn LogSource>,
        log_key: Option<&str>,
        proofs: Box<dyn Proofs + Send + Sync>,
        passports: Box<dyn Passports + Send + Sync>,
        keys: Option<Keys>,
        drand: Option<String>,
        output: Output,
    ) -> anyhow::Result<Service> {
        // The authority lives as long as the process: its verifiers too.
        let proofs: &'static dyn Proofs = Box::leak(proofs);
        let passports: &'static dyn Passports = Box::leak(passports);
        let tlock: &'static DrandTlock = Box::leak(Box::new(DrandTlock));
        let auditor = Auditor::new(log_key, Checkers { proofs, passports, tlock: Some(tlock) }).map_err(|e| anyhow::anyhow!(e))?;
        use rand::SeedableRng;
        Ok(Service { source, auditor, keys, drand, output, published: HashSet::new(), tag: None, rng: rand::rngs::StdRng::from_entropy() })
    }

    /// One round: new checkpoints, then the tallies due. Returns how many
    /// tallies were published. A failure of the log's source, of drand or
    /// of the output is returned to be retried; a log that does not verify
    /// is `LogFault`, which the caller must not retry past.
    pub async fn step(&mut self, now: u64) -> anyhow::Result<usize> {
        let next = self.auditor.state.last_checkpoint().map(|c| c.index + 1).unwrap_or(1);
        for (note, entries) in self.source.from(next).await? {
            self.auditor.checkpoint(&note, &entries).map_err(|e| LogFault(e))?;
        }
        if !self.auditor.report.problems.is_empty() {
            return Err(LogFault(format!("the log does not verify: {:?}", self.auditor.report.problems)).into());
        }
        if self.tag.is_none() {
            self.tag = self.auditor.state.ledger().map(|l| tag(&l.origin));
        }
        let mut n = 0;
        let polls: Vec<u32> = self.auditor.state.polls.keys().copied().collect();
        for id in polls {
            let Some(due) = policy::next_due(&self.auditor.state, id) else { continue };
            if !self.published.insert((id, due.checkpoint)) {
                continue;
            }
            let p = &self.auditor.state.polls[&id];
            let t = match &p.current().encryption {
                Encryption::Elgamal { pk, .. } => match &self.keys {
                    Some(k) if &k.pk == pk => match tally::build_elgamal(p, &due, &k.sk, &k.sign_seed, &mut self.rng) {
                        Ok(t) => t,
                        Err(e) => {
                            // Kept in `published`: not retried every round.
                            tracing::error!(poll = id, checkpoint = due.checkpoint, error = %e, "the tally could not be built");
                            continue;
                        }
                    },
                    _ => continue,
                },
                Encryption::Tlock { chain, period, genesis, round, .. } => {
                    let at = genesis + (round - 1) * period;
                    let Some(base) = &self.drand else { continue };
                    if now < at {
                        self.published.remove(&(id, due.checkpoint));
                        continue;
                    }
                    let beacon = fetch_beacon(base, chain, *round).await?;
                    tally::build_tlock(p, &due, &beacon, &DrandTlock).map_err(|e| anyhow::anyhow!(e))?
                }
            };
            self.publish(&canonical::to_vec(&t)?, now).await?;
            tracing::info!(poll = id, checkpoint = due.checkpoint, is_final = due.is_final, "tally published");
            n += 1;
        }
        Ok(n)
    }

    async fn publish(&self, body: &[u8], now: u64) -> anyhow::Result<()> {
        match &self.output {
            Output::Store(s) => {
                s.submit(isoloir_proto::body::EntryKind::Tally, body, now).await?;
            }
            Output::Relays { transport, nostr_sk } => {
                let tag = self.tag.clone().unwrap_or_default();
                let ev = Event::sign(nostr_sk, now, kinds::TALLY, vec![vec!["t".into(), tag]], String::from_utf8(body.to_vec())?);
                transport.publish_all(&ev).await;
            }
        }
        Ok(())
    }

    pub fn report(&self) -> &isoloir_proto::audit::Report {
        &self.auditor.report
    }
}

/// The log does not verify: the authority must not go on.
#[derive(Debug)]
pub struct LogFault(pub String);

impl std::fmt::Display for LogFault {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl std::error::Error for LogFault {}

/// The beacon of a round from a drand HTTP API.
pub async fn fetch_beacon(base: &str, chain: &str, round: u64) -> anyhow::Result<Beacon> {
    let v: serde_json::Value = reqwest::get(format!("{}/{chain}/public/{round}", base.trim_end_matches('/'))).await?.error_for_status()?.json().await?;
    let signature = v["signature"].as_str().ok_or_else(|| anyhow::anyhow!("drand: no signature"))?.to_string();
    Ok(Beacon { round, signature })
}
