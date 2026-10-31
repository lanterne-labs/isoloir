//! The calendars: submission of a digest and upgrade of the pending
//! attestations once Bitcoin confirmed.

use std::time::Duration;

use tracing::{debug, info, warn};

use crate::error::{Error, Result};
use crate::ots::{Attestation, Item, Ots, Timestamp};

/// The public calendars a digest is sent to by default.
pub const DEFAULT_CALENDARS: &[&str] = &[
    "https://a.pool.opentimestamps.org",
    "https://b.pool.opentimestamps.org",
    "https://a.pool.eternitywall.com",
    "https://ots.btc.catallaxy.com",
];

/// The default calendars, owned.
pub fn default_calendars() -> Vec<String> {
    DEFAULT_CALENDARS.iter().map(|s| s.to_string()).collect()
}

const ACCEPT: &str = "application/vnd.opentimestamps.v1";
/// The largest calendar answer read.
const MAX_ANSWER: u64 = 100_000;

/// An HTTP client of the calendars.
#[derive(Debug, Clone)]
pub struct Client {
    agent: ureq::Agent,
    allowed: Option<Vec<String>>,
}

impl Default for Client {
    fn default() -> Self {
        Client::new(Duration::from_secs(20))
    }
}

/// What a calendar said of a pending commitment.
enum Upgrade {
    /// The path down to a Bitcoin attestation.
    Done(Timestamp),
    /// Nothing yet (404, or an answer without a Bitcoin attestation).
    NotYet,
}

impl Client {
    /// A client whose requests time out after `timeout`.
    pub fn new(timeout: Duration) -> Self {
        let agent = ureq::Agent::config_builder()
            .timeout_global(Some(timeout))
            .http_status_as_error(false)
            .build()
            .into();
        Client {
            agent,
            allowed: None,
        }
    }

    /// Restricts the upgrade to pending attestations of these calendars
    /// (a proof read from elsewhere names the URLs fetched). Without it,
    /// any calendar the proof names is asked.
    pub fn allow_only(mut self, calendars: &[String]) -> Self {
        self.allowed = Some(
            calendars
                .iter()
                .map(|c| c.trim_end_matches('/').to_string())
                .collect(),
        );
        self
    }

    /// Sends the digest to each calendar's `/digest` and merges the
    /// answers into one proof, a branch per calendar. It succeeds when at
    /// least one calendar answered.
    pub fn submit(&self, digest: [u8; 32], calendars: &[String]) -> Result<Ots> {
        let mut root = Timestamp {
            msg: digest.to_vec(),
            items: Vec::new(),
        };
        let mut errors = Vec::new();
        for cal in calendars {
            let url = format!("{}/digest", cal.trim_end_matches('/'));
            let answer = self
                .post(&url, &digest)
                .and_then(|body| Timestamp::parse(&body, &digest).map_err(|e| http_err(&url, e)));
            match answer {
                Ok(t) => {
                    debug!(calendar = %cal, "calendar accepted the digest");
                    root.merge(t);
                }
                Err(e) => {
                    warn!(calendar = %cal, error = %e, "calendar refused the digest");
                    errors.push(e.to_string());
                }
            }
        }
        if root.items.is_empty() {
            if errors.is_empty() {
                errors.push("no calendar given".into());
            }
            return Err(Error::Calendars(errors));
        }
        info!(digest = %hex::encode(digest), answered = calendars.len() - errors.len(), failed = errors.len(), "digest submitted");
        Ok(Ots { digest, root })
    }

    /// Asks the calendar of every pending attestation for the rest of the
    /// path; an answer down to a Bitcoin attestation replaces the pending
    /// attestation in its node, and every other branch stays. A 404 means
    /// not yet. It returns the new proof and whether it changed; it fails
    /// only when nothing changed and a calendar failed (the failures of a
    /// partly upgraded proof are logged).
    pub fn upgrade(&self, ots: &Ots) -> Result<(Ots, bool)> {
        let mut out = ots.clone();
        let mut errors = Vec::new();
        let changed = self.upgrade_node(&mut out.root, &mut errors);
        if !changed && !errors.is_empty() {
            return Err(Error::Calendars(errors));
        }
        for e in &errors {
            warn!(error = %e, "calendar upgrade failed");
        }
        Ok((out, changed))
    }

    fn upgrade_node(&self, node: &mut Timestamp, errors: &mut Vec<String>) -> bool {
        let mut changed = false;
        // The children first: what is spliced here is not asked again.
        for item in &mut node.items {
            if let Item::Op(_, child) = item {
                changed |= self.upgrade_node(child, errors);
            }
        }
        let mut kept = Vec::with_capacity(node.items.len());
        let mut spliced = Vec::new();
        for item in std::mem::take(&mut node.items) {
            let Item::Attestation(Attestation::Pending { uri }) = &item else {
                kept.push(item);
                continue;
            };
            if let Some(allowed) = &self.allowed
                && !allowed.iter().any(|a| a == uri.trim_end_matches('/'))
            {
                debug!(calendar = %uri, "calendar not allowed, left pending");
                kept.push(item);
                continue;
            }
            match self.fetch(uri, &node.msg) {
                Ok(Upgrade::Done(t)) => {
                    info!(calendar = %uri, commitment = %hex::encode(&node.msg), "attestation upgraded");
                    spliced.push(t);
                }
                Ok(Upgrade::NotYet) => kept.push(item),
                Err(e) => {
                    errors.push(e.to_string());
                    kept.push(item);
                }
            }
        }
        node.items = kept;
        for t in spliced {
            node.merge(t);
            changed = true;
        }
        changed
    }

    fn fetch(&self, calendar: &str, commitment: &[u8]) -> Result<Upgrade> {
        let url = format!(
            "{}/timestamp/{}",
            calendar.trim_end_matches('/'),
            hex::encode(commitment)
        );
        let mut resp = self
            .agent
            .get(&url)
            .header("Accept", ACCEPT)
            .call()
            .map_err(|e| http_err(&url, e))?;
        let status = resp.status().as_u16();
        if status == 404 {
            debug!(url = %url, "not yet");
            return Ok(Upgrade::NotYet);
        }
        if status != 200 {
            return Err(http_err(&url, format!("HTTP {status}")));
        }
        let body = resp
            .body_mut()
            .with_config()
            .limit(MAX_ANSWER)
            .read_to_vec()
            .map_err(|e| http_err(&url, e))?;
        let t = Timestamp::parse(&body, commitment).map_err(|e| http_err(&url, e))?;
        let mut atts = Vec::new();
        t.walk(&mut atts);
        if !atts
            .iter()
            .any(|a| matches!(a.attestation, Attestation::Bitcoin { .. }))
        {
            debug!(url = %url, "an answer without a Bitcoin attestation");
            return Ok(Upgrade::NotYet);
        }
        Ok(Upgrade::Done(t))
    }

    fn post(&self, url: &str, body: &[u8]) -> Result<Vec<u8>> {
        let mut resp = self
            .agent
            .post(url)
            .header("Accept", ACCEPT)
            .header("Content-Type", "application/x-www-form-urlencoded")
            .send(body)
            .map_err(|e| http_err(url, e))?;
        let status = resp.status().as_u16();
        if status != 200 {
            return Err(http_err(url, format!("HTTP {status}")));
        }
        resp.body_mut()
            .with_config()
            .limit(MAX_ANSWER)
            .read_to_vec()
            .map_err(|e| http_err(url, e))
    }
}

fn http_err(url: &str, reason: impl std::fmt::Display) -> Error {
    Error::Http {
        url: url.to_string(),
        reason: reason.to_string(),
    }
}

/// [`Client::submit`] with the default client.
pub fn submit(digest: [u8; 32], calendars: &[String]) -> Result<Ots> {
    Client::default().submit(digest, calendars)
}

/// [`Client::upgrade`] with the default client (any calendar the proof
/// names is asked).
pub fn upgrade(ots: &Ots) -> Result<(Ots, bool)> {
    Client::default().upgrade(ots)
}
