//! Where the authority and the auditor read the log: the ingest's database,
//! or a mirror (a directory or a base URL), checkpoint by checkpoint.

use crate::mirror;
use crate::store::Store;
use isoloir_proto::body::EntryKind;

/// A checkpoint as read: its signed note and its entries in log order.
pub type Read = (String, Vec<(EntryKind, Vec<u8>)>);

#[async_trait::async_trait]
pub trait LogSource: Send + Sync {
    /// The checkpoints from `index` (1-based) on, as many as there are.
    async fn from(&self, index: u64) -> anyhow::Result<Vec<Read>>;
}

#[async_trait::async_trait]
impl LogSource for Store {
    async fn from(&self, index: u64) -> anyhow::Result<Vec<Read>> {
        let notes = self.checkpoints().await?;
        let entries = self.entries().await?;
        Ok(notes
            .into_iter()
            .filter(|(i, _)| *i as u64 >= index)
            .map(|(i, n)| (n, entries.iter().filter(|e| e.3 == i).map(|e| (e.1, e.2.clone())).collect()))
            .collect())
    }
}

/// A mirror: a local directory, or a base URL.
pub enum MirrorSource {
    Dir(std::path::PathBuf),
    Http { base: String, client: reqwest::Client },
}

impl MirrorSource {
    pub fn parse(s: &str) -> MirrorSource {
        if s.starts_with("http://") || s.starts_with("https://") {
            MirrorSource::Http { base: s.trim_end_matches('/').to_string(), client: reqwest::Client::new() }
        } else {
            MirrorSource::Dir(s.into())
        }
    }

    /// One file of the mirror, or None when it is not there.
    pub async fn get(&self, path: &str) -> anyhow::Result<Option<Vec<u8>>> {
        match self {
            MirrorSource::Dir(d) => match std::fs::read(d.join(path)) {
                Ok(b) => Ok(Some(b)),
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
                Err(e) => Err(e.into()),
            },
            MirrorSource::Http { base, client } => {
                let r = client.get(format!("{base}/{path}")).send().await?;
                if r.status() == reqwest::StatusCode::NOT_FOUND {
                    return Ok(None);
                }
                Ok(Some(r.error_for_status()?.bytes().await?.to_vec()))
            }
        }
    }
}

#[async_trait::async_trait]
impl LogSource for MirrorSource {
    async fn from(&self, index: u64) -> anyhow::Result<Vec<Read>> {
        let Some(latest) = self.get("checkpoint.txt").await? else { return Ok(vec![]) };
        let latest = String::from_utf8(latest)?;
        let last: u64 = latest.lines().find_map(|l| l.strip_prefix("index ")).and_then(|n| n.parse().ok()).ok_or_else(|| anyhow::anyhow!("checkpoint.txt: no index"))?;
        let mut out = vec![];
        for i in index..=last {
            let note = self.get(&format!("checkpoints/{i}.txt")).await?.ok_or_else(|| anyhow::anyhow!("checkpoint {i} missing"))?;
            let entries = self.get(&format!("entries/{i}.json")).await?.ok_or_else(|| anyhow::anyhow!("entries of {i} missing"))?;
            let parsed = mirror::parse_entries(&serde_json::from_slice(&entries)?)?;
            out.push((String::from_utf8(note)?, parsed.into_iter().map(|(_, k, b)| (k, b)).collect()));
        }
        Ok(out)
    }
}

/// What an audit gathers for the refusals, whose bodies the log does not
/// hold (SPEC §11.4, §16).
#[derive(Default)]
pub struct Refusals {
    /// Refused bodies by event id.
    pub copies: std::collections::HashMap<String, isoloir_proto::audit::Copy>,
    /// The lists of the `rejects` entries, by checkpoint index.
    pub lists: std::collections::HashMap<u64, Vec<Vec<u8>>>,
    /// What could not be read.
    pub warnings: Vec<String>,
}

impl Refusals {
    /// The refused messages the relays still hold: verified envelopes of
    /// the message kinds, by event id.
    pub fn add_events(&mut self, events: &[isoloir_proto::sig::Event]) {
        for e in events {
            if matches!(e.kind, 7100 | 7101 | 7105) && e.verify() {
                self.copies.entry(e.id.clone()).or_insert_with(|| isoloir_proto::audit::Copy { author: Some(e.pubkey.clone()), body: e.content.as_bytes().to_vec() });
            }
        }
    }

    /// Asks the ingest (`ledger`: the base URL of its HTTP service) for the
    /// lists of the `rejects` entries of `read` (checkpoints from 1, in
    /// order) and for the bodies of the refusals no copy was found for.
    /// The audit checks everything it gets against the log.
    pub async fn ask_ledger(&mut self, ledger: &str, read: &[Read]) {
        use isoloir_proto::body::{self, Body};
        let base = ledger.trim_end_matches('/');
        let client = reqwest::Client::new();
        let mut wanted: Vec<String> = vec![];
        for (i, (_, entries)) in read.iter().enumerate() {
            let index = i as u64 + 1;
            for (k, b) in entries {
                match (k, body::decode(*k, b)) {
                    (EntryKind::Reject, Ok(Body::Reject(r))) if r.raw.is_none() => wanted.push(r.of),
                    (EntryKind::Rejects, Ok(Body::Rejects(_))) => {
                        let got = async {
                            let r = client.get(format!("{base}/v1/rejects/{index}")).send().await?.error_for_status()?;
                            let v: serde_json::Value = r.json().await?;
                            let list = v["rejects"].as_array().ok_or_else(|| anyhow::anyhow!("no list"))?;
                            list.iter().map(|s| s.as_str().map(|s| s.as_bytes().to_vec()).ok_or_else(|| anyhow::anyhow!("not a string"))).collect::<anyhow::Result<Vec<_>>>()
                        };
                        match got.await {
                            Ok(list) => {
                                for rb in &list {
                                    if let Ok(Body::Reject(r)) = body::decode(EntryKind::Reject, rb) {
                                        wanted.push(r.of);
                                    }
                                }
                                self.lists.insert(index, list);
                            }
                            Err(e) => self.warnings.push(format!("the refusals of checkpoint {index}: {e}")),
                        }
                    }
                    _ => {}
                }
            }
        }
        let (mut gone, mut missing) = (0, 0);
        for id in wanted {
            if self.copies.contains_key(&id) {
                continue;
            }
            let r = match client.get(format!("{base}/v1/refused/{id}")).send().await {
                Ok(r) => r,
                Err(e) => {
                    self.warnings.push(format!("the ingest's copy of {id}: {e}"));
                    continue;
                }
            };
            match r.status() {
                reqwest::StatusCode::OK => match r.bytes().await {
                    Ok(b) => {
                        self.copies.insert(id, isoloir_proto::audit::Copy { author: None, body: b.to_vec() });
                    }
                    Err(e) => self.warnings.push(format!("the ingest's copy of {id}: {e}")),
                },
                reqwest::StatusCode::GONE => gone += 1,
                reqwest::StatusCode::NOT_FOUND => missing += 1,
                s => self.warnings.push(format!("the ingest's copy of {id}: {s}")),
            }
        }
        if gone > 0 {
            self.warnings.push(format!("{gone} refused bodies were over the size limit: the ingest did not keep them"));
        }
        if missing > 0 {
            self.warnings.push(format!("the ingest has no copy of {missing} refused bodies"));
        }
    }
}
