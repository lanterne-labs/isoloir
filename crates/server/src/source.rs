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
