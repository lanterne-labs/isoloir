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

impl MirrorSource {
    /// Checkpoint `i` from its own files.
    async fn one(&self, i: u64) -> anyhow::Result<Read> {
        let note = self.get(&format!("checkpoints/{i}.txt")).await?.ok_or_else(|| anyhow::anyhow!("checkpoint {i} missing"))?;
        let entries = self.get(&format!("entries/{i}.json")).await?.ok_or_else(|| anyhow::anyhow!("entries of {i} missing"))?;
        let parsed = mirror::parse_entries(&serde_json::from_slice(&entries)?)?;
        Ok((String::from_utf8(note)?, parsed.into_iter().map(|(_, k, b)| (k, b)).collect()))
    }
}

#[async_trait::async_trait]
impl LogSource for MirrorSource {
    /// The windows first (`windows/<k>.json`, SPEC §15), the checkpoint
    /// files for what no window holds: the checkpoints before the first
    /// window, a gap between two, everything after the last.
    async fn from(&self, index: u64) -> anyhow::Result<Vec<Read>> {
        let Some(latest) = self.get("checkpoint.txt").await? else { return Ok(vec![]) };
        let latest = String::from_utf8(latest)?;
        let last: u64 = latest.lines().find_map(|l| l.strip_prefix("index ")).and_then(|n| n.parse().ok()).ok_or_else(|| anyhow::anyhow!("checkpoint.txt: no index"))?;
        let mut out = vec![];
        let mut next = index.max(1);
        let mut k = 0;
        while next <= last {
            let Some(w) = self.get(&format!("windows/{k}.json")).await? else { break };
            let (from, to, cps) = mirror::parse_window(&serde_json::from_slice(&w)?)?;
            k += 1;
            if to < next {
                continue;
            }
            for i in next..from.min(last + 1) {
                out.push(self.one(i).await?);
            }
            for (i, note, entries) in cps {
                if i >= next && i <= last {
                    out.push((note, entries.into_iter().map(|(_, k, b)| (k, b)).collect()));
                }
            }
            next = next.max(from).max(to + 1);
        }
        for i in next..=last {
            out.push(self.one(i).await?);
        }
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use isoloir_proto::state::State;

    // The windows are read first, the checkpoint files fill what they do
    // not hold: before the first window, between two, after the last.
    #[tokio::test]
    async fn windows_then_files() {
        let tmp = tempfile::tempdir().unwrap();
        let m = mirror::Mirror::new(tmp.path().to_path_buf(), None);
        m.prepare().unwrap();
        for i in 1..=5u64 {
            m.write_checkpoint(&State::new(), i, 0, &format!("index {i}\n")).unwrap();
        }
        // The window holds 1..=5; checkpoints 6 and 7 have files only, and
        // checkpoint 1 is removed from the window to make a gap before it.
        for i in 6..=7u64 {
            std::fs::write(tmp.path().join(format!("checkpoints/{i}.txt")), format!("index {i}\n")).unwrap();
            std::fs::write(tmp.path().join(format!("entries/{i}.json")), "[]").unwrap();
        }
        std::fs::write(tmp.path().join("checkpoint.txt"), "index 7\n").unwrap();
        let mut w: serde_json::Value = serde_json::from_slice(&std::fs::read(tmp.path().join("windows/0.json")).unwrap()).unwrap();
        w["from"] = 2.into();
        w["checkpoints"].as_array_mut().unwrap().remove(0);
        std::fs::write(tmp.path().join("windows/0.json"), serde_json::to_vec(&w).unwrap()).unwrap();

        let src = MirrorSource::Dir(tmp.path().to_path_buf());
        let notes = |r: Vec<Read>| r.into_iter().map(|(n, _)| n).collect::<Vec<_>>();
        assert_eq!(notes(src.from(1).await.unwrap()), (1..=7).map(|i| format!("index {i}\n")).collect::<Vec<_>>());
        assert_eq!(notes(src.from(4).await.unwrap()), (4..=7).map(|i| format!("index {i}\n")).collect::<Vec<_>>());
        assert_eq!(notes(src.from(7).await.unwrap()), vec!["index 7\n".to_string()]);
        assert!(src.from(8).await.unwrap().is_empty());
    }
}
