//! The mirror (SPEC §15): the static files browsers read, written after
//! each checkpoint. A checkpoint's data files are written first; with a
//! git mirror they are committed, and the commit is the token the note
//! names, so a reader can prove which files it was served; the note
//! itself follows in a second commit.

use isoloir_core::field;
use isoloir_proto::body::{self, Body, EntryKind};
use isoloir_proto::state::State;
use serde_json::{json, Map, Value};
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::process::Command;

/// Leaves per shard.
pub const SHARD: usize = 1024;

pub struct Mirror {
    pub dir: PathBuf,
    /// Commit and push to this remote after each checkpoint.
    pub git: Option<String>,
}

fn write(path: &Path, bytes: &[u8]) -> anyhow::Result<()> {
    if let Some(d) = path.parent() {
        std::fs::create_dir_all(d)?;
    }
    let tmp = path.with_extension("tmp");
    std::fs::write(&tmp, bytes)?;
    std::fs::rename(&tmp, path)?;
    Ok(())
}

fn write_json(path: &Path, v: &Value) -> anyhow::Result<()> {
    write(path, &serde_json::to_vec(v)?)
}

fn read_json(path: &Path) -> Value {
    std::fs::read(path).ok().and_then(|b| serde_json::from_slice(&b).ok()).unwrap_or(Value::Null)
}

fn prefix(hex: &str) -> &str {
    &hex[2..4]
}

impl Mirror {
    /// Makes the directory a git mirror of `remote`: cloned when empty (an
    /// ephemeral disk: the circuits and the stamps come back with it),
    /// initialised when new, left alone when it already is one.
    pub fn prepare(&self) -> anyhow::Result<()> {
        let Some(remote) = &self.git else {
            std::fs::create_dir_all(&self.dir)?;
            return Ok(());
        };
        std::fs::create_dir_all(&self.dir)?;
        if self.dir.join(".git").is_dir() {
            return Ok(());
        }
        let empty = std::fs::read_dir(&self.dir)?.next().is_none();
        if empty {
            let out = git_command().arg("clone").arg("-q").arg(remote).arg(&self.dir).output()?;
            if out.status.success() {
                return Ok(());
            }
            let msg = String::from_utf8_lossy(&out.stderr);
            if !msg.contains("empty repository") && !msg.contains("not found") && !msg.contains("does not exist") {
                anyhow::bail!("git clone {remote}: {msg}");
            }
        }
        self.git(&["init", "-q", "-b", "main"])?;
        self.git(&["remote", "add", "origin", remote])?;
        Ok(())
    }

    fn git(&self, args: &[&str]) -> anyhow::Result<String> {
        let out = git_command().arg("-C").arg(&self.dir).args(args).output()?;
        if !out.status.success() {
            anyhow::bail!("git {}: {}", args.join(" "), String::from_utf8_lossy(&out.stderr));
        }
        Ok(String::from_utf8_lossy(&out.stdout).trim().to_string())
    }

    fn commit(&self, message: &str) -> anyhow::Result<Option<String>> {
        if self.git.is_none() {
            return Ok(None);
        }
        self.git(&["add", "-A"])?;
        if self.git(&["status", "--porcelain"])?.is_empty() {
            return Ok(Some(self.git(&["rev-parse", "HEAD"])?));
        }
        self.git(&["-c", "user.name=isoloir", "-c", "user.email=isoloir@localhost", "commit", "-q", "-m", message])?;
        Ok(Some(self.git(&["rev-parse", "HEAD"])?))
    }

    /// Pushes to the remote's main. The repository may take commits from
    /// elsewhere (a README): a push the remote refuses because it moved is
    /// retried after merging it, never rebased, so every commit a
    /// checkpoint names as its mirror token stays in the history.
    fn push(&self) -> anyhow::Result<()> {
        if self.git.is_none() {
            return Ok(());
        }
        if self.git(&["push", "-q", "origin", "HEAD:main"]).is_ok() {
            return Ok(());
        }
        self.git(&["fetch", "-q", "origin", "main"])?;
        self.git(&["-c", "user.name=isoloir", "-c", "user.email=isoloir@localhost", "merge", "-q", "--no-edit", "FETCH_HEAD"])?;
        self.git(&["push", "-q", "origin", "HEAD:main"])?;
        Ok(())
    }

    /// Writes the data files of the entries `from..state.next_seq()` of
    /// checkpoint `index` and returns the mirror token (the commit), if any.
    pub fn write_data(&self, state: &State, index: u64, from: u64) -> anyhow::Result<Option<String>> {
        let entries: Vec<Value> = (from..state.next_seq())
            .map(|seq| {
                let (k, b) = &state.entries[seq as usize];
                json!({"seq": seq, "kind": k.as_str(), "body": String::from_utf8_lossy(b)})
            })
            .collect();
        write_json(&self.dir.join(format!("entries/{index}.json")), &Value::Array(entries))?;
        let mut leaves_touched: BTreeSet<(u32, usize)> = BTreeSet::new();
        let mut positions_touched: BTreeSet<(u32, String)> = BTreeSet::new();
        let mut pseudonyms_touched: BTreeSet<(u32, String)> = BTreeSet::new();
        let mut ballot_shards: BTreeSet<(u32, usize)> = BTreeSet::new();
        for seq in from..state.next_seq() {
            let (k, b) = &state.entries[seq as usize];
            match body::decode(*k, b) {
                Ok(Body::Ledger(_)) => self.append_setup(&self.dir.join("setup/ledger.json"), proven(state, seq, index))?,
                Ok(Body::Registry(r)) => self.append_setup(&self.dir.join(format!("registries/{}.json", r.id)), proven(state, seq, index))?,
                Ok(Body::Poll(p)) => self.append_setup(&self.dir.join(format!("polls/{}.json", p.id)), proven(state, seq, index))?,
                Ok(Body::Register(r)) => {
                    let pos = state.registries[&r.registry].ids[&r.id] as usize;
                    leaves_touched.insert((r.registry, pos / SHARD));
                    positions_touched.insert((r.registry, prefix(&r.id).to_string()));
                }
                Ok(Body::Ballot(bal)) => {
                    let p = &state.polls[&bal.poll];
                    match (&bal.nullifier, &p.btree) {
                        (Some(n), _) => {
                            pseudonyms_touched.insert((bal.poll, prefix(n).to_string()));
                        }
                        (None, Some(t)) => {
                            ballot_shards.insert((bal.poll, (t.len() - 1) / SHARD));
                        }
                        _ => {}
                    }
                }
                Ok(Body::Tally(t)) => {
                    let v = proven(state, seq, index);
                    write_json(&self.dir.join(format!("polls/{}/tallies/{seq}.json", t.poll)), &v)?;
                    write_json(&self.dir.join(format!("polls/{}/tallies/latest.json", t.poll)), &v)?;
                }
                Ok(Body::Close(c)) => write_json(&self.dir.join(format!("polls/{}/close.json", c.poll)), &json!({"seq": seq, "body": String::from_utf8_lossy(b)}))?,
                _ => {}
            }
        }
        for (reg, k) in leaves_touched {
            let t = &state.registries[&reg].tree;
            let leaves: Vec<String> = (k * SHARD..((k + 1) * SHARD).min(t.len())).map(|i| field::to_hex(&t.leaf(i).unwrap())).collect();
            write_json(&self.dir.join(format!("registries/{reg}/leaves/{k}.json")), &json!(leaves))?;
        }
        for (reg, pp) in positions_touched {
            let mut m: Map<String, Value> = Map::new();
            for (id, pos) in &state.registries[&reg].ids {
                if prefix(id) == pp {
                    m.insert(id.clone(), json!(pos));
                }
            }
            write_json(&self.dir.join(format!("registries/{reg}/positions/{pp}.json")), &Value::Object(m))?;
        }
        for (poll, pp) in pseudonyms_touched {
            let mut m: Map<String, Value> = Map::new();
            for (n, (s, _)) in &state.polls[&poll].latest {
                if prefix(n) == pp {
                    m.insert(n.clone(), json!(s));
                }
            }
            write_json(&self.dir.join(format!("polls/{poll}/pseudonyms/{pp}.json")), &Value::Object(m))?;
        }
        for (poll, k) in ballot_shards {
            let t = state.polls[&poll].btree.as_ref().expect("delta");
            let leaves: Vec<String> = (k * SHARD..((k + 1) * SHARD).min(t.len())).map(|i| field::to_hex(&t.leaf(i).unwrap())).collect();
            write_json(&self.dir.join(format!("polls/{poll}/ballots/{k}.json")), &json!(leaves))?;
        }
        self.commit(&format!("checkpoint {index}: data"))
    }

    fn append_setup(&self, path: &Path, entry: Value) -> anyhow::Result<()> {
        let mut v = read_json(path);
        if !v.is_object() {
            v = json!({"setups": []});
        }
        v["setups"].as_array_mut().expect("setups").push(entry);
        write_json(path, &v)
    }

    /// Writes the signed note of a checkpoint, commits and pushes.
    pub fn write_note(&self, index: u64, note: &str) -> anyhow::Result<()> {
        write(&self.dir.join(format!("checkpoints/{index}.txt")), note.as_bytes())?;
        write(&self.dir.join("checkpoint.txt"), note.as_bytes())?;
        self.commit(&format!("checkpoint {index}"))?;
        self.push()
    }

    /// The index of the newest checkpoint on the mirror (0 for none).
    pub fn last_index(&self) -> u64 {
        std::fs::read_to_string(self.dir.join("checkpoint.txt"))
            .ok()
            .and_then(|t| t.lines().find_map(|l| l.strip_prefix("index ").and_then(|n| n.parse().ok())))
            .unwrap_or(0)
    }

    /// Writes a stamp.
    pub fn write_stamp(&self, index: u64, ots: &[u8]) -> anyhow::Result<()> {
        write(&self.dir.join(format!("stamps/{index}.ots")), ots)
    }

    /// Installs a circuit (artifact and verification key).
    pub fn install_circuit(&self, name: &str, artifact: &Path, vk: &Path) -> anyhow::Result<()> {
        let d = self.dir.join("circuits").join(name);
        std::fs::create_dir_all(&d)?;
        let bytes = isoloir_proto::artifact::published(&std::fs::read(artifact)?).map_err(anyhow::Error::msg)?;
        std::fs::write(d.join("artifact.json"), bytes)?;
        std::fs::copy(vk, d.join("vk"))?;
        Ok(())
    }
}

/// `git`, with `ISOLOIR_MIRROR_SSH_KEY` (a private key, for pushing to
/// the mirror's remote over SSH) when it is set: written once to a file
/// only the process reads.
fn git_command() -> Command {
    let mut c = Command::new("git");
    if let Some(path) = ssh_key_file() {
        c.env("GIT_SSH_COMMAND", format!("ssh -i {} -o IdentitiesOnly=yes -o StrictHostKeyChecking=accept-new", path.display()));
    }
    c
}

fn ssh_key_file() -> Option<PathBuf> {
    static FILE: std::sync::OnceLock<Option<PathBuf>> = std::sync::OnceLock::new();
    FILE.get_or_init(|| {
        let key = std::env::var("ISOLOIR_MIRROR_SSH_KEY").ok().filter(|k| !k.trim().is_empty())?;
        let path = std::env::temp_dir().join(format!("isoloir-mirror-key-{}", std::process::id()));
        let mut body = key.replace("\\n", "\n");
        if !body.ends_with('\n') {
            body.push('\n');
        }
        let write = || -> std::io::Result<()> {
            use std::io::Write;
            #[cfg(unix)]
            use std::os::unix::fs::OpenOptionsExt;
            let mut o = std::fs::OpenOptions::new();
            o.write(true).create(true).truncate(true);
            #[cfg(unix)]
            o.mode(0o600);
            o.open(&path)?.write_all(body.as_bytes())
        };
        match write() {
            Ok(()) => Some(path),
            Err(e) => {
                tracing::error!(error = %e, "ISOLOIR_MIRROR_SSH_KEY could not be written");
                None
            }
        }
    })
    .clone()
}

/// An entry with its proof of inclusion in the log at checkpoint `index`
/// (SPEC §15): a reader checks it against the signed note, so a mirror
/// cannot serve a setup or a tally the log does not hold.
fn proven(state: &State, seq: u64, index: u64) -> Value {
    let (k, b) = &state.entries[seq as usize];
    let size = state.next_seq();
    let path: Vec<String> = state.log.inclusion(seq as usize, size as usize).iter().map(hex::encode).collect();
    json!({"seq": seq, "kind": k.as_str(), "body": String::from_utf8_lossy(b), "checkpoint": index, "size": size, "path": path})
}

/// Reads a checkpoint's entries from a mirror's `entries/<index>.json`.
pub fn parse_entries(v: &Value) -> anyhow::Result<Vec<(u64, EntryKind, Vec<u8>)>> {
    v.as_array()
        .ok_or_else(|| anyhow::anyhow!("entries: not an array"))?
        .iter()
        .map(|e| {
            let seq = e["seq"].as_u64().ok_or_else(|| anyhow::anyhow!("entry without seq"))?;
            let kind = e["kind"].as_str().and_then(EntryKind::parse).ok_or_else(|| anyhow::anyhow!("entry {seq}: kind"))?;
            let body = e["body"].as_str().ok_or_else(|| anyhow::anyhow!("entry {seq}: body"))?.as_bytes().to_vec();
            Ok((seq, kind, body))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn run(dir: &Path, args: &[&str]) -> String {
        let out = Command::new("git").arg("-C").arg(dir).args(args).output().unwrap();
        assert!(out.status.success(), "git {args:?}: {}", String::from_utf8_lossy(&out.stderr));
        String::from_utf8_lossy(&out.stdout).trim().to_string()
    }

    // A commit pushed from elsewhere (a README) is merged, not lost, and
    // the mirror's own commits stay in the history.
    #[test]
    fn push_keeps_outside_commits() {
        let tmp = tempfile::tempdir().unwrap();
        let remote = tmp.path().join("remote.git");
        run(tmp.path(), &["init", "-q", "--bare", "-b", "main", remote.to_str().unwrap()]);
        let m = Mirror { dir: tmp.path().join("mirror"), git: Some(remote.to_str().unwrap().to_string()) };
        m.prepare().unwrap();
        m.write_note(1, "note 1\n").unwrap();
        let first = run(&m.dir, &["rev-parse", "HEAD"]);

        let other = tmp.path().join("other");
        run(tmp.path(), &["clone", "-q", remote.to_str().unwrap(), other.to_str().unwrap()]);
        std::fs::write(other.join("README.md"), "# a mirror\n").unwrap();
        run(&other, &["add", "README.md"]);
        run(&other, &["-c", "user.name=t", "-c", "user.email=t@t", "commit", "-q", "-m", "README"]);
        run(&other, &["push", "-q", "origin", "HEAD:main"]);

        m.write_note(2, "note 2\n").unwrap();
        run(&other, &["pull", "-q", "--no-rebase", "origin", "main"]);
        assert_eq!(std::fs::read_to_string(other.join("README.md")).unwrap(), "# a mirror\n");
        assert_eq!(std::fs::read_to_string(other.join("checkpoint.txt")).unwrap(), "note 2\n");
        run(&other, &["merge-base", "--is-ancestor", &first, "HEAD"]);
    }
}
