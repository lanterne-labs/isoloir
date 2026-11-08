//! The mirror (SPEC §15): the static files browsers read, written after
//! each checkpoint, in a git repository whose history only grows. A
//! checkpoint writes its files and returns; a background task commits
//! them and pushes, retrying what the remote lacks, so the git host down
//! or full never stops the log. A note names the newest commit the remote
//! is known to hold and the newest checkpoint that commit covers
//! (`mirror <commit>:<index>`).

use isoloir_core::field;
use isoloir_proto::body::{self, Body, EntryKind};
use isoloir_proto::state::State;
use serde_json::{json, Value};
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

/// Leaves per shard.
pub const SHARD: usize = 1024;

/// Checkpoints per window file (SPEC §15): a window closes at this many
/// checkpoints, or earlier once its file passes WINDOW_BYTES, so a quiet
/// year of heartbeats reads in about a hundred fetches and a busy day
/// never makes a file a browser cannot take.
pub const WINDOW: usize = 256;
pub const WINDOW_BYTES: usize = 1 << 20;

/// How often the background task tries again a push that failed.
pub const PUSH_RETRY: Duration = Duration::from_secs(30);

#[derive(Default)]
pub struct Mirror {
    pub dir: PathBuf,
    /// Commit and push to this remote.
    pub git: Option<String>,
    /// Held while files are written and while git reads the tree: a
    /// commit holds whole checkpoints.
    files: Mutex<()>,
    /// The newest checkpoint whose files are all written.
    written: AtomicU64,
    /// The newest commit the remote holds, and the checkpoint it covers.
    pushed: Mutex<Option<(String, u64)>>,
    wake: Mutex<Option<std::sync::mpsc::Sender<()>>>,
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

fn index_of(note: &str) -> Option<u64> {
    note.lines().find_map(|l| l.strip_prefix("index ").and_then(|n| n.parse().ok()))
}

impl Mirror {
    pub fn new(dir: PathBuf, git: Option<String>) -> Mirror {
        Mirror { dir, git, ..Default::default() }
    }

    /// Makes the directory a git mirror of `remote`: cloned when empty (an
    /// ephemeral disk: the circuits and the stamps come back with it),
    /// initialised when new, left alone when it already is one.
    ///
    /// The clone is partial (`--filter=blob:none`): every commit and tree,
    /// the files of the newest commit, and no older version of a file,
    /// which git fetches on demand (a merge in `push`). Not shallow: a
    /// push the remote refuses is merged, which needs the history.
    pub fn prepare(&self) -> anyhow::Result<()> {
        std::fs::create_dir_all(&self.dir)?;
        self.written.store(self.last_index(), Ordering::SeqCst);
        let Some(remote) = &self.git else { return Ok(()) };
        if !self.dir.join(".git").is_dir() {
            let empty = std::fs::read_dir(&self.dir)?.next().is_none();
            let mut cloned = false;
            if empty {
                let started = std::time::Instant::now();
                let out = git_command().arg("clone").arg("-q").arg("--filter=blob:none").arg(remote).arg(&self.dir).output()?;
                if out.status.success() {
                    tracing::info!(remote = %remote, seconds = started.elapsed().as_secs(), "mirror cloned (partial: blob:none)");
                    cloned = true;
                } else {
                    let msg = String::from_utf8_lossy(&out.stderr);
                    if !msg.contains("empty repository") && !msg.contains("not found") && !msg.contains("does not exist") {
                        anyhow::bail!("git clone {remote}: {msg}");
                    }
                }
            }
            if !cloned {
                self.git(&["init", "-q", "-b", "main"])?;
                self.git(&["remote", "add", "origin", remote])?;
            }
        }
        self.written.store(self.last_index(), Ordering::SeqCst);
        // What the remote holds already: its main, and the checkpoint its
        // checkpoint.txt names.
        if let Ok(head) = self.git(&["rev-parse", "--verify", "-q", "origin/main"]) {
            let covered = self.git(&["show", "origin/main:checkpoint.txt"]).ok().and_then(|n| index_of(&n)).unwrap_or(0);
            *self.pushed.lock().unwrap() = Some((head, covered));
        }
        Ok(())
    }

    /// Starts the background task that commits and pushes: after each
    /// checkpoint, and every PUSH_RETRY while the remote lacks commits.
    pub fn start(self: &Arc<Self>) {
        if self.git.is_none() {
            return;
        }
        let (tx, rx) = std::sync::mpsc::channel();
        *self.wake.lock().unwrap() = Some(tx);
        let m = self.clone();
        std::thread::spawn(move || {
            let mut failing = false;
            loop {
                match rx.recv_timeout(PUSH_RETRY) {
                    Ok(()) => while rx.try_recv().is_ok() {},
                    Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {}
                    Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => return,
                }
                match m.sync() {
                    Ok(()) if failing => {
                        failing = false;
                        tracing::info!("mirror pushed again");
                    }
                    Ok(()) => {}
                    Err(e) => {
                        failing = true;
                        tracing::error!(error = %e, "mirror push (retried in the background; the log goes on)");
                    }
                }
            }
        });
    }

    /// The note's `mirror` token: the newest pushed commit and the
    /// checkpoint it covers.
    pub fn token(&self) -> Option<String> {
        self.pushed.lock().unwrap().as_ref().map(|(c, i)| format!("{c}:{i}"))
    }

    /// The newest checkpoint the pushed commit covers.
    pub fn covered(&self) -> Option<u64> {
        self.pushed.lock().unwrap().as_ref().map(|(_, i)| *i)
    }

    fn git(&self, args: &[&str]) -> anyhow::Result<String> {
        let out = git_command().arg("-C").arg(&self.dir).args(args).output()?;
        if !out.status.success() {
            anyhow::bail!("git {}: {}", args.join(" "), String::from_utf8_lossy(&out.stderr));
        }
        Ok(String::from_utf8_lossy(&out.stdout).trim().to_string())
    }

    /// One round of the background task: commits the files written so
    /// far (whole checkpoints) and pushes what the remote lacks.
    pub fn sync(&self) -> anyhow::Result<()> {
        if self.git.is_none() {
            return Ok(());
        }
        let (head, covered) = {
            let _g = self.files.lock().unwrap();
            let covered = self.written.load(Ordering::SeqCst);
            self.git(&["add", "-A"])?;
            if !self.git(&["status", "--porcelain"])?.is_empty() {
                self.git(&["-c", "user.name=isoloir", "-c", "user.email=isoloir@localhost", "commit", "-q", "-m", &format!("checkpoint {covered}")])?;
            }
            (self.git(&["rev-parse", "--verify", "-q", "HEAD"]).ok(), covered)
        };
        let Some(head) = head else { return Ok(()) };
        if self.pushed.lock().unwrap().as_ref().is_some_and(|(c, _)| *c == head) {
            return Ok(());
        }
        self.push_merging()?;
        let head = self.git(&["rev-parse", "HEAD"])?;
        *self.pushed.lock().unwrap() = Some((head, covered));
        Ok(())
    }

    /// Pushes to the remote's main. The repository may take commits from
    /// elsewhere (a README): a push the remote refuses because it moved is
    /// retried after merging it, never rebased, so every pushed commit
    /// stays in the history.
    fn push_merging(&self) -> anyhow::Result<()> {
        if self.git(&["push", "-q", "origin", "HEAD:main"]).is_ok() {
            return Ok(());
        }
        self.git(&["fetch", "-q", "origin", "main"])?;
        {
            let _g = self.files.lock().unwrap();
            if let Err(e) = self.git(&["-c", "user.name=isoloir", "-c", "user.email=isoloir@localhost", "merge", "-q", "--no-edit", "FETCH_HEAD"]) {
                // A conflict: leave the tree as it was, never a half merge
                // that the next commit would take.
                let _ = self.git(&["merge", "--abort"]);
                return Err(e);
            }
        }
        self.git(&["push", "-q", "origin", "HEAD:main"])?;
        Ok(())
    }

    /// Writes a checkpoint's files: the data of the entries
    /// `from..state.next_seq()` and the signed note, as one step for the
    /// background commit. The checkpoint is in the store already: the
    /// mirror never holds one the log lacks.
    pub fn write_checkpoint(&self, state: &State, index: u64, from: u64, note: &str) -> anyhow::Result<()> {
        {
            let _g = self.files.lock().unwrap();
            let entries = self.write_data(state, index, from)?;
            write(&self.dir.join(format!("checkpoints/{index}.txt")), note.as_bytes())?;
            self.append_window(index, note, entries)?;
            write(&self.dir.join("checkpoint.txt"), note.as_bytes())?;
            self.written.store(index, Ordering::SeqCst);
        }
        if let Some(w) = self.wake.lock().unwrap().as_ref() {
            let _ = w.send(());
        }
        Ok(())
    }

    /// The data files of the entries `from..state.next_seq()` of
    /// checkpoint `index`; returns the entries as `entries/<index>.json`
    /// holds them. The positions and pseudonyms files of earlier versions
    /// are no longer written (SPEC §15).
    fn write_data(&self, state: &State, index: u64, from: u64) -> anyhow::Result<Vec<Value>> {
        let entries: Vec<Value> = (from..state.next_seq())
            .map(|seq| {
                let (k, b) = &state.entries[seq as usize];
                json!({"seq": seq, "kind": k.as_str(), "body": String::from_utf8_lossy(b)})
            })
            .collect();
        write_json(&self.dir.join(format!("entries/{index}.json")), &Value::Array(entries.clone()))?;
        let mut leaves_touched: BTreeSet<(u32, usize)> = BTreeSet::new();
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
                }
                Ok(Body::Ballot(bal)) => {
                    let p = &state.polls[&bal.poll];
                    if let (None, Some(t)) = (&bal.nullifier, &p.btree) {
                        ballot_shards.insert((bal.poll, (t.len() - 1) / SHARD));
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
        for (poll, k) in ballot_shards {
            let t = state.polls[&poll].btree.as_ref().expect("delta");
            let leaves: Vec<String> = (k * SHARD..((k + 1) * SHARD).min(t.len())).map(|i| field::to_hex(&t.leaf(i).unwrap())).collect();
            write_json(&self.dir.join(format!("polls/{poll}/ballots/{k}.json")), &json!(leaves))?;
        }
        Ok(entries)
    }

    /// The newest window file (its number and its content), if any.
    fn last_window(&self) -> Option<(u64, Value)> {
        let k = std::fs::read_dir(self.dir.join("windows"))
            .ok()?
            .filter_map(|e| e.ok()?.file_name().to_str()?.strip_suffix(".json")?.parse::<u64>().ok())
            .max()?;
        Some((k, read_json(&self.dir.join(format!("windows/{k}.json")))))
    }

    /// Adds checkpoint `index` (its note and its entries) to the open
    /// window, or opens the next one when the last is closed (WINDOW
    /// checkpoints, or WINDOW_BYTES) or does not end at `index - 1`: a
    /// window is contiguous, and a reader that finds a gap before one
    /// reads the checkpoint files of the gap (SPEC §15).
    fn append_window(&self, index: u64, note: &str, entries: Vec<Value>) -> anyhow::Result<()> {
        let (k, mut w) = match self.last_window() {
            Some((k, w)) => {
                let to = w["to"].as_u64().unwrap_or(0);
                let n = w["checkpoints"].as_array().map_or(0, |a| a.len());
                let bytes = std::fs::metadata(self.dir.join(format!("windows/{k}.json"))).map_or(0, |m| m.len() as usize);
                if to == index - 1 && n < WINDOW && bytes < WINDOW_BYTES {
                    (k, w)
                } else if to >= index {
                    // Written already (a boot that backfills what is there).
                    return Ok(());
                } else {
                    (k + 1, json!({"from": index, "to": index, "checkpoints": []}))
                }
            }
            None => (0, json!({"from": index, "to": index, "checkpoints": []})),
        };
        w["to"] = json!(index);
        w["checkpoints"].as_array_mut().expect("checkpoints").push(json!({"index": index, "note": note, "entries": entries}));
        write_json(&self.dir.join(format!("windows/{k}.json")), &w)
    }

    /// Writes the windows of the checkpoints the mirror holds that no
    /// window holds yet (a mirror written before the windows, at boot):
    /// `notes` are every checkpoint's note, `entries` the log's entries
    /// with the checkpoint each was logged in.
    pub fn backfill_windows(&self, notes: &[(u64, String)], entries: &[(u64, EntryKind, Vec<u8>, u64)]) -> anyhow::Result<u64> {
        let _g = self.files.lock().unwrap();
        let from = self.last_window().and_then(|(_, w)| w["to"].as_u64()).map_or(1, |to| to + 1);
        let mut n = 0;
        for (index, note) in notes.iter().filter(|(i, _)| *i >= from) {
            let es: Vec<Value> = entries
                .iter()
                .filter(|e| e.3 == *index)
                .map(|(seq, k, b, _)| json!({"seq": seq, "kind": k.as_str(), "body": String::from_utf8_lossy(b)}))
                .collect();
            self.append_window(*index, note, es)?;
            n += 1;
        }
        if n > 0 {
            if let Some(w) = self.wake.lock().unwrap().as_ref() {
                let _ = w.send(());
            }
        }
        Ok(n)
    }

    fn append_setup(&self, path: &Path, entry: Value) -> anyhow::Result<()> {
        let mut v = read_json(path);
        if !v.is_object() {
            v = json!({"setups": []});
        }
        v["setups"].as_array_mut().expect("setups").push(entry);
        write_json(path, &v)
    }

    /// The index of the newest checkpoint on the mirror (0 for none).
    pub fn last_index(&self) -> u64 {
        std::fs::read_to_string(self.dir.join("checkpoint.txt")).ok().and_then(|t| index_of(&t)).unwrap_or(0)
    }

    /// Writes a stamp.
    pub fn write_stamp(&self, index: u64, ots: &[u8]) -> anyhow::Result<()> {
        let _g = self.files.lock().unwrap();
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

/// A window file (`windows/<k>.json`): the checkpoints `from..=to`, each
/// with its note and its entries as `entries/<index>.json` holds them.
pub fn parse_window(v: &Value) -> anyhow::Result<(u64, u64, Vec<(u64, String, Vec<(u64, EntryKind, Vec<u8>)>)>)> {
    let from = v["from"].as_u64().ok_or_else(|| anyhow::anyhow!("window: no from"))?;
    let to = v["to"].as_u64().ok_or_else(|| anyhow::anyhow!("window: no to"))?;
    let cps = v["checkpoints"]
        .as_array()
        .ok_or_else(|| anyhow::anyhow!("window: no checkpoints"))?
        .iter()
        .map(|c| {
            let index = c["index"].as_u64().ok_or_else(|| anyhow::anyhow!("window: a checkpoint without index"))?;
            let note = c["note"].as_str().ok_or_else(|| anyhow::anyhow!("window: checkpoint {index} without note"))?.to_string();
            Ok((index, note, parse_entries(&c["entries"])?))
        })
        .collect::<anyhow::Result<Vec<_>>>()?;
    if cps.first().is_some_and(|c| c.0 != from) || cps.last().is_some_and(|c| c.0 != to) || cps.windows(2).any(|p| p[1].0 != p[0].0 + 1) {
        anyhow::bail!("window: the checkpoints are not {from}..={to}");
    }
    Ok((from, to, cps))
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

    /// A checkpoint's files (no entries), then one round of the background
    /// task.
    fn checkpoint(m: &Mirror, index: u64) -> anyhow::Result<()> {
        m.write_checkpoint(&State::new(), index, 0, &format!("index {index}\n"))?;
        m.sync()
    }

    fn bare(tmp: &Path) -> (PathBuf, String) {
        let remote = tmp.join("remote.git");
        run(tmp, &["init", "-q", "--bare", "-b", "main", remote.to_str().unwrap()]);
        run(&remote, &["config", "uploadpack.allowFilter", "true"]);
        let url = format!("file://{}", remote.display());
        (remote, url)
    }

    // A commit pushed from elsewhere (a README) is merged, not lost, and
    // the mirror's own commits stay in the history; the note's token names
    // the pushed commit and the checkpoint it covers.
    #[test]
    fn push_keeps_outside_commits() {
        let tmp = tempfile::tempdir().unwrap();
        let (_, url) = bare(tmp.path());
        let m = Mirror::new(tmp.path().join("mirror"), Some(url.clone()));
        m.prepare().unwrap();
        assert_eq!(m.token(), None);
        checkpoint(&m, 1).unwrap();
        let first = run(&m.dir, &["rev-parse", "HEAD"]);
        assert_eq!(m.token(), Some(format!("{first}:1")));

        let other = tmp.path().join("other");
        run(tmp.path(), &["clone", "-q", &url, other.to_str().unwrap()]);
        std::fs::write(other.join("README.md"), "# a mirror\n").unwrap();
        run(&other, &["add", "README.md"]);
        run(&other, &["-c", "user.name=t", "-c", "user.email=t@t", "commit", "-q", "-m", "README"]);
        run(&other, &["push", "-q", "origin", "HEAD:main"]);

        checkpoint(&m, 2).unwrap();
        run(&other, &["pull", "-q", "--no-rebase", "origin", "main"]);
        assert_eq!(std::fs::read_to_string(other.join("README.md")).unwrap(), "# a mirror\n");
        assert_eq!(std::fs::read_to_string(other.join("checkpoint.txt")).unwrap(), "index 2\n");
        run(&other, &["merge-base", "--is-ancestor", &first, "HEAD"]);
        let head = run(&other, &["rev-parse", "HEAD"]);
        assert_eq!(m.token(), Some(format!("{head}:2")));
    }

    // A boot on an empty disk clones without the old versions of files
    // (blob:none) and knows what the remote holds; every step after it
    // works: the commits, the merge of an outside commit (which fetches
    // the blobs it needs), the push. With the remote gone, checkpoints go
    // on and the token stays at the last pushed commit until it is back.
    #[test]
    fn partial_clone() {
        let tmp = tempfile::tempdir().unwrap();
        let (remote, url) = bare(tmp.path());
        let lines = |first: &str, last: &str| format!("{first}\n{}{last}\n", (0..50).map(|i| format!("line {i}\n")).collect::<String>());

        // A first life of the ingest: two versions of a file.
        let a = Mirror::new(tmp.path().join("a"), Some(url.clone()));
        a.prepare().unwrap();
        write(&a.dir.join("shard.txt"), lines("first", "last").as_bytes()).unwrap();
        checkpoint(&a, 1).unwrap();
        let old_blob = run(&a.dir, &["rev-parse", "HEAD:shard.txt"]);
        write(&a.dir.join("shard.txt"), lines("first", "last v2").as_bytes()).unwrap();
        checkpoint(&a, 2).unwrap();
        let second = run(&a.dir, &["rev-parse", "HEAD"]);

        // The next boot, on an empty disk.
        let m = Mirror::new(tmp.path().join("m"), Some(url.clone()));
        m.prepare().unwrap();
        assert_eq!(run(&m.dir, &["config", "remote.origin.partialclonefilter"]), "blob:none");
        let missing = run(&m.dir, &["rev-list", "--objects", "--all", "--missing=print"]);
        assert!(missing.lines().any(|l| l == format!("?{old_blob}")), "the old version is not fetched: {missing}");
        assert_eq!(m.last_index(), 2);
        assert_eq!(m.token(), Some(format!("{second}:2")));
        assert_eq!(std::fs::read_to_string(m.dir.join("shard.txt")).unwrap(), lines("first", "last v2"));

        // An outside commit changes the file's first line; the mirror its
        // last: the merge needs the other side's blob, fetched on demand.
        let other = tmp.path().join("other");
        run(tmp.path(), &["clone", "-q", &url, other.to_str().unwrap()]);
        std::fs::write(other.join("shard.txt"), lines("first (edited)", "last v2")).unwrap();
        run(&other, &["-c", "user.name=t", "-c", "user.email=t@t", "commit", "-q", "-am", "edit"]);
        run(&other, &["push", "-q", "origin", "HEAD:main"]);
        write(&m.dir.join("shard.txt"), lines("first", "last v3").as_bytes()).unwrap();
        m.write_stamp(3, b"ots").unwrap();
        checkpoint(&m, 3).unwrap();
        run(&other, &["pull", "-q", "--no-rebase", "origin", "main"]);
        assert_eq!(std::fs::read_to_string(other.join("shard.txt")).unwrap(), lines("first (edited)", "last v3"));
        assert!(other.join("stamps/3.ots").is_file());
        run(&other, &["merge-base", "--is-ancestor", &second, "HEAD"]);
        let pushed = m.token().unwrap();
        assert!(pushed.ends_with(":3"));

        // The remote gone: the files are written, the push fails, the
        // token stays; back, the next round pushes everything.
        run(&m.dir, &["remote", "set-url", "origin", "file:///nonexistent/remote.git"]);
        assert!(checkpoint(&m, 4).is_err());
        assert!(checkpoint(&m, 5).is_err());
        assert_eq!(m.token().unwrap(), pushed);
        run(&m.dir, &["remote", "set-url", "origin", &url]);
        m.sync().unwrap();
        assert!(m.token().unwrap().ends_with(":5"));
        assert_eq!(run(&remote, &["show", "main:checkpoint.txt"]), "index 5");
        assert_eq!(run(&remote, &["show", "main:checkpoints/4.txt"]), "index 4");
    }

    // A merge that conflicts is undone: the next commit takes no half
    // merge, and the push is tried again.
    #[test]
    fn conflicting_merge_is_undone() {
        let tmp = tempfile::tempdir().unwrap();
        let (_, url) = bare(tmp.path());
        let m = Mirror::new(tmp.path().join("m"), Some(url.clone()));
        m.prepare().unwrap();
        checkpoint(&m, 1).unwrap();
        let other = tmp.path().join("other");
        run(tmp.path(), &["clone", "-q", &url, other.to_str().unwrap()]);
        std::fs::write(other.join("checkpoint.txt"), "not a note\n").unwrap();
        run(&other, &["-c", "user.name=t", "-c", "user.email=t@t", "commit", "-q", "-am", "clash"]);
        run(&other, &["push", "-q", "origin", "HEAD:main"]);
        assert!(checkpoint(&m, 2).is_err());
        assert!(m.token().unwrap().ends_with(":1"));
        assert!(!m.dir.join(".git/MERGE_HEAD").exists());
        assert_eq!(std::fs::read_to_string(m.dir.join("checkpoint.txt")).unwrap(), "index 2\n");
    }

    // Every checkpoint joins the open window; a window closes at WINDOW
    // checkpoints; a boot backfills the checkpoints no window holds, and a
    // gap before a window is left to the checkpoint files.
    #[test]
    fn windows() {
        let tmp = tempfile::tempdir().unwrap();
        let m = Mirror::new(tmp.path().join("m"), None);
        m.prepare().unwrap();
        for i in 1..=(WINDOW as u64 + 2) {
            checkpoint(&m, i).unwrap();
        }
        let (from, to, cps) = parse_window(&read_json(&m.dir.join("windows/0.json"))).unwrap();
        assert_eq!((from, to, cps.len()), (1, WINDOW as u64, WINDOW));
        assert_eq!(cps[3].1, "index 4\n");
        let (from, to, cps) = parse_window(&read_json(&m.dir.join("windows/1.json"))).unwrap();
        assert_eq!((from, to, cps.len()), (WINDOW as u64 + 1, WINDOW as u64 + 2, 2));
        assert!(!m.dir.join("windows/2.json").exists());

        // A mirror written before the windows: the boot fills them, once.
        let old = Mirror::new(tmp.path().join("old"), None);
        old.prepare().unwrap();
        for i in 1..=3u64 {
            write(&old.dir.join(format!("checkpoints/{i}.txt")), format!("index {i}\n").as_bytes()).unwrap();
        }
        let notes: Vec<(u64, String)> = (1..=3).map(|i| (i, format!("index {i}\n"))).collect();
        let entries = vec![(0u64, EntryKind::Ledger, b"{}".to_vec(), 2u64)];
        assert_eq!(old.backfill_windows(&notes, &entries).unwrap(), 3);
        assert_eq!(old.backfill_windows(&notes, &entries).unwrap(), 0);
        let (from, to, cps) = parse_window(&read_json(&old.dir.join("windows/0.json"))).unwrap();
        assert_eq!((from, to), (1, 3));
        assert_eq!(cps[1].2, vec![(0, EntryKind::Ledger, b"{}".to_vec())]);
        assert!(cps[0].2.is_empty());

        // A checkpoint that does not follow the window's end opens a new one.
        checkpoint(&old, 6).unwrap();
        let (from, to, _) = parse_window(&read_json(&old.dir.join("windows/1.json"))).unwrap();
        assert_eq!((from, to), (6, 6));
    }

    // The background task pushes after a checkpoint without being asked.
    #[test]
    fn background_push() {
        let tmp = tempfile::tempdir().unwrap();
        let (remote, url) = bare(tmp.path());
        let m = Arc::new(Mirror::new(tmp.path().join("m"), Some(url)));
        m.prepare().unwrap();
        m.start();
        m.write_checkpoint(&State::new(), 1, 0, "index 1\n").unwrap();
        let until = std::time::Instant::now() + Duration::from_secs(20);
        while m.token().is_none() && std::time::Instant::now() < until {
            std::thread::sleep(Duration::from_millis(50));
        }
        assert!(m.token().unwrap().ends_with(":1"));
        assert_eq!(run(&remote, &["show", "main:checkpoint.txt"]), "index 1");
    }
}
