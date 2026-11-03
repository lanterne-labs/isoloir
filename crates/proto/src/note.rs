//! Checkpoints (SPEC §4) as C2SP signed notes: the text, the Ed25519
//! signature by the ledger's log key, and the verifier key string
//! `<name>+<key id hex>+<base64(0x01 ‖ public key)>`.

use crate::log::Hash;
use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use ed25519_dalek::{Signer as _, SigningKey, Verifier as _, VerifyingKey};
use isoloir_core::{Fr, field};
use sha2::{Digest, Sha256};

const ALG_ED25519: u8 = 1;

fn key_id(name: &str, pubkey: &[u8; 32]) -> [u8; 4] {
    let mut h = Sha256::new();
    h.update(name.as_bytes());
    h.update(b"\n");
    h.update([ALG_ED25519]);
    h.update(pubkey);
    h.finalize()[..4].try_into().unwrap()
}

/// A note signer: a name and an Ed25519 key.
pub struct Signer {
    pub name: String,
    key: SigningKey,
}

impl Signer {
    pub fn new(name: &str, seed: &[u8; 32]) -> Self {
        Signer { name: name.to_string(), key: SigningKey::from_bytes(seed) }
    }

    /// A signer from a C2SP private key string
    /// `PRIVATE+KEY+<name>+<key id hex>+<base64(0x01 ‖ seed)>` (what Go's
    /// `golang.org/x/mod/sumdb/note` writes), checked against its key id.
    pub fn from_private(s: &str) -> Result<Self, String> {
        let rest = s.strip_prefix("PRIVATE+KEY+").ok_or("not a PRIVATE+KEY string")?;
        // A name has no '+' (C2SP signed-note); the base64 key data may.
        let mut parts = rest.splitn(3, '+');
        let (name, id, kd) = (parts.next().ok_or("no name")?, parts.next().ok_or("no key id")?, parts.next().ok_or("no key data")?);
        let kd = STANDARD.decode(kd).map_err(|e| e.to_string())?;
        if kd.len() != 33 || kd[0] != ALG_ED25519 {
            return Err("not an Ed25519 key".into());
        }
        let seed: [u8; 32] = kd[1..].try_into().unwrap();
        let signer = Signer::new(name, &seed);
        let pk = signer.key.verifying_key().to_bytes();
        if hex::encode(key_id(name, &pk)) != id {
            return Err("the key id does not match the key".into());
        }
        Ok(signer)
    }

    /// The seed (secret).
    pub fn seed(&self) -> [u8; 32] {
        self.key.to_bytes()
    }

    /// The verifier key string.
    pub fn verifier(&self) -> String {
        let pk = self.key.verifying_key().to_bytes();
        let mut kd = vec![ALG_ED25519];
        kd.extend_from_slice(&pk);
        format!("{}+{}+{}", self.name, hex::encode(key_id(&self.name, &pk)), STANDARD.encode(kd))
    }

    /// Signs a text (ending in a newline): the signed note.
    pub fn sign(&self, text: &str) -> String {
        assert!(text.ends_with('\n'), "a note's text ends with a newline");
        let pk = self.key.verifying_key().to_bytes();
        let sig = self.key.sign(text.as_bytes());
        let mut blob = key_id(&self.name, &pk).to_vec();
        blob.extend_from_slice(&sig.to_bytes());
        format!("{text}\n\u{2014} {} {}\n", self.name, STANDARD.encode(blob))
    }
}

/// A parsed verifier key.
#[derive(Clone, Debug)]
pub struct Verifier {
    pub name: String,
    id: [u8; 4],
    key: VerifyingKey,
}

impl Verifier {
    pub fn parse(s: &str) -> Result<Verifier, String> {
        let mut parts = s.splitn(3, '+');
        let (name, id, kd) = (parts.next().unwrap_or(""), parts.next().ok_or("no key id")?, parts.next().ok_or("no key data")?);
        let kd = STANDARD.decode(kd).map_err(|e| e.to_string())?;
        if kd.len() != 33 || kd[0] != ALG_ED25519 {
            return Err("not an Ed25519 key".into());
        }
        let pk: [u8; 32] = kd[1..].try_into().unwrap();
        if hex::encode(key_id(name, &pk)) != id {
            return Err("key id does not match".into());
        }
        let key = VerifyingKey::from_bytes(&pk).map_err(|e| e.to_string())?;
        Ok(Verifier { name: name.to_string(), id: key_id(name, &pk), key })
    }

    /// Checks a signed note and returns its text.
    pub fn open<'a>(&self, note: &'a str) -> Result<&'a str, String> {
        let split = note.rfind("\n\n").ok_or("no signature block")?;
        let (text, sigs) = (&note[..split + 1], &note[split + 2..]);
        for line in sigs.lines() {
            let rest = line.strip_prefix("\u{2014} ").ok_or("a signature line starts with an em dash")?;
            let (name, b64) = rest.split_once(' ').ok_or("malformed signature line")?;
            if name != self.name {
                continue;
            }
            let blob = STANDARD.decode(b64).map_err(|e| e.to_string())?;
            if blob.len() != 68 || blob[..4] != self.id {
                continue;
            }
            let sig = ed25519_dalek::Signature::from_bytes(blob[4..].try_into().unwrap());
            if self.key.verify(text.as_bytes(), &sig).is_ok() {
                return Ok(text);
            }
            return Err("the signature does not verify".into());
        }
        Err("no signature by this key".into())
    }
}

/// The text of a checkpoint (SPEC §4).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Checkpoint {
    pub origin: String,
    pub size: u64,
    pub root: Hash,
    pub index: u64,
    pub time: u64,
    /// Registry id, tree size, tree root.
    pub registries: Vec<(u32, u64, Fr)>,
    /// Poll id, ballot tree size, root (delta polls).
    pub ballots: Vec<(u32, u64, Fr)>,
    pub mirror: Option<String>,
}

impl Checkpoint {
    /// The `mirror` token: a commit and the newest checkpoint it covers
    /// (`<commit>:<index>`), or, in notes of earlier versions, the commit
    /// of this checkpoint's own data (no index).
    pub fn mirror_commit(&self) -> Option<(&str, Option<u64>)> {
        let m = self.mirror.as_deref()?;
        Some(match m.split_once(':') {
            Some((c, i)) => (c, i.parse().ok()),
            None => (m, None),
        })
    }

    pub fn text(&self) -> String {
        let mut s = format!("{}\n{}\n{}\nindex {}\ntime {}\n", self.origin, self.size, STANDARD.encode(self.root), self.index, self.time);
        for (id, n, r) in &self.registries {
            s.push_str(&format!("registry {id} {n} {}\n", field::to_hex(r)));
        }
        for (id, n, r) in &self.ballots {
            s.push_str(&format!("ballots {id} {n} {}\n", field::to_hex(r)));
        }
        if let Some(m) = &self.mirror {
            s.push_str(&format!("mirror {m}\n"));
        }
        s
    }

    pub fn parse(text: &str) -> Result<Checkpoint, String> {
        let mut lines = text.lines();
        let origin = lines.next().ok_or("no origin")?.to_string();
        let size = lines.next().and_then(|l| l.parse().ok()).ok_or("no size")?;
        let root: Hash = lines
            .next()
            .and_then(|l| STANDARD.decode(l).ok())
            .and_then(|b| b.try_into().ok())
            .ok_or("no root")?;
        let mut c = Checkpoint { origin, size, root, index: 0, time: 0, registries: vec![], ballots: vec![], mirror: None };
        let (mut has_index, mut has_time) = (false, false);
        for l in lines {
            let f: Vec<&str> = l.split(' ').collect();
            match f.as_slice() {
                ["index", n] => {
                    c.index = n.parse().map_err(|_| "index")?;
                    has_index = true;
                }
                ["time", t] => {
                    c.time = t.parse().map_err(|_| "time")?;
                    has_time = true;
                }
                ["registry", id, n, r] => c.registries.push((
                    id.parse().map_err(|_| "registry id")?,
                    n.parse().map_err(|_| "registry size")?,
                    field::from_hex(r).map_err(|e| e.to_string())?,
                )),
                ["ballots", id, n, r] => c.ballots.push((
                    id.parse().map_err(|_| "poll id")?,
                    n.parse().map_err(|_| "ballot tree size")?,
                    field::from_hex(r).map_err(|e| e.to_string())?,
                )),
                ["mirror", m] => c.mirror = Some(m.to_string()),
                _ => return Err(format!("unknown line: {l}")),
            }
        }
        if !has_index || !has_time {
            return Err("no index or time".into());
        }
        if c.text() != text {
            return Err("not in canonical form".into());
        }
        Ok(c)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sign_open_and_parse() {
        let s = Signer::new("example.org/isoloir", &[7u8; 32]);
        let v = Verifier::parse(&s.verifier()).unwrap();
        let c = Checkpoint {
            origin: "example.org/isoloir".into(),
            size: 12,
            root: [3u8; 32],
            index: 2,
            time: 1_761_900_000,
            registries: vec![(1, 5, Fr::from(9u64))],
            ballots: vec![(7, 2, Fr::from(11u64))],
            mirror: Some("abc123".into()),
        };
        let note = s.sign(&c.text());
        let text = v.open(&note).unwrap();
        assert_eq!(Checkpoint::parse(text).unwrap(), c);
        let forged = note.replacen("\n12\n", "\n13\n", 1);
        assert!(v.open(&forged).is_err());
        // The C2SP private key form names the same key.
        let pk = s.key.verifying_key().to_bytes();
        let mut kd = vec![ALG_ED25519];
        kd.extend_from_slice(&s.key.to_bytes());
        let private = format!("PRIVATE+KEY+example.org/isoloir+{}+{}", hex::encode(key_id("example.org/isoloir", &pk)), STANDARD.encode(kd));
        assert_eq!(Signer::from_private(&private).unwrap().verifier(), s.verifier());
        // Key data with '+' in its base64.
        let t = (0u8..=255).map(|b| Signer::new("example.org/isoloir", &[b; 32])).find(|t| {
            let mut kd = vec![ALG_ED25519];
            kd.extend_from_slice(&t.seed());
            STANDARD.encode(kd).contains('+')
        });
        if let Some(t) = t {
            let pk = t.key.verifying_key().to_bytes();
            let mut kd = vec![ALG_ED25519];
            kd.extend_from_slice(&t.seed());
            let p = format!("PRIVATE+KEY+example.org/isoloir+{}+{}", hex::encode(key_id("example.org/isoloir", &pk)), STANDARD.encode(kd));
            assert_eq!(Signer::from_private(&p).unwrap().verifier(), t.verifier());
        }
        assert!(Signer::from_private(&private.replacen("example.org", "example.com", 1)).is_err());
        let other = Signer::new("example.org/isoloir", &[8u8; 32]);
        assert!(Verifier::parse(&other.verifier()).unwrap().open(&note).is_err());
    }
}
