//! The OpenTimestamps proof format, as the reference (Python) client writes
//! it: a header, the SHA-256 digest of the stamped data, then a tree of
//! operations whose leaves are attestations. Each node holds the message the
//! operations gave at that point (the commitment); a Bitcoin attestation
//! says that this message is the Merkle root of a block, a pending one names
//! the calendar that will serve the rest of the path once Bitcoin confirms.

use sha1::Sha1;
use sha2::{Digest, Sha256};
use sha3::Keccak256;

use crate::error::{Error, Result};

/// The magic bytes that start every detached timestamp file.
pub const MAGIC: &[u8] = b"\x00OpenTimestamps\x00\x00Proof\x00\xbf\x89\xe2\xe8\x84\xe8\x92\x94";
/// The major version of the format.
pub const VERSION: u64 = 1;

const TAG_ATTESTATION: u8 = 0x00;
const TAG_FORK: u8 = 0xff;
const OP_SHA1: u8 = 0x02;
const OP_RIPEMD160: u8 = 0x03;
const OP_SHA256: u8 = 0x08;
const OP_KECCAK256: u8 = 0x67;
const OP_APPEND: u8 = 0xf0;
const OP_PREPEND: u8 = 0xf1;
const OP_REVERSE: u8 = 0xf2;
const OP_HEXLIFY: u8 = 0xf3;

const ATT_BITCOIN: [u8; 8] = [0x05, 0x88, 0x96, 0x0d, 0x73, 0xd7, 0x19, 0x01];
const ATT_PENDING: [u8; 8] = [0x83, 0xdf, 0xe3, 0x0d, 0x2e, 0xf9, 0x0c, 0x8e];

/// Limits of the reference client.
const MAX_MSG_LENGTH: usize = 4096;
const MAX_PAYLOAD_LENGTH: usize = 8192;
const MAX_URI_LENGTH: usize = 1000;
const MAX_DEPTH: usize = 256;

/// An operation of the tree.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Op {
    Sha1,
    Ripemd160,
    Sha256,
    Keccak256,
    Append(Vec<u8>),
    Prepend(Vec<u8>),
    Reverse,
    Hexlify,
}

impl Op {
    fn tag(&self) -> u8 {
        match self {
            Op::Sha1 => OP_SHA1,
            Op::Ripemd160 => OP_RIPEMD160,
            Op::Sha256 => OP_SHA256,
            Op::Keccak256 => OP_KECCAK256,
            Op::Append(_) => OP_APPEND,
            Op::Prepend(_) => OP_PREPEND,
            Op::Reverse => OP_REVERSE,
            Op::Hexlify => OP_HEXLIFY,
        }
    }

    /// Evaluates the operation on a message.
    pub fn apply(&self, msg: &[u8]) -> Result<Vec<u8>> {
        let out = match self {
            Op::Sha1 => Sha1::digest(msg).to_vec(),
            Op::Ripemd160 => ripemd::Ripemd160::digest(msg).to_vec(),
            Op::Sha256 => Sha256::digest(msg).to_vec(),
            Op::Keccak256 => Keccak256::digest(msg).to_vec(),
            Op::Append(arg) => [msg, arg].concat(),
            Op::Prepend(arg) => [arg.as_slice(), msg].concat(),
            Op::Reverse => msg.iter().rev().copied().collect(),
            Op::Hexlify => hex::encode(msg).into_bytes(),
        };
        if out.len() > MAX_MSG_LENGTH {
            return Err(Error::Malformed(format!(
                "an operation gives {} bytes, at most {MAX_MSG_LENGTH} are allowed",
                out.len()
            )));
        }
        Ok(out)
    }
}

/// An attestation: a leaf of the tree.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Attestation {
    /// The calendar at `uri` will serve the rest of the path.
    Pending { uri: String },
    /// The commitment is the Merkle root of the Bitcoin block at `height`.
    Bitcoin { height: u64 },
    /// An attestation this crate does not know, kept as it is.
    Unknown { tag: [u8; 8], payload: Vec<u8> },
}

impl Attestation {
    fn decode(tag: [u8; 8], payload: Vec<u8>) -> Result<Attestation> {
        match tag {
            ATT_BITCOIN => {
                let mut r = Reader::new(&payload);
                let height = r.varuint()?;
                r.end()?;
                Ok(Attestation::Bitcoin { height })
            }
            ATT_PENDING => {
                let mut r = Reader::new(&payload);
                let uri = r.varbytes(MAX_URI_LENGTH)?;
                r.end()?;
                let uri = String::from_utf8(uri)
                    .map_err(|_| Error::Malformed("a calendar URI that is not UTF-8".into()))?;
                validate_uri(&uri)?;
                Ok(Attestation::Pending { uri })
            }
            _ => Ok(Attestation::Unknown { tag, payload }),
        }
    }

    fn encode(&self, w: &mut Vec<u8>) {
        let (tag, payload) = match self {
            Attestation::Bitcoin { height } => {
                let mut p = Vec::new();
                write_varuint(&mut p, *height);
                (ATT_BITCOIN, p)
            }
            Attestation::Pending { uri } => {
                let mut p = Vec::new();
                write_varbytes(&mut p, uri.as_bytes());
                (ATT_PENDING, p)
            }
            Attestation::Unknown { tag, payload } => (*tag, payload.clone()),
        };
        w.push(TAG_ATTESTATION);
        w.extend_from_slice(&tag);
        write_varbytes(w, &payload);
    }
}

/// The reference client's rule for calendar URIs (they are fetched).
fn validate_uri(uri: &str) -> Result<()> {
    let ok = uri
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || b"-._/:".contains(&b));
    if !ok {
        return Err(Error::Malformed(format!("invalid calendar URI {uri:?}")));
    }
    Ok(())
}

/// An item of a node: an attestation, or an operation leading to a child.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Item {
    Attestation(Attestation),
    Op(Op, Timestamp),
}

/// A node of the tree: the message at that point and its items, in the
/// order of the file (so that a proof re-serializes byte for byte).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Timestamp {
    pub(crate) msg: Vec<u8>,
    pub(crate) items: Vec<Item>,
}

impl Timestamp {
    /// The message (commitment) at this node.
    pub fn msg(&self) -> &[u8] {
        &self.msg
    }

    /// The items of this node.
    pub fn items(&self) -> &[Item] {
        &self.items
    }

    /// Reads a timestamp whose message is `msg` (the body of a calendar
    /// answer, or a node of a file).
    pub fn parse(bytes: &[u8], msg: &[u8]) -> Result<Timestamp> {
        let mut r = Reader::new(bytes);
        let t = Timestamp::read(&mut r, msg.to_vec(), 0)?;
        r.end()?;
        Ok(t)
    }

    fn read(r: &mut Reader, msg: Vec<u8>, depth: usize) -> Result<Timestamp> {
        if depth > MAX_DEPTH {
            return Err(Error::Malformed("the tree is too deep".into()));
        }
        let mut t = Timestamp {
            msg,
            items: Vec::new(),
        };
        loop {
            let tag = r.byte()?;
            if tag == TAG_FORK {
                let tag = r.byte()?;
                let item = t.read_item(r, tag, depth)?;
                t.items.push(item);
            } else {
                let item = t.read_item(r, tag, depth)?;
                t.items.push(item);
                return Ok(t);
            }
        }
    }

    fn read_item(&self, r: &mut Reader, tag: u8, depth: usize) -> Result<Item> {
        let op = match tag {
            TAG_ATTESTATION => {
                let att_tag: [u8; 8] = r.take(8)?.try_into().expect("8 bytes");
                let payload = r.varbytes(MAX_PAYLOAD_LENGTH)?;
                return Ok(Item::Attestation(Attestation::decode(att_tag, payload)?));
            }
            OP_SHA1 => Op::Sha1,
            OP_RIPEMD160 => Op::Ripemd160,
            OP_SHA256 => Op::Sha256,
            OP_KECCAK256 => Op::Keccak256,
            OP_APPEND => Op::Append(r.varbytes(MAX_MSG_LENGTH)?),
            OP_PREPEND => Op::Prepend(r.varbytes(MAX_MSG_LENGTH)?),
            OP_REVERSE => Op::Reverse,
            OP_HEXLIFY => Op::Hexlify,
            other => return Err(Error::Malformed(format!("unknown operation 0x{other:02x}"))),
        };
        let next = op.apply(&self.msg)?;
        let child = Timestamp::read(r, next, depth + 1)?;
        Ok(Item::Op(op, child))
    }

    fn write(&self, w: &mut Vec<u8>) {
        let n = self.items.len();
        for (i, item) in self.items.iter().enumerate() {
            if i + 1 < n {
                w.push(TAG_FORK);
            }
            match item {
                Item::Attestation(a) => a.encode(w),
                Item::Op(op, child) => {
                    w.push(op.tag());
                    if let Op::Append(arg) | Op::Prepend(arg) = op {
                        write_varbytes(w, arg);
                    }
                    child.write(w);
                }
            }
        }
    }

    /// Serializes the node (without the file header).
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut w = Vec::new();
        self.write(&mut w);
        w
    }

    /// Merges another timestamp of the same message into this one: an
    /// operation already here takes the other's subtree into its own, an
    /// attestation already here is not repeated.
    pub(crate) fn merge(&mut self, other: Timestamp) {
        debug_assert_eq!(self.msg, other.msg);
        for item in other.items {
            match item {
                Item::Attestation(a) => {
                    if !self
                        .items
                        .iter()
                        .any(|i| matches!(i, Item::Attestation(b) if *b == a))
                    {
                        self.items.push(Item::Attestation(a));
                    }
                }
                Item::Op(op, child) => {
                    let existing = self.items.iter_mut().find_map(|i| match i {
                        Item::Op(o, c) if *o == op => Some(c),
                        _ => None,
                    });
                    match existing {
                        Some(c) => c.merge(child),
                        None => self.items.push(Item::Op(op, child)),
                    }
                }
            }
        }
    }

    pub(crate) fn walk<'a>(&'a self, out: &mut Vec<AttestationAt<'a>>) {
        for item in &self.items {
            match item {
                Item::Attestation(a) => out.push(AttestationAt {
                    attestation: a,
                    commitment: &self.msg,
                }),
                Item::Op(_, child) => child.walk(out),
            }
        }
    }
}

/// An attestation and the commitment (message) it attests.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AttestationAt<'a> {
    pub attestation: &'a Attestation,
    pub commitment: &'a [u8],
}

/// A detached timestamp file of a SHA-256 digest.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ots {
    pub(crate) digest: [u8; 32],
    pub(crate) root: Timestamp,
}

impl Ots {
    /// The digest the proof is of.
    pub fn digest(&self) -> [u8; 32] {
        self.digest
    }

    /// The root of the tree (its message is the digest).
    pub fn timestamp(&self) -> &Timestamp {
        &self.root
    }

    /// Reads a .ots file.
    pub fn parse(file: &[u8]) -> Result<Ots> {
        let rest = file.strip_prefix(MAGIC).ok_or(Error::BadMagic)?;
        let mut r = Reader::new(rest);
        let version = r.varuint()?;
        if version != VERSION {
            return Err(Error::UnsupportedVersion(version));
        }
        let hash_op = r.byte()?;
        if hash_op != OP_SHA256 {
            return Err(Error::UnsupportedFileHash(hash_op));
        }
        let digest: [u8; 32] = r.take(32)?.try_into().expect("32 bytes");
        let root = Timestamp::read(&mut r, digest.to_vec(), 0)?;
        r.end()?;
        Ok(Ots { digest, root })
    }

    /// Serializes the proof as a .ots file.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut w = MAGIC.to_vec();
        write_varuint(&mut w, VERSION);
        w.push(OP_SHA256);
        w.extend_from_slice(&self.digest);
        self.root.write(&mut w);
        w
    }

    /// Every attestation of the proof, with the commitment it attests, in
    /// the order of the file.
    pub fn attestations(&self) -> Vec<AttestationAt<'_>> {
        let mut out = Vec::new();
        self.root.walk(&mut out);
        out
    }

    /// Whether the proof carries at least one Bitcoin attestation.
    pub fn is_complete(&self) -> bool {
        self.attestations()
            .iter()
            .any(|a| matches!(a.attestation, Attestation::Bitcoin { .. }))
    }
}

/// Every attestation of `ots` with the commitment it attests.
pub fn attestations(ots: &Ots) -> Vec<AttestationAt<'_>> {
    ots.attestations()
}

/// Whether `ots` carries at least one Bitcoin attestation.
pub fn is_complete(ots: &Ots) -> bool {
    ots.is_complete()
}

pub(crate) struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    pub(crate) fn new(buf: &'a [u8]) -> Self {
        Reader { buf, pos: 0 }
    }

    fn byte(&mut self) -> Result<u8> {
        let b = *self.buf.get(self.pos).ok_or(Error::Truncated)?;
        self.pos += 1;
        Ok(b)
    }

    fn take(&mut self, n: usize) -> Result<&'a [u8]> {
        if self.buf.len() - self.pos < n {
            return Err(Error::Truncated);
        }
        let s = &self.buf[self.pos..self.pos + n];
        self.pos += n;
        Ok(s)
    }

    /// An unsigned LEB128 integer, in its shortest form (so that it
    /// re-serializes as read).
    fn varuint(&mut self) -> Result<u64> {
        let mut v: u64 = 0;
        let mut shift = 0u32;
        loop {
            let b = self.byte()?;
            let low = u64::from(b & 0x7f);
            if shift == 63 && low > 1 || shift > 63 {
                return Err(Error::Malformed("a varint over 64 bits".into()));
            }
            v |= low << shift;
            if b & 0x80 == 0 {
                if b == 0 && shift > 0 {
                    return Err(Error::Malformed("a varint not in its shortest form".into()));
                }
                return Ok(v);
            }
            shift += 7;
        }
    }

    fn varbytes(&mut self, max: usize) -> Result<Vec<u8>> {
        let n = self.varuint()?;
        if n > max as u64 {
            return Err(Error::Malformed(format!(
                "{n} bytes where at most {max} are allowed"
            )));
        }
        Ok(self.take(n as usize)?.to_vec())
    }

    fn end(&self) -> Result<()> {
        match self.buf.len() - self.pos {
            0 => Ok(()),
            n => Err(Error::TrailingBytes(n)),
        }
    }
}

pub(crate) fn write_varuint(w: &mut Vec<u8>, mut v: u64) {
    while v >= 0x80 {
        w.push((v as u8) | 0x80);
        v >>= 7;
    }
    w.push(v as u8);
}

pub(crate) fn write_varbytes(w: &mut Vec<u8>, b: &[u8]) {
    write_varuint(w, b.len() as u64);
    w.extend_from_slice(b);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn varuint_round_trip_and_shortest_form() {
        for v in [0u64, 1, 127, 128, 300, 358391, u32::MAX as u64, u64::MAX] {
            let mut w = Vec::new();
            write_varuint(&mut w, v);
            let mut r = Reader::new(&w);
            assert_eq!(r.varuint().unwrap(), v);
            r.end().unwrap();
        }
        assert!(Reader::new(&[0x80, 0x00]).varuint().is_err());
        assert!(Reader::new(&[0xff; 11]).varuint().is_err());
    }

    #[test]
    fn ops_evaluate() {
        assert_eq!(Op::Append(b"cd".to_vec()).apply(b"ab").unwrap(), b"abcd");
        assert_eq!(Op::Prepend(b"cd".to_vec()).apply(b"ab").unwrap(), b"cdab");
        assert_eq!(Op::Reverse.apply(b"ab").unwrap(), b"ba");
        assert_eq!(Op::Hexlify.apply(&[0xab, 0x01]).unwrap(), b"ab01");
        assert_eq!(
            hex::encode(Op::Sha256.apply(b"").unwrap()),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        assert_eq!(
            hex::encode(Op::Keccak256.apply(b"").unwrap()),
            "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470"
        );
        assert_eq!(
            hex::encode(Op::Ripemd160.apply(b"").unwrap()),
            "9c1185a5c5e9fc54612808977ee8f548b2258d31"
        );
        assert_eq!(
            hex::encode(Op::Sha1.apply(b"").unwrap()),
            "da39a3ee5e6b4b0d3255bfef95601890afd80709"
        );
        assert!(Op::Append(vec![0; 4096]).apply(b"x").is_err());
    }
}
