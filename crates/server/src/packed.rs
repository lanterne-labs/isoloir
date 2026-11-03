//! A compact storage form of canonical JSON bodies (the store's columns,
//! never the log, the mirror or the wire). Ballots are mostly a proof in
//! base64 and points in hex: as bytes they take a quarter to a half less,
//! which neither pglz nor lz4 gets from them (base64 and hex of random
//! bytes do not compress).
//!
//! The form is `0x00 ‖ the bytes as they are`, or `0x01 ‖ the JSON value`
//! with its hex and base64 strings as bytes. A body is packed only when
//! unpacking gives its bytes back exactly (checked as it is packed), so
//! the log's hashes never depend on this code: anything else (junk, a
//! body that is not canonical) is kept as it is.

use serde_json::{Map, Number, Value};

const RAW: u8 = 0;
const PACKED: u8 = 1;

const NULL: u8 = 0;
const FALSE: u8 = 1;
const TRUE: u8 = 2;
const UINT: u8 = 3;
const NEG: u8 = 4;
const TEXT: u8 = 5;
/// `0x` and lower-case hex digits, an even number.
const HEX0X: u8 = 6;
/// Lower-case hex digits, an even number, at least 32.
const HEX: u8 = 7;
/// Standard base64 with padding, in its one spelling, at least 24 chars.
const B64: u8 = 8;
const ARRAY: u8 = 9;
const OBJECT: u8 = 10;

/// The storage form of a body.
pub fn pack(bytes: &[u8]) -> Vec<u8> {
    if let Some(p) = try_pack(bytes) {
        if unpack(&p).as_deref().ok() == Some(bytes) {
            return p;
        }
    }
    let mut out = Vec::with_capacity(bytes.len() + 1);
    out.push(RAW);
    out.extend_from_slice(bytes);
    out
}

fn try_pack(bytes: &[u8]) -> Option<Vec<u8>> {
    let v: Value = serde_json::from_slice(bytes).ok()?;
    if serde_json::to_vec(&v).ok()? != bytes {
        return None;
    }
    let mut out = vec![PACKED];
    value(&v, &mut out)?;
    Some(out)
}

/// The body of a storage form.
pub fn unpack(stored: &[u8]) -> anyhow::Result<Vec<u8>> {
    match stored.first() {
        Some(&RAW) => Ok(stored[1..].to_vec()),
        Some(&PACKED) => {
            let mut r = Reader { b: &stored[1..], i: 0 };
            let v = r.value(0)?;
            if r.i != r.b.len() {
                anyhow::bail!("packed body: trailing bytes");
            }
            Ok(serde_json::to_vec(&v)?)
        }
        _ => anyhow::bail!("packed body: unknown form"),
    }
}

fn varint(mut n: u64, out: &mut Vec<u8>) {
    while n >= 0x80 {
        out.push((n as u8) | 0x80);
        n >>= 7;
    }
    out.push(n as u8);
}

fn bytes(tag: u8, b: &[u8], out: &mut Vec<u8>) {
    out.push(tag);
    varint(b.len() as u64, out);
    out.extend_from_slice(b);
}

fn lower_hex(s: &str) -> Option<Vec<u8>> {
    if s.len() % 2 != 0 || !s.bytes().all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c)) {
        return None;
    }
    hex::decode(s).ok()
}

fn string(s: &str, out: &mut Vec<u8>) {
    if let Some(h) = s.strip_prefix("0x").filter(|h| !h.is_empty()).and_then(lower_hex) {
        return bytes(HEX0X, &h, out);
    }
    if s.len() >= 32 {
        if let Some(h) = lower_hex(s) {
            return bytes(HEX, &h, out);
        }
    }
    if s.len() >= 24 {
        if let Ok(b) = isoloir_core::encoding::unb64(s) {
            return bytes(B64, &b, out);
        }
    }
    bytes(TEXT, s.as_bytes(), out)
}

fn value(v: &Value, out: &mut Vec<u8>) -> Option<()> {
    match v {
        Value::Null => out.push(NULL),
        Value::Bool(false) => out.push(FALSE),
        Value::Bool(true) => out.push(TRUE),
        Value::Number(n) => {
            if let Some(u) = n.as_u64() {
                out.push(UINT);
                varint(u, out);
            } else {
                let i = n.as_i64()?;
                out.push(NEG);
                varint(!(i as u64), out);
            }
        }
        Value::String(s) => string(s, out),
        Value::Array(a) => {
            out.push(ARRAY);
            varint(a.len() as u64, out);
            for x in a {
                value(x, out)?;
            }
        }
        Value::Object(m) => {
            out.push(OBJECT);
            varint(m.len() as u64, out);
            for (k, x) in m {
                varint(k.len() as u64, out);
                out.extend_from_slice(k.as_bytes());
                value(x, out)?;
            }
        }
    }
    Some(())
}

struct Reader<'a> {
    b: &'a [u8],
    i: usize,
}

impl Reader<'_> {
    fn byte(&mut self) -> anyhow::Result<u8> {
        let c = *self.b.get(self.i).ok_or_else(|| anyhow::anyhow!("packed body: truncated"))?;
        self.i += 1;
        Ok(c)
    }

    fn varint(&mut self) -> anyhow::Result<u64> {
        let mut n = 0u64;
        for shift in (0..64).step_by(7) {
            let c = self.byte()?;
            n |= ((c & 0x7f) as u64) << shift;
            if c & 0x80 == 0 {
                return Ok(n);
            }
        }
        anyhow::bail!("packed body: varint too long")
    }

    fn take(&mut self) -> anyhow::Result<&[u8]> {
        let n = self.varint()? as usize;
        let end = self.i.checked_add(n).filter(|e| *e <= self.b.len()).ok_or_else(|| anyhow::anyhow!("packed body: truncated"))?;
        let s = &self.b[self.i..end];
        self.i = end;
        Ok(s)
    }

    fn value(&mut self, depth: usize) -> anyhow::Result<Value> {
        if depth > 64 {
            anyhow::bail!("packed body: too deep");
        }
        Ok(match self.byte()? {
            NULL => Value::Null,
            FALSE => Value::Bool(false),
            TRUE => Value::Bool(true),
            UINT => Value::Number(self.varint()?.into()),
            NEG => Value::Number(Number::from(!self.varint()? as i64)),
            TEXT => Value::String(String::from_utf8(self.take()?.to_vec())?),
            HEX0X => Value::String(format!("0x{}", hex::encode(self.take()?))),
            HEX => Value::String(hex::encode(self.take()?)),
            B64 => Value::String(isoloir_core::encoding::b64(self.take()?)),
            ARRAY => {
                let n = self.varint()?;
                let mut a = Vec::new();
                for _ in 0..n {
                    a.push(self.value(depth + 1)?);
                }
                Value::Array(a)
            }
            OBJECT => {
                let n = self.varint()?;
                let mut m = Map::new();
                for _ in 0..n {
                    let k = String::from_utf8(self.take()?.to_vec())?;
                    let x = self.value(depth + 1)?;
                    m.insert(k, x);
                }
                Value::Object(m)
            }
            t => anyhow::bail!("packed body: unknown tag {t}"),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cases_first() -> String {
        format!(r#"{{"ct":[["0x{0}","0x{0}"]],"id":"{0}","n":-3}}"#, "ab".repeat(32))
    }

    #[test]
    fn round_trips() {
        let proof = isoloir_core::encoding::b64(&[7u8; 300]);
        let cases: Vec<Vec<u8>> = vec![
            format!(r#"{{"ct":[["0x{0}","0x{0}"]],"id":"{0}","n":-3,"ok":true,"proof":"{proof}","s":"Édouard \"x\"","v":1,"x":null,"z":0}}"#, "ab".repeat(32)).into_bytes(),
            br#"{"a":"0xABCD","b":"0x","c":"abc","d":"0x0","e":"QUJD"}"#.to_vec(),
            b"junk".to_vec(),
            vec![0, 1, 2, 0xff],
            b"{ \"v\": 1 }".to_vec(),
            br#"{"f":1.5}"#.to_vec(),
            br#"{"b":1,"a":2}"#.to_vec(),
            Vec::new(),
        ];
        for c in cases {
            assert_eq!(unpack(&pack(&c)).unwrap(), c, "{}", String::from_utf8_lossy(&c));
        }
        // Keys come back sorted, so an unsorted object is kept as it is.
        assert_eq!(pack(br#"{"b":1,"a":2}"#)[0], RAW);
        assert_eq!(pack(cases_first().as_bytes())[0], PACKED);
        let p = pack(format!(r#"{{"proof":"{proof}"}}"#).as_bytes());
        assert_eq!(p[0], PACKED);
        assert!(p.len() < 320);
    }
}
