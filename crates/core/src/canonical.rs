//! Canonical JSON (SPEC §3): keys sorted bytewise, no insignificant
//! whitespace, integers only. A body is accepted only in its canonical
//! form, so its bytes, its hash and its signatures are unique.

use crate::{Error, Result};
use serde::Serialize;
use serde_json::Value;

/// The canonical bytes of a value.
pub fn to_vec<T: Serialize>(v: &T) -> Result<Vec<u8>> {
    let value = serde_json::to_value(v).map_err(|e| Error::Encoding(e.to_string()))?;
    check_numbers(&value)?;
    // serde_json's Map is a BTreeMap (no preserve_order feature), so the
    // keys come out sorted bytewise.
    serde_json::to_vec(&value).map_err(|e| Error::Encoding(e.to_string()))
}

/// The canonical text of a value.
pub fn to_string<T: Serialize>(v: &T) -> Result<String> {
    Ok(String::from_utf8(to_vec(v)?).expect("JSON is UTF-8"))
}

/// Parses bytes that must be canonical JSON.
pub fn parse(bytes: &[u8]) -> Result<Value> {
    let value: Value = serde_json::from_slice(bytes).map_err(|e| Error::Encoding(e.to_string()))?;
    check_numbers(&value)?;
    if serde_json::to_vec(&value).map_err(|e| Error::Encoding(e.to_string()))? != bytes {
        return Err(Error::NotCanonical);
    }
    Ok(value)
}

/// Parses canonical bytes into a type.
pub fn from_slice<T: serde::de::DeserializeOwned>(bytes: &[u8]) -> Result<T> {
    let value = parse(bytes)?;
    serde_json::from_value(value).map_err(|e| Error::Encoding(e.to_string()))
}

fn check_numbers(v: &Value) -> Result<()> {
    match v {
        Value::Number(n) if n.is_f64() => Err(Error::Encoding(format!("{n}: not an integer"))),
        Value::Array(a) => a.iter().try_for_each(check_numbers),
        Value::Object(o) => o.values().try_for_each(check_numbers),
        _ => Ok(()),
    }
}

/// The canonical bytes of an object without one of its keys (what a
/// signature inside a body covers).
pub fn without(bytes: &[u8], key: &str) -> Result<Vec<u8>> {
    let mut value: Value = serde_json::from_slice(bytes).map_err(|e| Error::Encoding(e.to_string()))?;
    value.as_object_mut().ok_or_else(|| Error::Encoding("not an object".into()))?.remove(key);
    serde_json::to_vec(&value).map_err(|e| Error::Encoding(e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn sorted_and_compact() {
        let s = to_string(&json!({"b": 1, "a": [true, null, "x<y"], "c": {"z": -2, "y": "é"}})).unwrap();
        assert_eq!(s, r#"{"a":[true,null,"x<y"],"b":1,"c":{"y":"é","z":-2}}"#);
        assert!(parse(s.as_bytes()).is_ok());
    }

    #[test]
    fn refuses_other_spellings() {
        assert_eq!(parse(br#"{"b":1,"a":2}"#), Err(Error::NotCanonical));
        assert_eq!(parse(br#"{"a": 2}"#), Err(Error::NotCanonical));
        assert!(parse(br#"{"a":2.5}"#).is_err());
        assert!(parse(b"{\"a\":\"\\u0041\"}").is_err());
    }

    #[test]
    fn without_a_key() {
        assert_eq!(without(br#"{"a":1,"sig":"x","z":2}"#, "sig").unwrap(), br#"{"a":1,"z":2}"#);
    }
}
