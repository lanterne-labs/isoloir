//! The domain tags (SPEC §3): `T_name` is the ASCII string
//! `isoloir/<name>` read as a big-endian integer, a field element.

use crate::field::{Fr, from_bytes_mod};

/// The tag of a name (at most 23 bytes, so the string fits 31 bytes).
pub fn tag(name: &str) -> Fr {
    let s = format!("isoloir/{name}");
    assert!(s.len() <= 31, "tag too long: {s}");
    from_bytes_mod(s.as_bytes())
}

macro_rules! tags {
    ($($fn:ident => $name:literal),* $(,)?) => {
        $(
            #[doc = concat!("`T_", $name, "`.")]
            pub fn $fn() -> Fr {
                static T: std::sync::OnceLock<Fr> = std::sync::OnceLock::new();
                *T.get_or_init(|| tag($name))
            }
        )*
        /// Every tag, by name, for the circuits' constants file.
        pub fn all() -> Vec<(&'static str, Fr)> {
            vec![$(($name, $fn())),*]
        }
    };
}

tags! {
    id => "id",
    null => "null",
    node => "node",
    reg => "reg",
    prf => "prf",
    relay => "relay",
    bnull => "bnull",
    bleaf => "bleaf",
    salt => "salt",
    cmt => "cmt",
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_ff::{BigInteger, PrimeField};

    #[test]
    fn a_tag_is_its_ascii() {
        let b = id().into_bigint().to_bytes_be();
        let s: Vec<u8> = b.into_iter().skip_while(|c| *c == 0).collect();
        assert_eq!(s, b"isoloir/id");
    }
}
