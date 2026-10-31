//! The 12 words (SPEC §14): BIP39 over 128 bits of entropy, and the voter
//! secret `SHA-256("isoloir/1/words" ‖ entropy) mod r` (nonzero).

use crate::api::{self, R};
use bip39::{Language, Mnemonic};
use rand_core::{OsRng, RngCore};

fn language(name: &str) -> R<Language> {
    match name {
        "" | "en" | "english" => Ok(Language::English),
        "fr" | "french" => Ok(Language::French),
        _ => Err(format!("word list {name}: english or french")),
    }
}

/// Twelve fresh words.
pub fn new_words(lang: &str) -> R<String> {
    let mut e = [0u8; 16];
    OsRng.fill_bytes(&mut e);
    words_of_entropy(&e, lang)
}

pub fn words_of_entropy(entropy: &[u8], lang: &str) -> R<String> {
    Mnemonic::from_entropy_in(language(lang)?, entropy).map(|m| m.to_string()).map_err(api::err)
}

fn mnemonic(words: &str, lang: &str) -> R<Mnemonic> {
    let norm = words.split_whitespace().map(str::to_lowercase).collect::<Vec<_>>().join(" ");
    let m = Mnemonic::parse_in(language(lang)?, norm).map_err(|e| format!("words: {e}"))?;
    if m.word_count() != 12 {
        return Err("words: twelve of them".into());
    }
    Ok(m)
}

/// The words in their one spelling (lower case, single spaces), or why
/// they are not twelve words of the list with a valid checksum.
pub fn normalize_words(words: &str, lang: &str) -> R<String> {
    Ok(mnemonic(words, lang)?.to_string())
}

/// The voter secret of twelve words.
pub fn secret_from_words(words: &str, lang: &str) -> R<String> {
    api::secret_from_entropy(&mnemonic(words, lang)?.to_entropy())
}
