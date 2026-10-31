//! The 12 words (SPEC §14): BIP39 over 128 bits of entropy, and the voter
//! secret `SHA-256("isoloir/1/words" ‖ entropy) mod r` (nonzero). Words
//! are read in any case, with or without their accents (the French list
//! stays unique without them), and refusals name the 1-based positions
//! of the words that are not on the list.

use crate::api::{self, R};
use bip39::{Language, Mnemonic};
use rand_core::{OsRng, RngCore};
use serde_json::json;
use std::collections::HashMap;

fn language(name: &str) -> R<Language> {
    match name {
        "" | "en" | "english" => Ok(Language::English),
        "fr" | "french" => Ok(Language::French),
        _ => Err(format!("word list {name}: english or french")),
    }
}

/// A word without case or accents: precomposed Latin letters folded, the
/// combining marks of a decomposed spelling dropped.
pub fn fold(w: &str) -> String {
    let mut out = String::with_capacity(w.len());
    for c in w.chars().flat_map(char::to_lowercase) {
        if ('\u{0300}'..='\u{036f}').contains(&c) {
            continue;
        }
        out.push(match c {
            'à' | 'á' | 'â' | 'ä' | 'ã' | 'å' => 'a',
            'ç' => 'c',
            'é' | 'è' | 'ê' | 'ë' => 'e',
            'í' | 'ì' | 'î' | 'ï' => 'i',
            'ñ' => 'n',
            'ó' | 'ò' | 'ô' | 'ö' | 'õ' => 'o',
            'ú' | 'ù' | 'û' | 'ü' => 'u',
            'ý' | 'ÿ' => 'y',
            c => c,
        });
    }
    out
}

fn folded_list(lang: Language) -> HashMap<String, &'static str> {
    lang.word_list().iter().map(|w| (fold(w), *w)).collect()
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

/// Each given word in the list's spelling, or the 1-based positions of
/// those not on the list.
fn canonical(words: &str, l: Language) -> (Vec<&'static str>, Vec<usize>, usize) {
    let list = folded_list(l);
    let given: Vec<&str> = words.split_whitespace().collect();
    let mut canon = vec![];
    let mut unknown = vec![];
    for (i, w) in given.iter().enumerate() {
        match list.get(&fold(w)) {
            Some(c) => canon.push(*c),
            None => unknown.push(i + 1),
        }
    }
    (canon, unknown, given.len())
}

/// What is wrong with a phrase: `{ok, count, unknown, checksum, words}`,
/// `unknown` the 1-based positions of the words not on the list, `words`
/// the phrase in the list's spelling when every word is on it.
pub fn check_words(words: &str, lang: &str) -> R<String> {
    let l = language(lang)?;
    let (canon, unknown, count) = canonical(words, l);
    let phrase = canon.join(" ");
    let checksum = unknown.is_empty() && count == 12 && Mnemonic::parse_in_normalized(l, &phrase).is_ok();
    Ok(json!({
        "ok": checksum,
        "count": count,
        "unknown": unknown,
        "checksum": checksum,
        "words": if unknown.is_empty() { Some(phrase) } else { None },
    })
    .to_string())
}

/// One word in the list's spelling (for a check of a few words), or null.
pub fn canonical_word(word: &str, lang: &str) -> R<Option<String>> {
    Ok(folded_list(language(lang)?).get(&fold(word.trim())).map(|w| w.to_string()))
}

fn mnemonic(words: &str, lang: &str) -> R<Mnemonic> {
    let l = language(lang)?;
    let (canon, unknown, count) = canonical(words, l);
    if count != 12 {
        return Err(format!("words: twelve of them, not {count}"));
    }
    if !unknown.is_empty() {
        let p: Vec<String> = unknown.iter().map(|p| p.to_string()).collect();
        return Err(format!("words: not on the list at positions {}", p.join(",")));
    }
    Mnemonic::parse_in_normalized(l, &canon.join(" ")).map_err(|_| "words: the checksum does not hold".to_string())
}

/// The words in their one spelling (the list's), or why they are not
/// twelve words of the list with a valid checksum.
pub fn normalize_words(words: &str, lang: &str) -> R<String> {
    Ok(mnemonic(words, lang)?.to_string())
}

/// The voter secret of twelve words.
pub fn secret_from_words(words: &str, lang: &str) -> R<String> {
    api::secret_from_entropy(&mnemonic(words, lang)?.to_entropy())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_lists_are_unique_without_accents() {
        assert_eq!(folded_list(Language::French).len(), 2048);
        assert_eq!(folded_list(Language::English).len(), 2048);
    }

    #[test]
    fn accents_are_optional_and_errors_name_positions() {
        let w = words_of_entropy(&[0x5au8; 16], "fr").unwrap();
        let bare: String = w.split(' ').map(fold).collect::<Vec<_>>().join(" ");
        assert_eq!(secret_from_words(&bare, "fr").unwrap(), secret_from_words(&w, "fr").unwrap());
        assert_eq!(normalize_words(&bare.to_uppercase(), "fr").unwrap(), w);
        let mut v: Vec<&str> = w.split(' ').collect();
        v[2] = "xyzzy";
        v[7] = "plugh";
        let c: serde_json::Value = serde_json::from_str(&check_words(&v.join(" "), "fr").unwrap()).unwrap();
        assert_eq!(c["unknown"], json!([3, 8]));
        assert_eq!(c["ok"], json!(false));
        assert!(secret_from_words(&v.join(" "), "fr").unwrap_err().contains("3,8"));
        let c: serde_json::Value = serde_json::from_str(&check_words(&bare, "fr").unwrap()).unwrap();
        assert_eq!(c["ok"], json!(true));
        assert_eq!(canonical_word(&fold(v[0]).to_uppercase(), "fr").unwrap().as_deref(), Some(v[0]));
    }
}
