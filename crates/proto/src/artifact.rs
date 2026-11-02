//! A compiled Noir circuit as the mirror publishes it: nargo names each
//! source file by its absolute path on the machine that compiled it (the
//! `file_map` of the artifact, for debug locations). Published, those paths
//! would name that machine's user; they are cut to the part from the
//! circuits' directory, the nargo dependency cache or the file's name.

use serde_json::Value;

/// The artifact with relative source paths, the rest unchanged.
pub fn published(artifact: &[u8]) -> Result<Vec<u8>, String> {
    let mut a: Value = serde_json::from_slice(artifact).map_err(|e| format!("artifact: {e}"))?;
    if let Some(files) = a.get_mut("file_map").and_then(Value::as_object_mut) {
        for f in files.values_mut() {
            if let Some(p) = f.get("path").and_then(Value::as_str) {
                let p = relative(p);
                f["path"] = Value::String(p);
            }
        }
    }
    serde_json::to_vec(&a).map_err(|e| e.to_string())
}

fn relative(p: &str) -> String {
    if !p.starts_with('/') && !p.contains(":\\") {
        return p.to_string();
    }
    let p = p.replace('\\', "/");
    for marker in ["/circuits/", "/nargo/"] {
        if let Some(i) = p.rfind(marker) {
            return p[i + 1..].to_string();
        }
    }
    p.rsplit('/').next().unwrap_or_default().to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn no_absolute_paths() {
        let a = br#"{"bytecode":"x","file_map":{"1":{"path":"/home/u/src/isoloir/circuits/lib/src/lib.nr","source":"s"},"2":{"path":"std/hash/mod.nr"},"3":{"path":"/Users/u/nargo/github.com/noir-lang/poseidon/v0.4.0/src/poseidon2.nr"},"4":{"path":"/tmp/x/main.nr"}}}"#;
        let out: Value = serde_json::from_slice(&published(a).unwrap()).unwrap();
        let paths: Vec<&str> = ["1", "2", "3", "4"].iter().map(|k| out["file_map"][k]["path"].as_str().unwrap()).collect();
        assert_eq!(paths, ["circuits/lib/src/lib.nr", "std/hash/mod.nr", "nargo/github.com/noir-lang/poseidon/v0.4.0/src/poseidon2.nr", "main.nr"]);
        assert_eq!(out["bytecode"], "x");
    }
}
