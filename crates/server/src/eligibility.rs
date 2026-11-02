//! Passport verification (SPEC §6): the ZKPassport verifier runs as a
//! Node sidecar (zkverifier/verify.mjs, the only verifier ZKPassport
//! ships is TypeScript); the `dev` provider takes the uid a test bundle
//! names and is refused unless the ingest was started for development.

use isoloir_proto::body::Eligibility;
use isoloir_proto::judge::Passports;
use serde_json::{json, Value};
use std::io::Write;
use std::path::PathBuf;
use std::process::{Command, Stdio};

pub struct Verifiers {
    /// node and verify.mjs; None when no zkpassport registry is served.
    pub zkpassport: Option<(PathBuf, PathBuf)>,
    /// An Ethereum RPC for the certificate registry roots.
    pub rpc_url: Option<String>,
    /// Accept the `dev` provider (tests and local trials only).
    pub allow_dev: bool,
}

impl Passports for Verifiers {
    fn verify(&self, e: &Eligibility, proof: &Value, custom_data: &str, proof_date: u64) -> Result<Option<String>, String> {
        match e.provider.as_str() {
            "dev" if self.allow_dev => Ok(proof.get("uid").and_then(Value::as_str).map(String::from)),
            "dev" => Ok(None),
            "zkpassport" => {
                let Some((node, script)) = &self.zkpassport else { return Err("no ZKPassport verifier configured".into()) };
                let req = json!({
                    "proofs": proof.get("proofs"),
                    "result": proof.get("result"),
                    "challenge": custom_data,
                    "domain": e.domain,
                    "scope": e.scope,
                    "minAge": e.min_age,
                    "nationality": e.nationality,
                    "documentType": e.document_type,
                    "requireExpiry": e.require_expiry,
                    "oprfKey": e.oprf_key,
                    "proofDate": proof_date * 1000,
                    "rpcUrl": self.rpc_url,
                });
                let mut child = Command::new(node).arg(script).stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::piped()).spawn().map_err(|e| format!("node: {e}"))?;
                child.stdin.take().expect("stdin").write_all(req.to_string().as_bytes()).map_err(|e| e.to_string())?;
                let out = child.wait_with_output().map_err(|e| e.to_string())?;
                let ans: Value = serde_json::from_slice(&out.stdout).map_err(|_| format!("verifier: {}", String::from_utf8_lossy(&out.stderr)))?;
                if ans.get("infrastructure").and_then(Value::as_bool) == Some(true) {
                    return Err(format!("verifier: {}", ans["errors"]));
                }
                if ans.get("verified").and_then(Value::as_bool) == Some(true) {
                    Ok(ans.get("uniqueIdentifier").and_then(Value::as_str).map(String::from).filter(|u| !u.is_empty()))
                } else {
                    tracing::debug!(errors = %ans["errors"], "passport proof refused");
                    Ok(None)
                }
            }
            p => Err(format!("unknown provider {p}")),
        }
    }
}
