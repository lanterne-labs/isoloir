//! The audit in the browser (SPEC §16): the same `isoloir_proto::audit`
//! the CLI runs, replaying the log checkpoint by checkpoint. The ballot
//! proofs (bb.js) and the passport proofs (the ZKPassport SDK) are
//! asynchronous in a page, and the judge calls its verifiers
//! synchronously; so the audit runs in two passes over the same log:
//!
//!   1. every checkpoint is fed with no verdict known: each proof the judge
//!      asks for is recorded as a request (and counts as "not checked"),
//!   2. the page verifies the requests, gives the verdicts back, and feeds
//!      the log again from the start: the judge now gets its answers.
//!
//! The state is applied whatever the verdicts (as in the CLI), so both
//! passes ask for the same proofs. A verdict that is missing in the second
//! pass stays a problem: a check that could not run is not a pass.

use crate::api::{err, R};
use base64::Engine as _;
use isoloir_core::{canonical, encoding};
use isoloir_proto::audit::{self, Auditor, Report};
use isoloir_proto::body::{CircuitRef, Eligibility, EntryKind};
use isoloir_proto::judge::{Checkers, Passports, Proofs};
use isoloir_proto::state::State;
use serde_json::{json, Value};
use std::cell::RefCell;
use std::collections::HashMap;

/// A verdict the page gives back for a request.
#[derive(Clone, Debug)]
enum Answer {
    Proof(Result<bool, String>),
    Passport(Result<Option<String>, String>),
}

/// The verifiers of one audit: they answer from the verdicts the page
/// gave, and record what they were asked and could not answer.
#[derive(Default)]
struct Asked {
    answers: RefCell<HashMap<String, Answer>>,
    requests: RefCell<Vec<Value>>,
    /// The dev provider accepted (a local trial); else its registrations are refused.
    allow_dev: bool,
}

const PENDING: &str = "pending: verified in the page";

fn proof_key(c: &CircuitRef, proof: &[u8], inputs: &[[u8; 32]]) -> String {
    let mut b = Vec::with_capacity(proof.len() + inputs.len() * 32 + 128);
    b.extend_from_slice(c.name.as_bytes());
    b.push(0);
    b.extend_from_slice(c.vk_hash.as_bytes());
    b.push(0);
    b.extend_from_slice(proof);
    for i in inputs {
        b.extend_from_slice(i);
    }
    encoding::body_hash(&b)
}

impl Proofs for Asked {
    fn verify(&self, circuit: &CircuitRef, proof: &[u8], inputs: &[[u8; 32]]) -> Result<bool, String> {
        let key = proof_key(circuit, proof, inputs);
        if let Some(Answer::Proof(a)) = self.answers.borrow().get(&key) {
            return a.clone();
        }
        self.requests.borrow_mut().push(json!({
            "key": key,
            "type": "proof",
            "circuit": circuit.name,
            "vk_hash": circuit.vk_hash,
            "proof": base64::engine::general_purpose::STANDARD.encode(proof),
            "inputs": inputs.iter().map(|i| format!("0x{}", hex::encode(i))).collect::<Vec<_>>(),
        }));
        Err(PENDING.into())
    }
}

impl Passports for Asked {
    fn verify(&self, e: &Eligibility, proof: &Value, custom_data: &str, proof_date: u64) -> Result<Option<String>, String> {
        // The dev provider takes anyone, its "proof" is the uid itself:
        // accepted in a trial only, refused otherwise (as the ingest does).
        if e.provider == "dev" {
            return Ok(if self.allow_dev { proof.get("uid").and_then(Value::as_str).map(String::from) } else { None });
        }
        let req = json!({ "eligibility": e, "proof": proof, "custom_data": custom_data, "proof_date": proof_date });
        let key = encoding::body_hash(&canonical::to_vec(&req).map_err(err)?);
        if let Some(Answer::Passport(a)) = self.answers.borrow().get(&key) {
            return a.clone();
        }
        let mut r = req;
        r["key"] = json!(key);
        r["type"] = json!("passport");
        self.requests.borrow_mut().push(r);
        Err(PENDING.into())
    }
}

/// One audit run (one pass over the log).
pub struct Run {
    asked: &'static Asked,
    auditor: Option<Auditor<'static>>,
    finished: Option<(State, Report)>,
}

impl Run {
    /// A pass; `verdicts` the answers of an earlier pass (`{}` for the
    /// first); `allow_dev` accepts the dev provider (a local trial).
    pub fn new(log_key: Option<&str>, verdicts_json: &str, allow_dev: bool) -> R<Run> {
        let asked: &'static Asked = Box::leak(Box::new(Asked { allow_dev, ..Default::default() }));
        let v: HashMap<String, Value> = serde_json::from_str(verdicts_json).map_err(err)?;
        let mut answers = asked.answers.borrow_mut();
        for (k, a) in v {
            let answer = if let Some(e) = a.get("error").and_then(Value::as_str) {
                if a.get("type").and_then(Value::as_str) == Some("passport") { Answer::Passport(Err(e.into())) } else { Answer::Proof(Err(e.into())) }
            } else if let Some(ok) = a.get("ok").and_then(Value::as_bool) {
                Answer::Proof(Ok(ok))
            } else if a.get("type").and_then(Value::as_str) == Some("passport") {
                Answer::Passport(Ok(a.get("uid").and_then(Value::as_str).map(String::from)))
            } else {
                return Err(format!("verdict {k}: neither ok, uid nor error"));
            };
            answers.insert(k, answer);
        }
        drop(answers);
        // The tlock opener needs drand: not in the page (a tlock tally is
        // then reported as not checked).
        let auditor = Auditor::new(log_key, Checkers { proofs: asked, passports: asked, tlock: None })?;
        Ok(Run { asked, auditor: Some(auditor), finished: None })
    }

    /// Feeds a checkpoint: its signed note and its entries file (the
    /// mirror's `entries/<i>.json`). Returns the checkpoint's index and
    /// time, the counts so far and the requests it made.
    pub fn checkpoint(&mut self, note: &str, entries_json: &str) -> R<String> {
        let a = self.auditor.as_mut().ok_or("the audit is finished")?;
        let v: Value = serde_json::from_str(entries_json).map_err(err)?;
        let entries = v
            .as_array()
            .ok_or("entries: not an array")?
            .iter()
            .map(|e| {
                let seq = e["seq"].as_u64().ok_or("entry without seq")?;
                let kind = e["kind"].as_str().and_then(EntryKind::parse).ok_or_else(|| format!("entry {seq}: kind"))?;
                let body = e["body"].as_str().ok_or_else(|| format!("entry {seq}: body"))?.as_bytes().to_vec();
                Ok((kind, body))
            })
            .collect::<R<Vec<_>>>()?;
        let cp = a.checkpoint(note, &entries)?;
        let requests = std::mem::take(&mut *self.asked.requests.borrow_mut());
        Ok(json!({ "index": cp.index, "time": cp.time, "report": report_json(&a.report), "requests": requests }).to_string())
    }

    /// Ends the pass: the final report.
    pub fn finish(&mut self) -> R<String> {
        if self.finished.is_none() {
            let a = self.auditor.take().ok_or("the audit is finished")?;
            let (state, mut r) = a.finish();
            // As the CLI: a dev registry is a problem, a warning in a trial.
            for (id, reg) in &state.registries {
                if reg.current().eligibility.provider == "dev" {
                    let w = format!("registry {id} takes the dev provider: anyone may register");
                    if self.asked.allow_dev { r.warnings.push(w) } else { r.problems.push(w) }
                }
            }
            self.finished = Some((state, r));
        }
        let (state, r) = self.finished.as_ref().unwrap();
        let mut out = report_json(r);
        // Where to read the relays' copies, and each poll's last tally.
        if let Some(l) = state.ledger() {
            out["ledger"] = json!({
                "origin": l.origin,
                "relays": l.nostr(false),
                "tag": format!("{}/{}", isoloir_proto::PROTOCOL, l.origin),
                "ingest": l.ingest,
                "grace": 2 * l.checkpoint_period + 60,
            });
        }
        out["polls"] = state
            .polls
            .iter()
            .map(|(id, p)| json!({ "id": id, "title": p.current().title, "ballots": p.ballots.len() }))
            .collect::<Vec<_>>()
            .into();
        Ok(out.to_string())
    }

    /// Withholding (SPEC §11.3): the events the relays hold for this
    /// ledger (after `finish`). Returns the problems found.
    pub fn relays(&self, events_json: &str) -> R<String> {
        let (state, _) = self.finished.as_ref().ok_or("finish the audit first")?;
        let l = state.ledger().ok_or("no ledger")?;
        let events: Vec<isoloir_proto::sig::Event> = serde_json::from_str(events_json).map_err(err)?;
        let problems = audit::check_relays(state, &events, &l.ingest, 2 * l.checkpoint_period + 60);
        Ok(json!(problems).to_string())
    }
}

fn report_json(r: &Report) -> Value {
    json!({
        "problems": r.problems,
        "warnings": r.warnings,
        "checkpoints": r.checkpoints,
        "entries": r.entries,
        "registrations": r.registrations,
        "ballots": r.ballots,
        "rejects": r.rejects,
        "tallies": r.tallies,
        "summarized": r.summarized,
        "unjudged": r.unjudged,
        "unlisted": r.unlisted,
    })
}
