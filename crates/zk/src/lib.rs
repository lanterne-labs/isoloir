//! The circuits of isoloir through their tools (SPEC §9.1): `nargo`
//! compiles and executes them, `bb` writes their verification keys,
//! proves (in tests and tools; browsers prove with bb.js) and verifies
//! (in the ingest and the auditor). Both run as subprocesses.

use isoloir_core::encoding;
use isoloir_proto::body::CircuitRef;
use isoloir_proto::judge::Proofs;
use serde_json::{Map, Value};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Mutex;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("{0} not found: set {1} or put it on the PATH")]
    Missing(&'static str, &'static str),
    #[error("{0}: {1}")]
    Tool(String, String),
    #[error(transparent)]
    Io(#[from] std::io::Error),
}

pub type Result<T> = std::result::Result<T, Error>;

/// The proving system's target: what browsers prove with and the
/// verifier checks.
pub const TARGET: &str = "noir-recursive";

/// The tools' paths.
#[derive(Clone, Debug)]
pub struct Tools {
    pub nargo: PathBuf,
    pub bb: PathBuf,
}

fn which(name: &str) -> Option<PathBuf> {
    std::env::var_os("PATH").and_then(|p| std::env::split_paths(&p).map(|d| d.join(name)).find(|f| f.is_file()))
}

impl Tools {
    /// From `ISOLOIR_NARGO` and `ISOLOIR_BB`, else the PATH (and nargo's
    /// default install, `~/.nargo/bin`).
    pub fn find() -> Result<Tools> {
        let nargo = std::env::var_os("ISOLOIR_NARGO")
            .map(PathBuf::from)
            .or_else(|| which("nargo"))
            .or_else(|| std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".nargo/bin/nargo")).filter(|p| p.is_file()))
            .ok_or(Error::Missing("nargo", "ISOLOIR_NARGO"))?;
        let bb = Self::find_bb()?;
        Ok(Tools { nargo, bb })
    }

    /// bb alone (the verifier needs nothing else).
    pub fn find_bb() -> Result<PathBuf> {
        std::env::var_os("ISOLOIR_BB").map(PathBuf::from).or_else(|| which("bb")).ok_or(Error::Missing("bb", "ISOLOIR_BB"))
    }
}

fn run(cmd: &mut Command) -> Result<String> {
    let out = cmd.output()?;
    if !out.status.success() {
        return Err(Error::Tool(format!("{cmd:?}"), String::from_utf8_lossy(&[out.stdout, out.stderr].concat()).trim().to_string()));
    }
    Ok(String::from_utf8_lossy(&out.stdout).to_string())
}

/// `0x` + SHA-256 of a verification key: what a poll names.
pub fn vk_hash(vk: &[u8]) -> String {
    encoding::body_hash(vk)
}

/// The circuits directory (circuits/: gen.py, lib/, build/).
#[derive(Clone, Debug)]
pub struct Circuits {
    pub root: PathBuf,
}

/// A built circuit.
#[derive(Clone, Debug)]
pub struct Built {
    pub name: String,
    pub artifact: PathBuf,
    pub vk: PathBuf,
    pub vk_hash: String,
}

impl Circuits {
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Circuits { root: root.into() }
    }

    /// The circuits of this repository (for tests).
    pub fn repo() -> Self {
        Circuits::new(Path::new(env!("CARGO_MANIFEST_DIR")).join("../../circuits"))
    }

    fn package(&self, name: &str) -> PathBuf {
        self.root.join("build").join(name)
    }

    /// Generates (when missing), compiles and writes the verification key
    /// of a variant; does nothing when both are newer than the sources.
    pub fn build(&self, tools: &Tools, name: &str) -> Result<Built> {
        let pkg = self.package(name);
        if !pkg.join("src/main.nr").is_file() {
            run(Command::new("python3").arg(self.root.join("gen.py")).arg(name))?;
        }
        let artifact = pkg.join("target").join(format!("{name}.json"));
        let vk_dir = pkg.join("target").join("vk_out");
        let vk = vk_dir.join("vk");
        let stale = |out: &Path| -> bool {
            let Ok(t) = out.metadata().and_then(|m| m.modified()) else { return true };
            [pkg.join("src/main.nr"), self.root.join("lib/src/lib.nr"), self.root.join("lib/src/tags.nr")]
                .iter()
                .any(|src| src.metadata().and_then(|m| m.modified()).map(|s| s > t).unwrap_or(true))
        };
        if stale(&artifact) {
            run(Command::new(&tools.nargo).arg("compile").current_dir(&pkg))?;
        }
        if stale(&vk) || vk.metadata()?.modified()? < artifact.metadata()?.modified()? {
            std::fs::create_dir_all(&vk_dir)?;
            run(Command::new(&tools.bb).args(["write_vk", "-b"]).arg(&artifact).arg("-o").arg(&vk_dir).args(["-t", TARGET]))?;
        }
        Ok(Built { name: name.to_string(), vk_hash: vk_hash(&std::fs::read(&vk)?), artifact, vk })
    }
}

fn toml_value(v: &Value) -> String {
    match v {
        Value::String(s) => format!("\"{s}\""),
        Value::Number(n) => n.to_string(),
        Value::Bool(b) => b.to_string(),
        Value::Array(a) => format!("[{}]", a.iter().map(toml_value).collect::<Vec<_>>().join(", ")),
        _ => panic!("no such circuit input: {v}"),
    }
}

/// A proof and its public inputs.
pub struct Proof {
    pub proof: Vec<u8>,
    pub public_inputs: Vec<[u8; 32]>,
}

/// Proves with nargo and bb (tests and tools).
pub struct Prover {
    pub tools: Tools,
    pub circuits: Circuits,
    lock: Mutex<()>,
}

impl Prover {
    pub fn new(tools: Tools, circuits: Circuits) -> Self {
        Prover { tools, circuits, lock: Mutex::new(()) }
    }

    /// Executes the circuit on the inputs and proves.
    pub fn prove(&self, name: &str, inputs: &Map<String, Value>) -> Result<Proof> {
        let built = self.circuits.build(&self.tools, name)?;
        let pkg = self.circuits.package(name);
        let tag = format!("w{}", rand::random::<u64>());
        let prover_name = format!("Prover_{tag}");
        let toml: String = inputs.iter().map(|(k, v)| format!("{k} = {}\n", toml_value(v))).collect();
        std::fs::write(pkg.join(format!("{prover_name}.toml")), toml)?;
        let out = tempfile::tempdir()?;
        let result = (|| {
            {
                // nargo may touch the package's target: one at a time.
                let _g = self.lock.lock().unwrap();
                run(Command::new(&self.tools.nargo).args(["execute", &tag, "-p", &prover_name]).current_dir(&pkg))?;
            }
            let witness = pkg.join("target").join(format!("{tag}.gz"));
            let r = run(Command::new(&self.tools.bb)
                .args(["prove", "-b"])
                .arg(&built.artifact)
                .arg("-w")
                .arg(&witness)
                .arg("-k")
                .arg(&built.vk)
                .arg("-o")
                .arg(out.path())
                .args(["-t", TARGET]));
            let _ = std::fs::remove_file(&witness);
            r?;
            let proof = std::fs::read(out.path().join("proof"))?;
            let pi = std::fs::read(out.path().join("public_inputs"))?;
            Ok(Proof { proof, public_inputs: pi.chunks(32).map(|c| c.try_into().expect("32-byte fields")).collect() })
        })();
        let _ = std::fs::remove_file(pkg.join(format!("{prover_name}.toml")));
        result
    }
}

/// Verifies proofs with bb against verification keys from a directory
/// laid out as `<dir>/<circuit name>/vk` (the mirror's `circuits/`), each
/// checked against the hash the poll names.
pub struct BbProofs {
    bb: PathBuf,
    dir: PathBuf,
    known: Mutex<HashMap<String, PathBuf>>,
}

impl BbProofs {
    pub fn new(bb: PathBuf, dir: PathBuf) -> Self {
        BbProofs { bb, dir, known: Mutex::new(HashMap::new()) }
    }

    fn vk(&self, c: &CircuitRef) -> std::result::Result<PathBuf, String> {
        if let Some(p) = self.known.lock().unwrap().get(&c.vk_hash) {
            return Ok(p.clone());
        }
        if c.name.contains(['/', '.']) {
            return Err(format!("circuit name {}", c.name));
        }
        let path = self.dir.join(&c.name).join("vk");
        let bytes = std::fs::read(&path).map_err(|e| format!("{}: {e}", path.display()))?;
        if vk_hash(&bytes) != c.vk_hash {
            return Err(format!("{}: its hash is not the poll's", path.display()));
        }
        self.known.lock().unwrap().insert(c.vk_hash.clone(), path.clone());
        Ok(path)
    }
}

impl Proofs for BbProofs {
    fn verify(&self, circuit: &CircuitRef, proof: &[u8], inputs: &[[u8; 32]]) -> std::result::Result<bool, String> {
        let vk = self.vk(circuit)?;
        let dir = tempfile::tempdir().map_err(|e| e.to_string())?;
        std::fs::write(dir.path().join("proof"), proof).map_err(|e| e.to_string())?;
        std::fs::write(dir.path().join("public_inputs"), inputs.concat()).map_err(|e| e.to_string())?;
        let out = Command::new(&self.bb)
            .args(["verify", "-k"])
            .arg(&vk)
            .arg("-p")
            .arg(dir.path().join("proof"))
            .arg("-i")
            .arg(dir.path().join("public_inputs"))
            .args(["-t", TARGET])
            .output()
            .map_err(|e| format!("bb: {e}"))?;
        // bb exits 1 both for a proof that does not verify and for a
        // failure of its own (a file it cannot open, memory): the message
        // tells them apart. A refusal must never come from our failure.
        let text = format!("{}{}", String::from_utf8_lossy(&out.stdout), String::from_utf8_lossy(&out.stderr));
        match out.status.code() {
            Some(0) => Ok(true),
            Some(_) if INFRA.iter().any(|m| text.contains(m)) => Err(format!("bb verify: {}", text.trim())),
            Some(_) => Ok(false),
            None => Err(format!("bb verify: {}", text.trim())),
        }
    }
}

/// What bb prints when it could not run, as opposed to a proof that does
/// not verify.
const INFRA: &[&str] = &["Unable to open file", "No such file", "bad_alloc", "Cannot allocate", "out of memory", "Permission denied", "Killed", "Aborted"];

/// Installs a built circuit into a verification-key directory
/// (`<dir>/<name>/vk` and the artifact browsers prove with).
pub fn install(built: &Built, dir: &Path) -> Result<()> {
    let d = dir.join(&built.name);
    std::fs::create_dir_all(&d)?;
    std::fs::copy(&built.vk, d.join("vk"))?;
    std::fs::copy(&built.artifact, d.join("artifact.json"))?;
    Ok(())
}
