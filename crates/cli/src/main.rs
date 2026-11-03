//! `isoloir`: run a ledger. See README.md for the order of operations.

use anyhow::{bail, Context, Result};
use clap::{Parser, Subcommand};
use isoloir_decrypt::keys::AuthorityKeys;
use isoloir_decrypt::tlock::DrandTlock;
use isoloir_proto::audit::Auditor;
use isoloir_proto::body::{self, Body, EntryKind};
use isoloir_proto::judge::Checkers;
use isoloir_proto::note;
use isoloir_relay::Pool;
use isoloir_server::eligibility::Verifiers;
use isoloir_server::ingest::{Config, Ingest};
use isoloir_server::mirror::Mirror;
use isoloir_server::direct::{self, DirectHub};
use isoloir_server::relays::{self, Channels};
use isoloir_server::source::{LogSource, MirrorSource};
use isoloir_server::store::Store;
use isoloir_server::authority::{Keys, Output, Service};
use isoloir_zk::{BbProofs, Circuits, Tools};
use rand::RngCore;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

mod voter;

#[derive(Parser)]
#[command(name = "isoloir", version, about = "Anonymous polls with passport eligibility")]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Makes keys.
    #[command(subcommand)]
    Keygen(Keygen),
    /// Builds circuit variants and installs them into a mirror's circuits/.
    Circuits {
        /// Variant names (circuits/gen.py), e.g. choice4_single_linked_d20.
        names: Vec<String>,
        #[arg(long, default_value = "circuits")]
        circuits: PathBuf,
        #[arg(long)]
        mirror: PathBuf,
    },
    /// Starts a ledger: logs its setup as the first entry.
    Genesis {
        #[arg(long, env = "DATABASE_URL")]
        db: String,
        /// The ledger setup (SPEC §4.1), JSON.
        ledger: PathBuf,
        #[arg(long, env = "ISOLOIR_LOG_SEED", hide_env_values = true)]
        log_seed: String,
    },
    /// Submits a setup (registry, poll, or a later ledger version).
    Submit {
        #[arg(long, env = "DATABASE_URL")]
        db: String,
        /// ledger, registry or poll.
        kind: String,
        /// The setup, JSON (written canonically before it is submitted).
        file: PathBuf,
    },
    /// Runs the ingest.
    Ingest {
        #[arg(long, env = "DATABASE_URL")]
        db: String,
        #[arg(long, env = "ISOLOIR_LOG_SEED", hide_env_values = true)]
        log_seed: String,
        #[arg(long, env = "ISOLOIR_NOSTR_KEY", hide_env_values = true)]
        nostr_key: String,
        #[arg(long)]
        mirror_dir: PathBuf,
        /// Commit the mirror and push it to this git remote.
        #[arg(long)]
        mirror_git: Option<String>,
        /// The ZKPassport verifier script (zkverifier/verify.mjs).
        #[arg(long)]
        zkverifier: Option<PathBuf>,
        #[arg(long, default_value = "node")]
        node: PathBuf,
        #[arg(long, env = "ISOLOIR_ETH_RPC")]
        rpc_url: Option<String>,
        /// Accept the dev passport provider (local trials only).
        #[arg(long)]
        dev: bool,
        /// Do not timestamp the checkpoints.
        #[arg(long)]
        no_stamps: bool,
        /// Where to serve the ledger's direct channel (when it lists one).
        #[arg(long)]
        listen: Option<std::net::SocketAddr>,
    },
    /// Runs an authority: verifies the log, publishes the tallies due.
    Authority {
        /// The log: a mirror directory or URL; absent, the ingest's database (--db).
        #[arg(long)]
        mirror: Option<String>,
        #[arg(long)]
        log_key: Option<String>,
        /// The authority's keys (keygen authority), or ISOLOIR_AUTHORITY_KEYS
        /// (the file's JSON); absent: tlock polls only.
        #[arg(long)]
        keys: Option<PathBuf>,
        /// The ledger's log key (its verifier string), pinned.
        #[arg(long, env = "ISOLOIR_LOG_KEY")]
        log_key_env: Option<String>,
        /// A drand HTTP API, for tlock polls.
        #[arg(long, default_value = "https://api.drand.sh")]
        drand: String,
        /// Verification keys (<dir>/<circuit>/vk); default: the mirror's circuits/ (a local
        /// mirror), else a clone of ISOLOIR_MIRROR_GIT.
        #[arg(long)]
        circuits: Option<PathBuf>,
        /// The ZKPassport verifier script, to check registrations.
        #[arg(long)]
        zkverifier: Option<PathBuf>,
        #[arg(long, default_value = "node")]
        node: PathBuf,
        #[arg(long, env = "ISOLOIR_ETH_RPC")]
        rpc_url: Option<String>,
        /// Post the tallies to the ingest's database instead of the relays.
        #[arg(long, env = "DATABASE_URL")]
        db: Option<String>,
        #[arg(long, env = "ISOLOIR_NOSTR_KEY", hide_env_values = true)]
        nostr_key: Option<String>,
        #[arg(long, default_value_t = 20)]
        every: u64,
        #[arg(long)]
        once: bool,
        /// Accept registrations of the dev passport provider (local trials
        /// only): without it, a dev registration in the log stops the authority.
        #[arg(long)]
        dev: bool,
    },
    /// A reference voter (dev provider registries; trials and tests).
    #[command(subcommand)]
    Voter(Voter),
    /// A local relay for trials (in memory, NIP-01 only).
    Relay {
        #[arg(long, default_value = "127.0.0.1:7777")]
        listen: std::net::SocketAddr,
    },
    /// Audits a ledger from its mirror.
    Audit {
        #[arg(long)]
        mirror: String,
        /// The ledger's log key, pinned; absent, the key the log names.
        #[arg(long)]
        log_key: Option<String>,
        /// Verification keys (<dir>/<circuit>/vk); default: the mirror's.
        #[arg(long)]
        circuits: Option<PathBuf>,
        #[arg(long)]
        zkverifier: Option<PathBuf>,
        #[arg(long, default_value = "node")]
        node: PathBuf,
        #[arg(long, env = "ISOLOIR_ETH_RPC")]
        rpc_url: Option<String>,
        /// Also read the ledger's relays: withholding, and the refused
        /// messages they still hold (judged again).
        #[arg(long)]
        relays: bool,
        /// The ingest's HTTP service (its base URL): the lists of the
        /// refusals a checkpoint sums up, and the refused bodies the relays
        /// no longer hold; all checked against the log.
        #[arg(long)]
        ledger: Option<String>,
        /// Do not check the passport proofs (they are then reported as not checked).
        #[arg(long)]
        skip_passports: bool,
        /// Check the checkpoints' stamps against Bitcoin block headers (blockstream.info, mempool.space).
        #[arg(long)]
        bitcoin: bool,
        /// Accept a registry of the dev passport provider (local trials): a
        /// warning, not a problem.
        #[arg(long)]
        dev: bool,
    },
    /// Checks a setup file offline: its spelling, its rules, the circuit it needs.
    Check {
        /// ledger, registry or poll.
        kind: String,
        file: PathBuf,
        /// The registry a poll belongs to (its setup file).
        #[arg(long)]
        registry: Option<PathBuf>,
    },
}

#[derive(Subcommand)]
enum Voter {
    /// Prints a new voter secret.
    Secret,
    /// Registers a voter secret in a dev registry.
    Register {
        #[arg(long)]
        mirror: PathBuf,
        #[arg(long)]
        registry: u32,
        #[arg(long)]
        secret: String,
        #[arg(long)]
        uid: String,
    },
    /// Casts a ballot: a slot number, "none", or a ranking "2,0,5".
    Vote {
        #[arg(long)]
        mirror: PathBuf,
        #[arg(long, default_value = "circuits")]
        circuits: PathBuf,
        #[arg(long)]
        poll: u32,
        #[arg(long)]
        secret: String,
        #[arg(long)]
        choice: String,
        #[arg(long, default_value_t = 0)]
        seq: u32,
    },
}

#[derive(Subcommand)]
enum Keygen {
    /// The ledger's log key: prints the seed (secret) and the verifier key.
    Log {
        #[arg(long)]
        origin: String,
    },
    /// A Nostr key (the ingest's): prints the secret and the public key;
    /// with ISOLOIR_NOSTR_KEY set, only the public key of that one.
    Nostr,
    /// An authority's keys, written to a file; prints the public half.
    Authority {
        #[arg(long)]
        out: PathBuf,
    },
}

fn now() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).expect("clock").as_secs()
}

/// The log key: 32 bytes of hex, or a C2SP `PRIVATE+KEY+…` string (whose
/// name must be the ledger's origin).
fn parse_log_key(s: &str, origin: Option<&str>) -> Result<[u8; 32]> {
    let s = s.trim();
    if s.starts_with("PRIVATE+KEY+") {
        let signer = note::Signer::from_private(s).map_err(|e| anyhow::anyhow!("log key: {e}"))?;
        if let Some(o) = origin {
            if signer.name != o {
                bail!("the log key is named {}, the ledger's origin is {o}", signer.name);
            }
        }
        return Ok(signer.seed());
    }
    seed(s, "log seed")
}

fn seed(hexs: &str, what: &str) -> Result<[u8; 32]> {
    hex::decode(hexs.trim()).ok().and_then(|b| b.try_into().ok()).with_context(|| format!("{what}: 32 bytes of hex"))
}

fn canonical_file(path: &PathBuf) -> Result<Vec<u8>> {
    let v: serde_json::Value = serde_json::from_slice(&std::fs::read(path)?)?;
    Ok(isoloir_core::canonical::to_vec(&v)?)
}

fn passports(zkverifier: Option<PathBuf>, node: PathBuf, rpc_url: Option<String>, dev: bool) -> Verifiers {
    Verifiers { zkpassport: zkverifier.map(|s| (node, s)), rpc_url, allow_dev: dev }
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt().with_env_filter(tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info,sqlx=warn".into())).init();
    match Cli::parse().cmd {
        Cmd::Keygen(Keygen::Log { origin }) => {
            let mut s = [0u8; 32];
            rand::rngs::OsRng.fill_bytes(&mut s);
            println!("ISOLOIR_LOG_SEED={}", hex::encode(s));
            println!("log_key: {}", note::Signer::new(&origin, &s).verifier());
        }
        Cmd::Keygen(Keygen::Nostr) if std::env::var("ISOLOIR_NOSTR_KEY").is_ok() => {
            let s = seed(&std::env::var("ISOLOIR_NOSTR_KEY")?, "ISOLOIR_NOSTR_KEY")?;
            println!("ingest: {}", hex::encode(isoloir_proto::sig::xonly(&s)));
        }
        Cmd::Keygen(Keygen::Nostr) => {
            let mut s = [0u8; 32];
            rand::rngs::OsRng.fill_bytes(&mut s);
            println!("ISOLOIR_NOSTR_KEY={}", hex::encode(s));
            println!("ingest: {}", hex::encode(isoloir_proto::sig::xonly(&s)));
        }
        Cmd::Keygen(Keygen::Authority { out }) => {
            if out.exists() {
                bail!("{} exists: an authority's keys are never overwritten", out.display());
            }
            let k = AuthorityKeys::generate(&mut rand::rngs::OsRng);
            std::fs::write(&out, serde_json::to_vec_pretty(&k)?)?;
            println!("{}", serde_json::to_string_pretty(&k.public())?);
        }
        Cmd::Circuits { names, circuits, mirror } => {
            let tools = Tools::find()?;
            let c = Circuits::new(circuits);
            let m = Mirror::new(mirror, None);
            for n in names {
                let b = c.build(&tools, &n)?;
                m.install_circuit(&n, &b.artifact, &b.vk)?;
                println!("{n} {}", b.vk_hash);
            }
        }
        Cmd::Genesis { db, ledger, log_seed } => {
            let store = Store::connect(&db).await?;
            let bytes = canonical_file(&ledger)?;
            let Body::Ledger(l) = body::decode(EntryKind::Ledger, &bytes).map_err(|r| anyhow::anyhow!("ledger: {}", r.as_str()))? else { unreachable!() };
            let config = Config { log_seed: parse_log_key(&log_seed, Some(&l.origin))?, nostr_sk: [0u8; 32] };
            Ingest::genesis(&store, &config, &l, now()).await?;
            println!("ledger {} started", l.origin);
        }
        Cmd::Submit { db, kind, file } => {
            let k = EntryKind::parse(&kind).filter(|k| matches!(k, EntryKind::Ledger | EntryKind::Registry | EntryKind::Poll)).context("kind: ledger, registry or poll")?;
            let bytes = canonical_file(&file)?;
            body::decode_verbose(k, &bytes).map_err(|e| anyhow::anyhow!("{kind}: {e}"))?;
            let store = Store::connect(&db).await?;
            let id = store.submit(k, &bytes, now()).await?;
            // Wait for the ingest's verdict.
            for _ in 0..120 {
                tokio::time::sleep(Duration::from_secs(1)).await;
                if let Some((status, err)) = store.submission(id).await? {
                    match status.as_str() {
                        "logged" => {
                            println!("logged");
                            return Ok(());
                        }
                        "rejected" => bail!("refused: {}", err.unwrap_or_default()),
                        _ => {}
                    }
                }
            }
            bail!("submitted ({id}) but not logged within two minutes: is the ingest running?");
        }
        Cmd::Ingest { db, log_seed, nostr_key, mirror_dir, mirror_git, zkverifier, node, rpc_url, dev, no_stamps, listen } => {
            if dev && std::env::var_os("RAILWAY_ENVIRONMENT").is_some() {
                bail!("--dev is for local trials");
            }
            let store = Store::connect(&db).await?;
            let _lease = store.lease_wait(Duration::from_secs(600)).await?;
            let entries = store.entries().await?;
            // The channels of the ledger's current version.
            let Some((_, _, last_ledger, _)) = entries.iter().filter(|e| e.1 == EntryKind::Ledger).last() else { bail!("no ledger: run isoloir genesis first") };
            let Ok(Body::Ledger(l)) = body::decode(EntryKind::Ledger, last_ledger) else { bail!("the ledger entry does not decode") };
            let listen = listen.or_else(|| std::env::var("PORT").ok().and_then(|p| format!("0.0.0.0:{p}").parse().ok()));
            let relays = l.nostr(true);
            let pool = (!relays.is_empty()).then(|| Pool::connect(relays));
            let hubs: Vec<Arc<DirectHub>> = l.direct(true).iter().map(|u| DirectHub::new(u)).collect();
            if !hubs.is_empty() && listen.is_none() {
                bail!("the ledger lists a direct channel ({}): --listen to serve it", l.direct(true).join(", "));
            }
            let transport = Arc::new(Channels { pool: pool.clone(), direct: hubs.clone() });
            let bb = Tools::find_bb()?;
            let mirror = Mirror::new(mirror_dir.clone(), mirror_git.or_else(|| std::env::var("ISOLOIR_MIRROR_GIT").ok()));
            mirror.prepare()?;
            let config = Config { log_seed: parse_log_key(&log_seed, Some(&l.origin))?, nostr_sk: seed(&nostr_key, "nostr key")? };
            let mut ing = Ingest::load(
                store.clone(),
                config,
                transport,
                Box::new(BbProofs::new(bb, mirror_dir.join("circuits"))),
                Box::new(passports(zkverifier, node, rpc_url, dev)),
                Some(Box::new(DrandTlock)),
                Some(mirror),
            )
            .await?;
            if !no_stamps {
                ing.calendars = isoloir_stamps_calendars();
            }
            let (tx, mut rx) = tokio::sync::mpsc::channel(1024);
            if let Some(p) = &pool {
                relays::subscribe(p, &store, ing.tag(), tx.clone()).await?;
            }
            if let Some(addr) = listen {
                // The first direct hub, or health only.
                let app = match hubs.first() {
                    Some(hub) => direct::router(hub.clone(), tx.clone(), store.clone()),
                    None => direct::health_router(store.clone()),
                };
                if hubs.len() > 1 {
                    tracing::warn!("the ledger lists {} direct channels; this process serves the first", hubs.len());
                }
                let listener = tokio::net::TcpListener::bind(addr).await?;
                tracing::info!(%addr, "listening");
                tokio::spawn(async move {
                    if let Err(e) = axum::serve(listener, app).await {
                        tracing::error!(error = %e, "direct channel");
                    }
                });
            }
            drop(tx);
            tracing::info!(origin = %l.origin, "ingest running");
            let mut tick = tokio::time::interval(Duration::from_secs(1));
            loop {
                tokio::select! {
                    biased;
                    m = rx.recv() => match m {
                        Some(inc) => ing.handle(inc, now()).await?,
                        None => bail!("every channel stopped"),
                    },
                    _ = tick.tick() => {
                        if let (Some(_), Some(p)) = (ing.tick(now()).await?, &pool) {
                            relays::save_cursors(p, &store).await?;
                        }
                    }
                    _ = tokio::signal::ctrl_c() => {
                        if let Some(p) = &pool {
                            relays::save_cursors(p, &store).await?;
                        }
                        return Ok(());
                    }
                    // The proof checks, one at a time, between messages.
                    _ = std::future::ready(()), if ing.has_work() => ing.work(now()).await?,
                }
            }
        }
        Cmd::Authority { mirror, log_key, log_key_env, keys, drand, circuits, zkverifier, node, rpc_url, db, nostr_key, every, once, dev } => {
            if dev && std::env::var_os("RAILWAY_ENVIRONMENT").is_some() {
                bail!("--dev is for local trials");
            }
            let log_key = log_key.or(log_key_env).context("--log-key or ISOLOIR_LOG_KEY: the ledger's log key, pinned")?;
            let bb = Tools::find_bb()?;
            let vk_dir = match (circuits, &mirror) {
                (Some(c), _) => c,
                (None, Some(m)) if !m.starts_with("http") => PathBuf::from(m).join("circuits"),
                (None, _) => {
                    // A fresh clone of the mirror's repository: its circuits.
                    let git = std::env::var("ISOLOIR_MIRROR_GIT").map_err(|_| anyhow::anyhow!("--circuits, or ISOLOIR_MIRROR_GIT to clone them from"))?;
                    let dir = std::env::temp_dir().join(format!("isoloir-authority-{}", std::process::id()));
                    let _ = std::fs::remove_dir_all(&dir);
                    Mirror::new(dir.clone(), Some(git)).prepare()?;
                    dir.join("circuits")
                }
            };
            let keys_json = match (keys, std::env::var("ISOLOIR_AUTHORITY_KEYS").ok()) {
                (Some(p), _) => Some(std::fs::read(p)?),
                (None, Some(j)) => Some(j.into_bytes()),
                (None, None) => None,
            };
            let keys = match keys_json {
                Some(bytes) => {
                    let k: AuthorityKeys = serde_json::from_slice(&bytes)?;
                    let (sk, sign_seed) = k.secrets().map_err(|e| anyhow::anyhow!(e))?;
                    Some(Keys { pk: k.pk, sk, sign_seed })
                }
                None => None,
            };
            let output = match (db.clone(), nostr_key) {
                (Some(db), _) => Output::Store(Store::connect(&db).await?),
                (None, Some(k)) => {
                    let src = MirrorSource::parse(mirror.as_deref().context("--mirror, or --db")?);
                    let first = src.from(1).await?.into_iter().next().context("an empty mirror")?;
                    let Some((EntryKind::Ledger, b)) = first.1.first() else { bail!("no ledger entry") };
                    let Ok(Body::Ledger(l)) = body::decode(EntryKind::Ledger, b) else { bail!("ledger") };
                    let relays = l.nostr(true);
                    if relays.is_empty() {
                        bail!("the ledger has no relay: post tallies with --db");
                    }
                    Output::Relays { transport: Arc::new(Channels { pool: Some(Pool::connect(relays)), direct: vec![] }), nostr_sk: seed(&k, "nostr key")? }
                }
                (None, None) => bail!("--db or --nostr-key: where tallies go"),
            };
            let source: Box<dyn LogSource> = match (&mirror, &db) {
                (Some(m), _) => Box::new(MirrorSource::parse(m)),
                (None, Some(db)) => Box::new(Store::connect(db).await?),
                (None, None) => bail!("--mirror or --db: where the log is read"),
            };
            let mut t = Service::new(
                source,
                Some(&log_key),
                Box::new(BbProofs::new(bb, vk_dir)),
                Box::new(passports(zkverifier, node, rpc_url, dev)),
                keys,
                Some(drand),
                output,
            )?;
            loop {
                match t.step(now()).await {
                    Ok(n) if n > 0 => tracing::info!(n, "tallies published"),
                    Ok(_) => {}
                    // The log does not verify: never decrypt past it.
                    Err(e) if e.downcast_ref::<isoloir_server::authority::LogFault>().is_some() => return Err(e),
                    Err(e) => {
                        if once {
                            return Err(e);
                        }
                        tracing::warn!(error = %e, "retried next round");
                    }
                }
                if once {
                    return Ok(());
                }
                tokio::time::sleep(Duration::from_secs(every)).await;
            }
        }
        Cmd::Voter(Voter::Secret) => {
            println!("{}", isoloir_core::field::to_hex(&isoloir_core::grumpkin::random_fr(&mut rand::rngs::OsRng)));
        }
        Cmd::Voter(Voter::Register { mirror, registry, secret, uid }) => voter::register(&mirror, registry, &secret, &uid).await?,
        Cmd::Voter(Voter::Vote { mirror, circuits, poll, secret, choice, seq }) => voter::vote(&mirror, &circuits, poll, &secret, &choice, seq).await?,
        Cmd::Relay { listen } => {
            let (addr, task) = isoloir_relay::local::serve(listen).await?;
            println!("relay on ws://{addr}");
            task.await?;
        }
        Cmd::Check { kind, file, registry } => {
            let k = EntryKind::parse(&kind).filter(|k| matches!(k, EntryKind::Ledger | EntryKind::Registry | EntryKind::Poll)).context("kind: ledger, registry or poll")?;
            let bytes = canonical_file(&file)?;
            let b = body::decode_verbose(k, &bytes).map_err(|e| anyhow::anyhow!("{}: {e}", file.display()))?;
            match &b {
                Body::Ledger(l) => isoloir_proto::matrix::check_ledger(l).map_err(|e| anyhow::anyhow!(e))?,
                Body::Registry(r) => isoloir_proto::matrix::check_registry(r).map_err(|e| anyhow::anyhow!(e))?,
                Body::Poll(p) => {
                    let rb = canonical_file(&registry.context("--registry: the poll's registry setup")?)?;
                    let Body::Registry(r) = body::decode_verbose(EntryKind::Registry, &rb).map_err(|e| anyhow::anyhow!("registry: {e}"))? else { unreachable!() };
                    let v = isoloir_proto::matrix::check_poll(p, &r).map_err(|e| anyhow::anyhow!(e))?;
                    println!("circuit to build and install: {}", v.name());
                }
                _ => unreachable!(),
            }
            println!("ok: {}", String::from_utf8_lossy(&bytes));
        }
        Cmd::Audit { mirror, log_key, circuits, zkverifier, node, rpc_url, relays, ledger, skip_passports, bitcoin, dev } => {
            let bb = Tools::find_bb()?;
            let vk_dir = match circuits {
                Some(c) => c,
                None if mirror.starts_with("http") => bail!("--circuits: where the verification keys are (an HTTP mirror); build them yourself from circuits/ to trust nobody"),
                None => PathBuf::from(&mirror).join("circuits"),
            };
            let proofs = BbProofs::new(bb, vk_dir);
            if zkverifier.is_none() && !skip_passports {
                bail!("--zkverifier <verify.mjs> to check the passport proofs, or --skip-passports to report them as not checked");
            }
            // The dev provider takes anyone: a registry of it is a problem,
            // and its registrations are refused, unless --dev (a trial).
            let passports = passports(zkverifier, node, rpc_url, dev);
            let mut a = Auditor::new(log_key.as_deref(), Checkers { proofs: &proofs, passports: &passports, tlock: Some(&DrandTlock) }).map_err(|e| anyhow::anyhow!(e))?;
            let read = MirrorSource::parse(&mirror).from(1).await?;
            // The relays first: their copies of the refused messages are
            // judged again in the replay (the log keeps only their hash).
            let mut events = vec![];
            let mut relay_warnings = vec![];
            let mut relay_count = 0;
            if relays {
                let mut urls: Vec<String> = vec![];
                let mut origin = None;
                for (k, b) in read.iter().flat_map(|(_, es)| es.iter()) {
                    if let (EntryKind::Ledger, Ok(Body::Ledger(l))) = (k, body::decode(*k, b)) {
                        origin = Some(l.origin.clone());
                        for u in l.nostr(false) {
                            if !urls.contains(&u) {
                                urls.push(u);
                            }
                        }
                    }
                }
                let tag = format!("{}/{}", isoloir_proto::PROTOCOL, origin.context("no ledger")?);
                let pool = Pool::connect(urls.clone());
                for u in &urls {
                    let f = isoloir_relay::Filter { kinds: vec![7100, 7101, 7102, 7105, 7106], t: Some(tag.clone()), ..Default::default() };
                    match pool.fetch(u, f, Duration::from_secs(30)).await {
                        Ok(es) => events.extend(es),
                        Err(e) => relay_warnings.push(format!("relay {u}: {e}")),
                    }
                }
                relay_count = urls.len();
            }
            let mut refusals = isoloir_server::source::Refusals::default();
            refusals.add_events(&events);
            if let Some(l) = &ledger {
                refusals.ask_ledger(l, &read).await;
            }
            a.copies = std::mem::take(&mut refusals.copies);
            a.lists = std::mem::take(&mut refusals.lists);
            for (n, es) in read {
                a.checkpoint(&n, &es).map_err(|e| anyhow::anyhow!(e))?;
            }
            let (state, mut r) = a.finish();
            r.warnings.extend(relay_warnings);
            r.warnings.extend(refusals.warnings);
            for (id, reg) in &state.registries {
                if reg.current().eligibility.provider == "dev" {
                    let w = format!("registry {id} takes the dev provider: anyone may register");
                    if dev { r.warnings.push(w) } else { r.problems.push(w) }
                }
            }
            if bitcoin {
                let src = MirrorSource::parse(&mirror);
                let headers = isoloir_stamps::Esplora::default();
                let (mut attested, mut pending) = (0, 0);
                for cp in &state.checkpoints {
                    let Some(ots) = src.get(&format!("stamps/{}.ots", cp.index)).await? else {
                        r.warnings.push(format!("checkpoint {}: no stamp on the mirror", cp.index));
                        continue;
                    };
                    let note = src.get(&format!("checkpoints/{}.txt", cp.index)).await?.context("note")?;
                    let digest = isoloir_core::encoding::sha256(&note);
                    match isoloir_stamps::Ots::parse(&ots).map_err(|e| e.to_string()).and_then(|o| isoloir_stamps::verify(&o, digest, &headers).map_err(|e| e.to_string())) {
                        Ok(blocks) => {
                            attested += 1;
                            if let Some((h, t)) = blocks.iter().min_by_key(|b| b.0) {
                                if (*t as u64) + 86_400 < cp.time {
                                    r.problems.push(format!("checkpoint {}: attested in block {h} ({t}), a day before its own time {}", cp.index, cp.time));
                                }
                            }
                        }
                        Err(e) if e.contains("NoBitcoinAttestation") || e.contains("pending") => pending += 1,
                        Err(e) => r.problems.push(format!("checkpoint {}: stamp: {e}", cp.index)),
                    }
                }
                println!("stamps: {attested} attested in Bitcoin, {pending} pending");
            }
            if relays {
                let l = state.ledger().context("no ledger")?.clone();
                println!("{} events read from {} relays", events.len(), relay_count);
                let (problems, warnings) = isoloir_proto::audit::check_relays_report(&state, &events, &l.ingest, 2 * l.checkpoint_period + 60);
                r.problems.extend(problems);
                r.warnings.extend(warnings);
            }
            println!(
                "{} checkpoints, {} entries: {} registrations, {} ballots, {} refusals ({} summed up, {} not judged again), {} tallies",
                r.checkpoints, r.entries, r.registrations, r.ballots, r.rejects + r.unlisted, r.summarized, r.unjudged + r.unlisted, r.tallies
            );
            for w in &r.warnings {
                println!("warning: {w}");
            }
            for p in &r.problems {
                println!("PROBLEM: {p}");
            }
            if !r.problems.is_empty() {
                std::process::exit(1);
            }
        }
    }
    Ok(())
}

fn isoloir_stamps_calendars() -> Vec<String> {
    isoloir_server::stamps_calendars()
}
