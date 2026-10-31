//! `isoloir`: run a ledger. See README.md for the order of operations.

use anyhow::{bail, Context, Result};
use clap::{Parser, Subcommand};
use isoloir_decrypt::keys::DecrypterKeys;
use isoloir_decrypt::tlock::DrandTlock;
use isoloir_proto::audit::Auditor;
use isoloir_proto::body::{self, Body, EntryKind, RelayState};
use isoloir_proto::judge::Checkers;
use isoloir_proto::note;
use isoloir_relay::Pool;
use isoloir_server::eligibility::Verifiers;
use isoloir_server::ingest::{Config, Ingest};
use isoloir_server::mirror::Mirror;
use isoloir_server::relays::{self, PoolTransport};
use isoloir_server::source::{LogSource, MirrorSource};
use isoloir_server::store::Store;
use isoloir_server::trustee::{Keys, Output, Trustee};
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
        /// Variant names (circuits/gen.py), e.g. choice4_elgamal_linked_d20.
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
    },
    /// Runs a trustee: verifies the log, publishes the tallies due.
    Trustee {
        /// The log: a mirror directory or URL.
        #[arg(long)]
        mirror: String,
        #[arg(long)]
        log_key: String,
        /// The decrypter's keys (keygen decrypter); absent: tlock polls only.
        #[arg(long)]
        keys: Option<PathBuf>,
        /// A drand HTTP API, for tlock polls.
        #[arg(long, default_value = "https://api.drand.sh")]
        drand: String,
        /// Post the tallies to the ingest's database instead of the relays.
        #[arg(long, env = "DATABASE_URL")]
        db: Option<String>,
        #[arg(long, env = "ISOLOIR_NOSTR_KEY", hide_env_values = true)]
        nostr_key: Option<String>,
        #[arg(long, default_value_t = 20)]
        every: u64,
        #[arg(long)]
        once: bool,
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
        /// Also read the ledger's relays: withholding.
        #[arg(long)]
        relays: bool,
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
    /// A Nostr key (the ingest's): prints the secret and the public key.
    Nostr,
    /// A decrypter's keys, written to a file; prints the public half.
    Decrypter {
        #[arg(long)]
        out: PathBuf,
    },
}

fn now() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).expect("clock").as_secs()
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
        Cmd::Keygen(Keygen::Nostr) => {
            let mut s = [0u8; 32];
            rand::rngs::OsRng.fill_bytes(&mut s);
            println!("ISOLOIR_NOSTR_KEY={}", hex::encode(s));
            println!("ingest: {}", hex::encode(isoloir_proto::sig::xonly(&s)));
        }
        Cmd::Keygen(Keygen::Decrypter { out }) => {
            if out.exists() {
                bail!("{} exists: a decrypter's keys are never overwritten", out.display());
            }
            let k = DecrypterKeys::generate(&mut rand::rngs::OsRng);
            std::fs::write(&out, serde_json::to_vec_pretty(&k)?)?;
            println!("{}", serde_json::to_string_pretty(&k.public())?);
        }
        Cmd::Circuits { names, circuits, mirror } => {
            let tools = Tools::find()?;
            let c = Circuits::new(circuits);
            let m = Mirror { dir: mirror, git: None };
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
            let config = Config { log_seed: seed(&log_seed, "log seed")?, nostr_sk: [0u8; 32] };
            Ingest::genesis(&store, &config, &l, now()).await?;
            println!("ledger {} started", l.origin);
        }
        Cmd::Submit { db, kind, file } => {
            let store = Store::connect(&db).await?;
            let k = EntryKind::parse(&kind).filter(|k| matches!(k, EntryKind::Ledger | EntryKind::Registry | EntryKind::Poll)).context("kind: ledger, registry or poll")?;
            let bytes = canonical_file(&file)?;
            body::decode(k, &bytes).map_err(|r| anyhow::anyhow!("{kind}: {}", r.as_str()))?;
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
            println!("submitted ({id}); not logged yet: is the ingest running?");
        }
        Cmd::Ingest { db, log_seed, nostr_key, mirror_dir, mirror_git, zkverifier, node, rpc_url, dev, no_stamps } => {
            if dev && std::env::var_os("ISOLOIR_PRODUCTION").is_some() {
                bail!("--dev is for local trials");
            }
            let store = Store::connect(&db).await?;
            let _lease = store.lease().await?;
            let entries = store.entries().await?;
            let Some((_, EntryKind::Ledger, first, _)) = entries.first() else { bail!("no ledger: run isoloir genesis first") };
            let Ok(Body::Ledger(l)) = body::decode(EntryKind::Ledger, first) else { bail!("the first entry is not a ledger") };
            let urls: Vec<String> = l.relays.iter().filter(|r| r.state == RelayState::Active).map(|r| r.url.clone()).collect();
            let pool = Pool::connect(urls);
            let transport = Arc::new(PoolTransport { pool: pool.clone() });
            let bb = Tools::find_bb()?;
            let mirror = Mirror { dir: mirror_dir.clone(), git: mirror_git };
            let config = Config { log_seed: seed(&log_seed, "log seed")?, nostr_sk: seed(&nostr_key, "nostr key")? };
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
            let mut rx = relays::subscribe(&pool, &store, ing.tag()).await?;
            tracing::info!(origin = %l.origin, "ingest running");
            let mut tick = tokio::time::interval(Duration::from_secs(1));
            loop {
                tokio::select! {
                    m = rx.recv() => match m {
                        Some(inc) => ing.handle(inc, now()).await?,
                        None => bail!("the relay pool stopped"),
                    },
                    _ = tick.tick() => {
                        if ing.tick(now()).await?.is_some() {
                            relays::save_cursors(&pool, &store).await?;
                        }
                    }
                    _ = tokio::signal::ctrl_c() => {
                        relays::save_cursors(&pool, &store).await?;
                        return Ok(());
                    }
                }
            }
        }
        Cmd::Trustee { mirror, log_key, keys, drand, db, nostr_key, every, once } => {
            let bb = Tools::find_bb()?;
            let vk_dir = if mirror.starts_with("http") { bail!("a trustee reads verification keys from a local mirror copy for now") } else { PathBuf::from(&mirror).join("circuits") };
            let keys = match keys {
                Some(p) => {
                    let k: DecrypterKeys = serde_json::from_slice(&std::fs::read(p)?)?;
                    let (sk, sign_seed) = k.secrets().map_err(|e| anyhow::anyhow!(e))?;
                    Some(Keys { pk: k.pk, sk, sign_seed })
                }
                None => None,
            };
            let output = match (db, nostr_key) {
                (Some(db), _) => Output::Store(Store::connect(&db).await?),
                (None, Some(k)) => {
                    let src = MirrorSource::parse(&mirror);
                    let first = src.from(1).await?.into_iter().next().context("an empty mirror")?;
                    let Some((EntryKind::Ledger, b)) = first.1.first() else { bail!("no ledger entry") };
                    let Ok(Body::Ledger(l)) = body::decode(EntryKind::Ledger, b) else { bail!("ledger") };
                    let pool = Pool::connect(l.relays.iter().filter(|r| r.state == RelayState::Active).map(|r| r.url.clone()).collect());
                    Output::Relays { transport: Arc::new(PoolTransport { pool }), nostr_sk: seed(&k, "nostr key")? }
                }
                (None, None) => bail!("--db or --nostr-key: where tallies go"),
            };
            let mut t = Trustee::new(
                Box::new(MirrorSource::parse(&mirror)),
                Some(&log_key),
                Box::new(BbProofs::new(bb, vk_dir)),
                Box::new(Verifiers { zkpassport: None, rpc_url: None, allow_dev: true }),
                keys,
                Some(drand),
                output,
            )?;
            loop {
                let n = t.step(now()).await?;
                if n > 0 {
                    tracing::info!(n, "tallies published");
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
        Cmd::Audit { mirror, log_key, circuits, zkverifier, node, rpc_url, relays } => {
            let bb = Tools::find_bb()?;
            let vk_dir = circuits.unwrap_or_else(|| PathBuf::from(&mirror).join("circuits"));
            let proofs = BbProofs::new(bb, vk_dir);
            // The dev provider is accepted by an auditor: its registry says
            // so in the log, for everyone to see.
            let passports = passports(zkverifier, node, rpc_url, true);
            let mut a = Auditor::new(log_key.as_deref(), Checkers { proofs: &proofs, passports: &passports, tlock: Some(&DrandTlock) }).map_err(|e| anyhow::anyhow!(e))?;
            for (n, es) in MirrorSource::parse(&mirror).from(1).await? {
                a.checkpoint(&n, &es).map_err(|e| anyhow::anyhow!(e))?;
            }
            let (state, mut r) = a.finish();
            if relays {
                let l = state.ledger().context("no ledger")?.clone();
                let urls: Vec<String> = l.relays.iter().map(|r| r.url.clone()).collect();
                let pool = Pool::connect(urls.clone());
                let tag = format!("{}/{}", isoloir_proto::PROTOCOL, l.origin);
                let mut events = vec![];
                for u in &urls {
                    let f = isoloir_relay::Filter { kinds: vec![7100, 7101, 7102, 7105], t: Some(tag.clone()), ..Default::default() };
                    match pool.fetch(u, f, Duration::from_secs(30)).await {
                        Ok(es) => events.extend(es),
                        Err(e) => r.warnings.push(format!("relay {u}: {e}")),
                    }
                }
                println!("{} events read from {} relays", events.len(), urls.len());
                r.problems.extend(isoloir_proto::audit::check_relays(&state, &events, &l.ingest, 2 * l.checkpoint_period + 60));
            }
            println!("{} checkpoints, {} entries: {} registrations, {} ballots, {} refusals, {} tallies", r.checkpoints, r.entries, r.registrations, r.ballots, r.rejects, r.tallies);
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
