use std::collections::HashMap;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpListener;
use std::sync::{Arc, Mutex};

use isoloir_stamps::{
    Attestation, BlockHeader, BlockHeaders, Client, Error, Item, MAGIC, Op, Ots, Result,
    attestations, is_complete, verify,
};
use sha2::{Digest, Sha256};

const HELLO_WORLD: &[u8] = include_bytes!("fixtures/hello-world.txt.ots");
const INCOMPLETE: &[u8] = include_bytes!("fixtures/incomplete.txt.ots");
const MERKLE1: &[u8] = include_bytes!("fixtures/merkle1.txt.ots");
const TWO_CALENDARS: &[u8] = include_bytes!("fixtures/two-calendars.txt.ots");
const KNOWN_UNKNOWN: &[u8] = include_bytes!("fixtures/known-and-unknown-notary.txt.ots");
const BAD_STAMP: &[u8] = include_bytes!("fixtures/bad-stamp.txt.ots");
const HELLO_TXT: &[u8] = include_bytes!("fixtures/hello-world.txt");
const HEADER_358391: &str = include_str!("fixtures/block-358391.header.hex");

fn sha256(b: &[u8]) -> [u8; 32] {
    Sha256::digest(b).into()
}

/// Headers from a map.
struct Fixed(HashMap<u64, BlockHeader>);

impl BlockHeaders for Fixed {
    fn header(&self, height: u64) -> Result<BlockHeader> {
        self.0.get(&height).copied().ok_or(Error::BlockHeader {
            height,
            reason: "unknown".into(),
        })
    }
}

fn block_358391() -> Fixed {
    let raw = hex::decode(HEADER_358391.trim()).unwrap();
    Fixed(HashMap::from([(
        358391,
        BlockHeader::from_raw(&raw).unwrap(),
    )]))
}

// ---- the format ------------------------------------------------------------

#[test]
fn real_files_round_trip_byte_for_byte() {
    for (name, file) in [
        ("hello-world", HELLO_WORLD),
        ("incomplete", INCOMPLETE),
        ("merkle1", MERKLE1),
        ("two-calendars", TWO_CALENDARS),
        ("known-and-unknown-notary", KNOWN_UNKNOWN),
        ("bad-stamp", BAD_STAMP),
    ] {
        let ots = Ots::parse(file).unwrap_or_else(|e| panic!("{name}: {e}"));
        assert_eq!(ots.to_bytes(), file, "{name}");
    }
}

#[test]
fn real_files_attestations() {
    let hello = Ots::parse(HELLO_WORLD).unwrap();
    assert_eq!(hello.digest(), sha256(HELLO_TXT));
    assert!(is_complete(&hello));
    let atts = attestations(&hello);
    assert_eq!(atts.len(), 1);
    assert_eq!(
        *atts[0].attestation,
        Attestation::Bitcoin { height: 358391 }
    );

    let incomplete = Ots::parse(INCOMPLETE).unwrap();
    assert!(!incomplete.is_complete());
    let atts = incomplete.attestations();
    assert_eq!(atts.len(), 1);
    assert_eq!(
        *atts[0].attestation,
        Attestation::Pending {
            uri: "https://alice.btc.calendar.opentimestamps.org".into()
        }
    );

    let two = Ots::parse(TWO_CALENDARS).unwrap();
    let uris: Vec<_> = two
        .attestations()
        .iter()
        .filter_map(|a| match a.attestation {
            Attestation::Pending { uri } => Some(uri.clone()),
            _ => None,
        })
        .collect();
    assert_eq!(
        uris,
        [
            "https://alice.btc.calendar.opentimestamps.org",
            "https://bob.btc.calendar.opentimestamps.org"
        ]
    );

    let unknown = Ots::parse(KNOWN_UNKNOWN).unwrap();
    assert!(unknown.attestations().iter().any(|a| matches!(
        a.attestation,
        Attestation::Unknown { tag, payload } if *tag == [1, 2, 3, 4, 5, 6, 7, 8] && payload.len() == 46
    )));
}

#[test]
fn malformed_files_are_refused() {
    assert!(matches!(Ots::parse(b"not a proof"), Err(Error::BadMagic)));
    assert!(matches!(
        Ots::parse(&HELLO_WORLD[..HELLO_WORLD.len() - 1]),
        Err(Error::Truncated)
    ));
    let mut extra = HELLO_WORLD.to_vec();
    extra.push(0);
    assert!(matches!(Ots::parse(&extra), Err(Error::TrailingBytes(1))));
    let mut v2 = HELLO_WORLD.to_vec();
    v2[MAGIC.len()] = 2;
    assert!(matches!(Ots::parse(&v2), Err(Error::UnsupportedVersion(2))));
    let mut sha1 = HELLO_WORLD.to_vec();
    sha1[MAGIC.len() + 1] = 0x02;
    assert!(matches!(
        Ots::parse(&sha1),
        Err(Error::UnsupportedFileHash(0x02))
    ));
    // An unknown operation.
    let mut bad = ots_prefix(&[7; 32]);
    bad.push(0x55);
    assert!(Ots::parse(&bad).is_err());
    // A calendar URI outside the allowed characters.
    let mut bad = ots_prefix(&[7; 32]);
    bad.extend(pending("https://evil.example/?x=1"));
    assert!(Ots::parse(&bad).is_err());
}

// ---- verification ----------------------------------------------------------

#[test]
fn verify_against_a_known_block() {
    let hello = Ots::parse(HELLO_WORLD).unwrap();
    let got = verify(&hello, sha256(HELLO_TXT), &block_358391()).unwrap();
    assert_eq!(got, vec![(358391, 1432827678)]);
}

#[test]
fn verify_refuses_wrong_digest_wrong_root_and_pending() {
    let hello = Ots::parse(HELLO_WORLD).unwrap();
    // Another digest.
    let e = verify(&hello, sha256(b"other"), &block_358391()).unwrap_err();
    assert!(matches!(e, Error::DigestMismatch { .. }), "{e}");
    // bad-stamp.txt.ots claims block 358391 for another digest: its path
    // does not lead to the block's Merkle root.
    let bad = Ots::parse(BAD_STAMP).unwrap();
    let e = verify(&bad, bad.digest(), &block_358391()).unwrap_err();
    assert!(
        matches!(e, Error::MerkleRootMismatch { height: 358391, .. }),
        "{e}"
    );
    // A wrong header for the height.
    let mut raw = hex::decode(HEADER_358391.trim()).unwrap();
    raw[40] ^= 1;
    let wrong = Fixed(HashMap::from([(
        358391,
        BlockHeader::from_raw(&raw).unwrap(),
    )]));
    assert!(matches!(
        verify(&hello, hello.digest(), &wrong),
        Err(Error::MerkleRootMismatch { .. })
    ));
    // A pending proof.
    let inc = Ots::parse(INCOMPLETE).unwrap();
    assert!(matches!(
        verify(&inc, inc.digest(), &block_358391()),
        Err(Error::NoBitcoinAttestation)
    ));
}

// ---- hand-built proofs and a local calendar --------------------------------

fn varuint(mut v: u64) -> Vec<u8> {
    let mut w = Vec::new();
    while v >= 0x80 {
        w.push((v as u8) | 0x80);
        v >>= 7;
    }
    w.push(v as u8);
    w
}

fn varbytes(b: &[u8]) -> Vec<u8> {
    [varuint(b.len() as u64), b.to_vec()].concat()
}

fn ots_prefix(digest: &[u8; 32]) -> Vec<u8> {
    [MAGIC, &[0x01, 0x08], digest].concat()
}

fn pending(uri: &str) -> Vec<u8> {
    [
        &[0x00][..],
        &[0x83, 0xdf, 0xe3, 0x0d, 0x2e, 0xf9, 0x0c, 0x8e],
        &varbytes(&varbytes(uri.as_bytes())),
    ]
    .concat()
}

fn bitcoin(height: u64) -> Vec<u8> {
    [
        &[0x00][..],
        &[0x05, 0x88, 0x96, 0x0d, 0x73, 0xd7, 0x19, 0x01],
        &varbytes(&varuint(height)),
    ]
    .concat()
}

/// prepend `arg`, sha256, Bitcoin attestation at `height`: what a calendar
/// serves once confirmed.
fn continuation(arg: &[u8], height: u64) -> Vec<u8> {
    [&[0xf1][..], &varbytes(arg), &[0x08], &bitcoin(height)].concat()
}

struct Calendar {
    url: String,
    /// The requests: method and path.
    requests: Arc<Mutex<Vec<(String, String)>>>,
}

/// A calendar on localhost answering with `answer(method, path, body)`
/// (status and body).
fn calendar(answer: impl Fn(&str, &str, &[u8]) -> (u16, Vec<u8>) + Send + 'static) -> Calendar {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    let requests = Arc::new(Mutex::new(Vec::new()));
    let log = requests.clone();
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { continue };
            let mut reader = BufReader::new(stream.try_clone().unwrap());
            let mut line = String::new();
            if reader.read_line(&mut line).is_err() {
                continue;
            }
            let mut parts = line.split_whitespace();
            let method = parts.next().unwrap_or("").to_string();
            let path = parts.next().unwrap_or("").to_string();
            let mut len = 0;
            loop {
                let mut h = String::new();
                reader.read_line(&mut h).unwrap();
                if h.trim().is_empty() {
                    break;
                }
                if let Some((k, v)) = h.split_once(':')
                    && k.eq_ignore_ascii_case("content-length")
                {
                    len = v.trim().parse().unwrap();
                }
            }
            let mut body = vec![0; len];
            reader.read_exact(&mut body).unwrap();
            log.lock().unwrap().push((method.clone(), path.clone()));
            let (status, out) = answer(&method, &path, &body);
            let head = format!(
                "HTTP/1.1 {status} X\r\nContent-Length: {}\r\nContent-Type: application/octet-stream\r\nConnection: close\r\n\r\n",
                out.len()
            );
            let _ = stream.write_all(head.as_bytes());
            let _ = stream.write_all(&out);
        }
    });
    Calendar { url, requests }
}

#[test]
fn submit_merges_the_calendars_answers() {
    let digest = sha256(b"checkpoint");
    let a = calendar(move |m, p, body| {
        assert_eq!((m, p), ("POST", "/digest"));
        assert_eq!(body, digest);
        (
            200,
            [
                &[0xf0][..],
                &varbytes(b"aa"),
                &[0x08],
                &pending("https://a.example"),
            ]
            .concat(),
        )
    });
    let b = calendar(|_, _, _| {
        (
            200,
            [
                &[0xf0][..],
                &varbytes(b"bb"),
                &[0x08],
                &pending("https://b.example"),
            ]
            .concat(),
        )
    });
    let down = calendar(|_, _, _| (500, vec![]));
    let ots = Client::default()
        .submit(digest, &[a.url.clone(), down.url.clone(), b.url.clone()])
        .unwrap();
    assert_eq!(ots.digest(), digest);
    assert_eq!(ots.timestamp().items().len(), 2);
    let atts = ots.attestations();
    assert_eq!(atts.len(), 2);
    assert_eq!(atts[0].commitment, sha256(&[&digest[..], b"aa"].concat()));
    assert_eq!(atts[1].commitment, sha256(&[&digest[..], b"bb"].concat()));
    // The merged file is a valid proof.
    let bytes = ots.to_bytes();
    assert_eq!(Ots::parse(&bytes).unwrap(), ots);
    assert_eq!(down.requests.lock().unwrap().len(), 1);

    // No calendar answered.
    let e = Client::default()
        .submit(digest, std::slice::from_ref(&down.url))
        .unwrap_err();
    assert!(matches!(e, Error::Calendars(ref v) if v.len() == 1), "{e}");
}

/// Two branches pending at two calendars; only one has the Bitcoin part.
/// The upgraded branch gets it, the other branch stays as it was (the Go
/// version dropped branches here).
#[test]
fn upgrade_splices_one_branch_and_keeps_the_other() {
    let digest = sha256(b"checkpoint");
    let ca = sha256(&[&digest[..], b"aa"].concat());
    let cb = sha256(&[&digest[..], b"bb"].concat());
    let a = calendar(move |m, p, _| {
        assert_eq!(
            (m, p.to_string()),
            ("GET", format!("/timestamp/{}", hex::encode(ca)))
        );
        (200, continuation(b"cd", 9))
    });
    let b = calendar(|_, _, _| (404, b"Pending confirmation in Bitcoin blockchain".to_vec()));
    let file = [
        ots_prefix(&digest),
        vec![0xff, 0xf0],
        varbytes(b"aa"),
        vec![0x08],
        pending(&a.url),
        vec![0xf0],
        varbytes(b"bb"),
        vec![0x08],
        pending(&b.url),
    ]
    .concat();
    let ots = Ots::parse(&file).unwrap();
    assert!(!ots.is_complete());

    let (up, changed) = Client::default().upgrade(&ots).unwrap();
    assert!(changed);
    assert!(up.is_complete());
    // The input is untouched.
    assert_eq!(ots.to_bytes(), file);
    let atts = up.attestations();
    assert_eq!(atts.len(), 2);
    let root9 = sha256(&[&b"cd"[..], &ca].concat());
    assert_eq!(*atts[0].attestation, Attestation::Bitcoin { height: 9 });
    assert_eq!(atts[0].commitment, root9);
    assert_eq!(
        *atts[1].attestation,
        Attestation::Pending { uri: b.url.clone() }
    );
    assert_eq!(atts[1].commitment, cb);
    // Byte for byte: the pending attestation of a became the continuation.
    let want = [
        ots_prefix(&digest),
        vec![0xff, 0xf0],
        varbytes(b"aa"),
        vec![0x08],
        continuation(b"cd", 9),
        vec![0xf0],
        varbytes(b"bb"),
        vec![0x08],
        pending(&b.url),
    ]
    .concat();
    assert_eq!(up.to_bytes(), want);
    let headers = Fixed(HashMap::from([(
        9,
        BlockHeader {
            merkle_root: root9,
            time: 1234,
        },
    )]));
    assert_eq!(verify(&up, digest, &headers).unwrap(), vec![(9, 1234)]);

    // Upgrading again asks b only and changes nothing.
    let asked_a = a.requests.lock().unwrap().len();
    let (again, changed) = Client::default().upgrade(&up).unwrap();
    assert!(!changed);
    assert_eq!(again, up);
    assert_eq!(a.requests.lock().unwrap().len(), asked_a);
}

/// Two pending attestations at the same node (the Go test's shape), and a
/// sibling branch already on Bitcoin: one calendar upgrades, the other has
/// nothing yet.
#[test]
fn upgrade_at_one_node_with_two_calendars() {
    let digest = sha256(b"checkpoint");
    let a = calendar(|_, _, _| (200, continuation(b"cd", 9)));
    let b = calendar(|_, _, _| (404, vec![]));
    let file = [
        ots_prefix(&digest),
        vec![0xff],
        pending(&a.url),
        vec![0xff],
        pending(&b.url),
        vec![0xf0],
        varbytes(b"ab"),
        vec![0x08],
        bitcoin(7),
    ]
    .concat();
    let ots = Ots::parse(&file).unwrap();
    let (up, changed) = Client::default().upgrade(&ots).unwrap();
    assert!(changed);
    let kinds: Vec<_> = up
        .attestations()
        .iter()
        .map(|a| a.attestation.clone())
        .collect();
    assert_eq!(
        kinds,
        [
            Attestation::Pending { uri: b.url.clone() },
            Attestation::Bitcoin { height: 7 },
            Attestation::Bitcoin { height: 9 },
        ]
    );
    // The spliced operations join the root.
    assert!(
        up.timestamp()
            .items()
            .iter()
            .any(|i| matches!(i, Item::Op(Op::Prepend(arg), _) if arg == b"cd"))
    );
    assert_eq!(Ots::parse(&up.to_bytes()).unwrap(), up);
}

#[test]
fn upgrade_not_yet_errors_and_allow_list() {
    let digest = sha256(b"checkpoint");
    // 404 everywhere: unchanged, no error.
    let none = calendar(|_, _, _| (404, vec![]));
    let file = [ots_prefix(&digest), pending(&none.url)].concat();
    let ots = Ots::parse(&file).unwrap();
    let (same, changed) = Client::default().upgrade(&ots).unwrap();
    assert!(!changed);
    assert_eq!(same.to_bytes(), file);

    // An answer still pending is not spliced.
    let still = calendar(|_, _, _| {
        (
            200,
            [&[0xf1][..], &varbytes(b"cd"), &pending("https://x.example")].concat(),
        )
    });
    let file = [ots_prefix(&digest), pending(&still.url)].concat();
    let (same, changed) = Client::default()
        .upgrade(&Ots::parse(&file).unwrap())
        .unwrap();
    assert!(!changed);
    assert_eq!(same.to_bytes(), file);

    // A failing calendar with nothing upgraded is an error.
    let broken = calendar(|_, _, _| (500, vec![]));
    let file = [ots_prefix(&digest), pending(&broken.url)].concat();
    assert!(matches!(
        Client::default().upgrade(&Ots::parse(&file).unwrap()),
        Err(Error::Calendars(_))
    ));

    // A failing calendar beside an upgraded branch: the upgrade is kept.
    let good = calendar(|_, _, _| (200, continuation(b"cd", 9)));
    let file = [
        ots_prefix(&digest),
        vec![0xff],
        pending(&broken.url),
        pending(&good.url),
    ]
    .concat();
    let (up, changed) = Client::default()
        .upgrade(&Ots::parse(&file).unwrap())
        .unwrap();
    assert!(changed && up.is_complete());

    // A calendar outside the allow list is not asked.
    let (same, changed) = Client::default()
        .allow_only(&["https://a.pool.opentimestamps.org".into()])
        .upgrade(&Ots::parse(&file).unwrap())
        .unwrap();
    assert!(!changed);
    assert_eq!(same.to_bytes(), file);
}

// ---- the network -----------------------------------------------------------

#[test]
#[ignore = "network: blockstream.info / mempool.space"]
fn esplora_headers() {
    let h = isoloir_stamps::Esplora::default().header(358391).unwrap();
    assert_eq!(h, block_358391().0[&358391]);
    let mempool = isoloir_stamps::Esplora::new(vec!["https://mempool.space/api".into()]);
    assert_eq!(mempool.header(358391).unwrap(), h);
    let hello = Ots::parse(HELLO_WORLD).unwrap();
    assert_eq!(
        verify(&hello, hello.digest(), &isoloir_stamps::Esplora::default()).unwrap(),
        vec![(358391, 1432827678)]
    );
}

#[test]
#[ignore = "network: the public calendars"]
fn submit_to_the_public_calendars() {
    let digest =
        sha256(format!("isoloir-stamps test {:?}", std::time::SystemTime::now()).as_bytes());
    let ots = isoloir_stamps::submit(digest, &isoloir_stamps::default_calendars()).unwrap();
    assert!(!ots.attestations().is_empty());
    assert_eq!(Ots::parse(&ots.to_bytes()).unwrap(), ots);
    let (_, changed) = isoloir_stamps::upgrade(&ots).unwrap();
    assert!(!changed);
}
