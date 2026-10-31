#!/usr/bin/env python3
"""Generates the circuit of each ballot variant (SPEC §9.1).

A variant is a kind and its slot count (choiceM, rankedM, rankedmM), a
decryption mode, a re-vote mode (linked, which also serves "none", or
delta), the registry depth and, for delta, the ballot tree depth. The
decryption mode decides how ballots are packed (SPEC §7.1): `single`
(ElGamal, one authority, who may open each ballot: seven values per
chunk), `threshold` (ElGamal decrypted by aggregate only: two values per
chunk), `tlock` (a commitment to the values). Each variant is a small
Noir binary in build/<name>/ calling the library in lib/. The name says
everything: choice4_single_linked_d20, ranked12_single_delta_d20_b22,
choice4_tlock_linked_d20.

    gen.py NAME...          writes those variants
    gen.py --defaults       writes the default set
"""
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
K = 3  # the depth of a ranking

DEFAULTS = [
    "choice4_single_linked_d20",
    "choice4_single_delta_d20_b22",
    "choice4_tlock_linked_d20",
    "choice16_single_linked_d20",
    "choice16_single_delta_d20_b22",
    "ranked12_single_linked_d20",
    "ranked12_single_delta_d20_b22",
    "rankedm12_single_linked_d20",
]

# Values per chunk, by decryption mode (0: no packing).
PER_CHUNK = {"single": 7, "threshold": 2, "tlock": 0}

NAME = re.compile(r"^(choice|ranked|rankedm)(\d+)_(single|threshold|tlock)_(linked|delta)_d(\d+)(?:_b(\d+))?$")


def parse(name):
    m = NAME.match(name)
    if not m:
        raise SystemExit(f"{name}: not a variant name")
    kind, slots, mode, revote, d, bd = m.groups()
    slots, d = int(slots), int(d)
    if not 2 <= slots <= 32:
        raise SystemExit(f"{name}: 2 to 32 slots")
    if mode == "tlock" and (kind != "choice" or revote != "linked"):
        raise SystemExit(f"{name}: tlock is for single-choice kinds with one ballot per voter only (SPEC §8)")
    if (revote == "delta") != (bd is not None):
        raise SystemExit(f"{name}: a ballot tree depth with delta, and only then")
    enc = "tlock" if mode == "tlock" else "elgamal"
    return dict(kind=kind, m=slots, enc=enc, revote=revote, d=d, bd=int(bd) if bd else None, per=PER_CHUNK[mode])


def values(kind, m):
    if kind == "choice":
        return m
    if kind == "ranked":
        return 2 * m
    return 2 * m + m * (m - 1) // 2


def main_nr(v):
    kind, m, enc, revote, d, bd, per = v["kind"], v["m"], v["enc"], v["revote"], v["d"], v["bd"], v["per"]
    nv = values(kind, m)
    nc = (nv + per - 1) // per if per else 0
    ranked = kind != "choice"
    pub = ["registry: pub Field", "poll: pub Field", "setup: pub Field", "mask: pub u32"]
    if ranked:
        pub.append("blank: pub u32")
    pub.append("root: pub Field")
    if revote == "linked":
        pub += ["nullifier: pub Field", "seq: pub u32"]
    else:
        pub += ["ident: pub Field", "broot: pub Field", "cmt: pub Field"]
    if enc == "elgamal":
        pub += ["pk_x: pub Field", "pk_y: pub Field"]
    else:
        pub += ["vcmt: pub Field", "bhash: pub Field"]
    priv = ["s: Field", f"path: [Field; {d}]", "index: u32"]
    priv += ["len: u32", f"slots: [u32; {K}]"] if ranked else ["pick: u32"]
    if revote == "delta":
        priv += ["i: u32"]
        priv += ["old_len: u32", f"old_slots: [u32; {K}]"] if ranked else ["old_pick: u32"]
        priv += [f"bpath: [Field; {bd}]", "bindex: u32"]
    priv += [f"rho: [Field; {nc}]"] if enc == "elgamal" else ["salt: Field"]
    ret = f" -> pub [Field; {4 * nc}]" if enc == "elgamal" else ""

    def vals(prefix):
        if kind == "choice":
            return f"isoloir::choice_values::<{m}>({prefix}pick, mask)"
        fn = "ranked_values" if kind == "ranked" else "ranked_margin_values"
        return (f"isoloir::{fn}::<{m}, {K}, {nv}>({prefix}len, {prefix}slots, "
                f"isoloir::ranks::<{m}, {K}>({prefix}len, {prefix}slots, mask, blank))")

    def choice_hash(prefix):
        if kind == "choice":
            return f"isoloir::hn([{prefix}pick as Field])"
        return (f"isoloir::hn([{prefix}len as Field, {prefix}slots[0] as Field, "
                f"{prefix}slots[1] as Field, {prefix}slots[2] as Field])")

    body = ["    isoloir::member(registry, s, path, index, root);"]
    if revote == "linked":
        body += ["    assert(nullifier == isoloir::nullifier(poll, s));",
                 "    let _ = (setup, seq);",
                 f"    let v: [Field; {nv}] = {vals('')};"]
    else:
        body += ["    let _ = setup;",
                 f"    let has_old = isoloir::chain(poll, s, i, ident, cmt, {choice_hash('')}, {choice_hash('old_')}, bpath, bindex, broot);",
                 f"    let new: [Field; {nv}] = {vals('')};",
                 f"    let old: [Field; {nv}] = {vals('old_')};",
                 "    let v = isoloir::correction(new, old, has_old);"]
    if enc == "elgamal":
        body.append(f"    isoloir::encrypt::<{nc}, {4 * nc}>(isoloir::pack::<{nv}, {nc}, {per}>(v), rho, pk_x, pk_y)")
    else:
        body.append("    let _ = bhash;")
        body.append("    assert(vcmt == isoloir::commit(salt, v));")
    sig = ",\n    ".join(pub + priv)
    return (f"// {v['name']}: generated by circuits/gen.py from lib/ (SPEC §9.1); do not edit.\n"
            f"// {values(kind, m)} values, {nc} chunks.\n\n"
            f"fn main(\n    {sig},\n){ret} {{\n" + "\n".join(body) + "\n}\n")


def write(name):
    v = parse(name)
    v["name"] = name
    out = os.path.join(HERE, "build", name)
    os.makedirs(os.path.join(out, "src"), exist_ok=True)
    with open(os.path.join(out, "Nargo.toml"), "w") as f:
        f.write(f'[package]\nname = "{name}"\ntype = "bin"\nauthors = ["isoloir"]\ncompiler_version = ">=1.0.0"\n\n'
                f'[dependencies]\nisoloir = {{ path = "../../lib" }}\n')
    with open(os.path.join(out, "src", "main.nr"), "w") as f:
        f.write(main_nr(v))
    print(out)


if __name__ == "__main__":
    names = DEFAULTS if sys.argv[1:] == ["--defaults"] else sys.argv[1:]
    if not names:
        raise SystemExit(__doc__)
    for n in names:
        write(n)
