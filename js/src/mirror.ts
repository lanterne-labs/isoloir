// The mirror (SPEC §15): the static files the browser reads instead of
// asking the operator anything. Every checkpoint note is verified under
// the pinned verifier key before anything it names is trusted; files are
// read at the checkpoint's commit (its `mirror` token) where a source
// serves by commit, so a reader can prove which files it was served.
//
// File formats this reader expects (the ingest writes them):
//   checkpoint.txt, checkpoints/<i>.txt   a signed note
//   entries/<i>.json                       [{seq, kind, body}], body the logged text (or its JSON)
//   setup/ledger.json                      {seq, body}
//   registries/<id>.json, polls/<id>.json  {setups: [{seq, body}, …]}: every version, the last in force
//                                          (a bare {seq, body}, or the body alone, are read too)
//   registries/<id>/leaves/<k>.json        ["0x…", …] leaves 1024·k … 1024·k+1023
//   registries/<id>/positions/<pp>.json    {"0x<leaf>": position}, pp the leaf's first two hex digits
//   polls/<id>/pseudonyms/<pp>.json        {"0x<nullifier>": last seq}
//   polls/<id>/ballots/<k>.json            ["0x…", …] ballot tree leaves, 1024 per file
//   polls/<id>/tallies/latest.json         {seq, body} (or the bare body)
//   circuits/<name>/artifact.json          the compiled Noir circuit

import { IsoloirError } from './errors.js';
import type { Checkpoint, Entry, Setup } from './types.js';
import type { Core } from './wasm.js';

export const SHARD = 1024;

export interface FetchResponse {
	status: number;
	ok: boolean;
	text(): Promise<string>;
}

export type Fetcher = (url: string, init?: { cache?: string; credentials?: string }) => Promise<FetchResponse>;

export interface MirrorSource {
	/** The address of a path at a commit token ('' for the latest files). */
	url(path: string, token: string): string;
	/** Whether the source honours tokens (a git repository read by commit). */
	byCommit: boolean;
}

/** A directory of the latest files (a static host). */
export function dirSource(base: string): MirrorSource {
	const b = base.replace(/\/$/, '');
	return { url: (path) => `${b}/${path}`, byCommit: false };
}

/** A GitHub repository read through jsDelivr by commit. */
export function jsDelivrSource(repo: string, branch = 'main'): MirrorSource {
	return { url: (path, token) => `https://cdn.jsdelivr.net/gh/${repo}@${token || branch}/${path}`, byCommit: true };
}

interface Attempt {
	source: MirrorSource;
	token: string;
}

export class Mirror {
	private readonly fetcher: Fetcher;
	private readonly notes = new Map<number, Checkpoint>();

	constructor(
		private readonly core: Core,
		private readonly sources: MirrorSource[],
		private readonly verifierKey: string,
		fetcher?: Fetcher
	) {
		if (sources.length === 0) throw new IsoloirError('no_setup', 'no mirror source');
		this.fetcher = fetcher ?? ((url, init) => fetch(url, init as RequestInit));
	}

	private attempts(token: string): Attempt[] {
		const out: Attempt[] = [];
		if (token) for (const source of this.sources) if (source.byCommit) out.push({ source, token });
		for (const source of this.sources) out.push({ source, token: '' });
		return out;
	}

	/** A file's text, or null when no source has it; throws mirror when every source failed. */
	async text(path: string, token = ''): Promise<string | null> {
		let lastErr: unknown = null;
		let missing = false;
		for (const a of this.attempts(token)) {
			try {
				const res = await this.fetcher(a.source.url(path, a.token), { credentials: 'omit', cache: a.token ? 'force-cache' : 'no-cache' });
				if (res.status === 404) {
					missing = true;
					continue;
				}
				if (!res.ok) throw new Error(`HTTP ${res.status}`);
				return await res.text();
			} catch (e) {
				lastErr = e;
			}
		}
		if (missing || !lastErr) return null;
		throw new IsoloirError('mirror', `${path}: ${lastErr instanceof Error ? lastErr.message : String(lastErr)}`);
	}

	async json<T>(path: string, token = ''): Promise<T | null> {
		const t = await this.text(path, token);
		if (t === null) return null;
		try {
			return JSON.parse(t) as T;
		} catch {
			throw new IsoloirError('mirror', `${path}: not JSON`);
		}
	}

	/** Verifies a note under the pinned key; throws log_key when it does not hold. */
	verify(note: string): Checkpoint {
		let c: Checkpoint;
		try {
			c = this.core.verifyNote(note, this.verifierKey);
		} catch (e) {
			throw new IsoloirError('log_key', e instanceof Error ? e.message : String(e));
		}
		this.notes.set(c.index, c);
		return c;
	}

	/** The newest checkpoint, verified. */
	async latest(): Promise<Checkpoint | null> {
		const note = await this.text('checkpoint.txt');
		return note === null ? null : this.verify(note);
	}

	/** Checkpoint i, verified (kept once read). */
	async checkpoint(index: number, token = ''): Promise<Checkpoint | null> {
		const held = this.notes.get(index);
		if (held) return held;
		const note = await this.text(`checkpoints/${index}.txt`, token);
		if (note === null) return null;
		const c = this.verify(note);
		if (c.index !== index) throw new IsoloirError('mirror', `checkpoints/${index}.txt holds checkpoint ${c.index}`);
		return c;
	}

	/** The entries of checkpoint i, null while the mirror has none. */
	async entries(index: number, token = ''): Promise<Entry[] | null> {
		const list = await this.json<{ seq: number; kind: string; body: unknown }[]>(`entries/${index}.json`, token);
		if (list === null) return null;
		return list.map((e) => ({ seq: e.seq, kind: e.kind, body: typeof e.body === 'string' ? e.body : this.core.canonical(e.body) }));
	}

	/** A setup file (SPEC §15): its body, checked by the wasm core, and its seq. */
	async setup<T>(path: string, kind: string, token = ''): Promise<Setup<T> | null> {
		let raw = await this.json<Record<string, unknown>>(path, token);
		if (raw === null) return null;
		if (Array.isArray(raw.setups)) {
			const last = raw.setups[raw.setups.length - 1] as Record<string, unknown> | undefined;
			if (!last) return null;
			raw = last;
		}
		const wrapped = 'body' in raw && !('v' in raw);
		const inner = wrapped ? raw.body : raw;
		const text = typeof inner === 'string' ? inner : this.core.canonical(inner);
		let body: T;
		try {
			body = this.core.decodeBody<T>(kind, text);
		} catch (e) {
			throw new IsoloirError('no_setup', `${path}: ${e instanceof Error ? e.message : String(e)}`);
		}
		const seq = wrapped && typeof raw.seq === 'number' ? raw.seq : null;
		return { seq, body, text };
	}

	/** The first `size` leaves of a sharded tree file set. */
	async leaves(dir: string, size: number, token = ''): Promise<string[]> {
		const out: string[] = [];
		for (let k = 0; k * SHARD < size; k++) {
			const shard = await this.json<string[]>(`${dir}/${k}.json`, token);
			if (!shard) throw new IsoloirError('no_path', `${dir}/${k}.json missing`);
			out.push(...shard);
		}
		if (out.length < size) throw new IsoloirError('no_path', `${dir}: ${out.length} leaves, the checkpoint names ${size}`);
		return out.slice(0, size);
	}

	/** A leaf's position in a registry, from its shard. */
	async position(registry: number, leaf: string, token = ''): Promise<number | null> {
		const shard = await this.json<Record<string, number>>(`registries/${registry}/positions/${leaf.slice(2, 4)}.json`, token);
		return shard?.[leaf] ?? null;
	}

	/** The last seq a pseudonym cast in a linked poll. */
	async pseudonymSeq(poll: number, nullifier: string, token = ''): Promise<number | null> {
		const shard = await this.json<Record<string, number>>(`polls/${poll}/pseudonyms/${nullifier.slice(2, 4)}.json`, token);
		return shard?.[nullifier] ?? null;
	}

	/** The latest tally's body text. */
	async latestTally(poll: number, token = ''): Promise<string | null> {
		const text = await this.text(`polls/${poll}/tallies/latest.json`, token);
		if (text === null) return null;
		const t = text.trim();
		const v = JSON.parse(t) as Record<string, unknown>;
		if ('v' in v) return t;
		if (typeof v.body === 'string') return v.body;
		return this.core.canonical(v.body);
	}
}
