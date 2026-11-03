// The mirror (SPEC §15): the static files the browser reads instead of
// asking the operator anything. Every checkpoint note is verified under
// the pinned verifier key before anything it names is trusted; files are
// read at the commit the newest note names (its `mirror` line) where a
// source serves by commit, so a reader can prove which files it was
// served. A note of this version names the newest pushed commit and the
// newest checkpoint it covers (`mirror <commit>:<index>`): the files of a
// later checkpoint wait for a later note (covered()). A note of an earlier
// version names the commit of its own files (`mirror <commit>`).
//
// A setup or a tally is used only once proven in the log: its file names
// the checkpoint c whose log holds it and the RFC 6962 inclusion proof of
// its leaf; c's note is fetched and verified under the pinned key, and
// the proof checked against c's root by the wasm core. A mirror cannot
// serve another ingest key, other channels or another poll key.
//
// File formats this reader expects (the ingest writes them):
//   checkpoint.txt, checkpoints/<i>.txt   a signed note
//   entries/<i>.json                       [{seq, kind, body}], body the logged text (or its JSON)
//   setup/ledger.json, registries/<id>.json, polls/<id>.json
//                                          {setups: [{seq, body, checkpoint, size, path}, …]}: every
//                                          version in order, the last in force
//   registries/<id>/leaves/<k>.json        ["0x…", …] leaves 1024·k … 1024·k+1023
//   polls/<id>/ballots/<k>.json            ["0x…", …] ballot tree leaves, 1024 per file
//   polls/<id>/tallies/latest.json         {seq, body, checkpoint, size, path}
//   circuits/<name>/artifact.json          the compiled Noir circuit

import { IsoloirError } from './errors.js';
import type { Checkpoint, Entry, Logged, Setup } from './types.js';
import type { Core } from './wasm.js';

export const SHARD = 1024;

/**
 * The newest checkpoint whose files a note's commit holds (SPEC §15): the
 * index its `mirror` line names, the note's own index for a note of an
 * earlier version or one without a commit (a directory of the latest
 * files).
 */
export function covered(cp: Checkpoint): number {
	return cp.mirror && cp.mirror_index != null ? Math.min(cp.mirror_index, cp.index) : cp.index;
}

export interface FetchResponse {
	status: number;
	ok: boolean;
	text(): Promise<string>;
}

export type Fetcher = (url: string, init?: { cache?: string; credentials?: string; signal?: AbortSignal }) => Promise<FetchResponse>;

/** A fetch that gives up after `ms`: a hung request never freezes the session. */
export async function withTimeout<T>(ms: number, run: (signal: AbortSignal) => Promise<T>): Promise<T> {
	const ctl = new AbortController();
	let timer: ReturnType<typeof setTimeout> | undefined;
	const timeout = new Promise<never>((_, reject) => {
		timer = setTimeout(() => {
			ctl.abort();
			reject(new Error(`timeout after ${ms} ms`));
		}, ms);
	});
	try {
		return await Promise.race([run(ctl.signal), timeout]);
	} finally {
		clearTimeout(timer);
	}
}

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
		fetcher?: Fetcher,
		private readonly timeoutMs = 15_000
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
				const got = await withTimeout(this.timeoutMs, async (signal) => {
					const res = await this.fetcher(a.source.url(path, a.token), { credentials: 'omit', cache: a.token ? 'force-cache' : 'no-cache', signal });
					if (res.status === 404) return null;
					if (!res.ok) throw new Error(`HTTP ${res.status}`);
					return await res.text();
				});
				if (got === null) {
					missing = true;
					continue;
				}
				return got;
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

	/**
	 * Proves an entry in the log: checkpoint c's note (verified under the
	 * pinned key) has the size the proof is for, and the proof leads from
	 * the entry's leaf to its root. Throws unproven otherwise.
	 */
	async prove(rec: Logged, kind: string, what: string): Promise<Checkpoint> {
		if (!Number.isInteger(rec.seq) || !Number.isInteger(rec.checkpoint) || !Number.isInteger(rec.size) || !Array.isArray(rec.path) || typeof rec.body !== 'string') {
			throw new IsoloirError('unproven', `${what}: no inclusion proof`);
		}
		const cp = await this.checkpoint(rec.checkpoint);
		if (!cp) throw new IsoloirError('unproven', `${what}: checkpoint ${rec.checkpoint} is not on the mirror`);
		if (cp.size !== rec.size) throw new IsoloirError('unproven', `${what}: a proof for ${rec.size} entries, checkpoint ${rec.checkpoint} has ${cp.size}`);
		let ok = false;
		try {
			ok = this.core.verifyLogged(rec.seq, kind, rec.body, rec.path, rec.size, cp.root);
		} catch (e) {
			throw new IsoloirError('unproven', `${what}: ${e instanceof Error ? e.message : String(e)}`);
		}
		if (!ok) throw new IsoloirError('unproven', `${what}: the inclusion proof does not hold`);
		return cp;
	}

	/** A setup file (SPEC §15): its last version, proven in the log, decoded by the wasm core. */
	async setup<T>(path: string, kind: string, token = ''): Promise<Setup<T> | null> {
		const raw = await this.json<{ setups?: Logged[] }>(path, token);
		if (raw === null) return null;
		const last = Array.isArray(raw.setups) ? raw.setups[raw.setups.length - 1] : undefined;
		if (!last) throw new IsoloirError('no_setup', `${path}: no setup`);
		await this.prove(last, kind, path);
		let body: T;
		try {
			body = this.core.decodeBody<T>(kind, last.body);
		} catch (e) {
			throw new IsoloirError('no_setup', `${path}: ${e instanceof Error ? e.message : String(e)}`);
		}
		return { seq: last.seq, body, text: last.body, checkpoint: last.checkpoint };
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

	/** The latest tally: its body text and seq, proven in the log. */
	async latestTally(poll: number, token = ''): Promise<{ seq: number; body: string; checkpoint: number } | null> {
		const path = `polls/${poll}/tallies/latest.json`;
		const rec = await this.json<Logged>(path, token);
		if (rec === null) return null;
		await this.prove(rec, 'tally', path);
		return { seq: rec.seq, body: rec.body, checkpoint: rec.checkpoint };
	}
}
