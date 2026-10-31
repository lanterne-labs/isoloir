// What every session test needs: a session on a fake world, a passport
// app, a registered voter whose words are confirmed.

import { afterEach, expect } from 'vitest';
import { Session, type SessionConfig, type StoredKey } from '../src/session.js';
import { MemoryStore } from '../src/storage.js';
import type { PassportProof, RegistrationRequest } from '../src/types.js';
import { core, MIRROR, ORIGIN, StubProver, world } from './fakes.js';

export type World = ReturnType<typeof world>;

const sessions: Session[] = [];
afterEach(() => {
	for (const s of sessions.splice(0)) s.destroy();
});

export function session(w: World, opts: Partial<SessionConfig> = {}): Session {
	const s = new Session({
		core,
		origin: ORIGIN,
		verifierKey: w.ingest.verifier,
		registry: 1,
		poll: 7,
		mirror: MIRROR,
		fetch: w.mirror.fetch,
		channels: w.channels,
		store: new MemoryStore(),
		prover: new StubProver(),
		ackTimeoutMs: 100,
		refreshMs: 0,
		watchRelays: false,
		...opts
	});
	sessions.push(s);
	return s;
}

let uid = 0;
export function passport(seen?: RegistrationRequest[], fixed?: string, date?: () => number) {
	return async (req: RegistrationRequest): Promise<PassportProof> => {
		seen?.push(req);
		return { uid: fixed ?? `P${++uid}`, proof: { dev: true, custom_data: req.customData }, proofDate: date ? date() : Math.floor(Date.now() / 1000) };
	};
}

/** The voter's answers to a word challenge. */
export const answers = async ({ words, positions }: { words: string; positions: number[] }) => positions.map((p) => words.split(' ')[p - 1]);

/** A registered voter with confirmed words, ready to vote. */
export async function voter(w: World, opts: Partial<SessionConfig> = {}, uidOf?: string): Promise<{ s: Session; words: string }> {
	const s = session(w, opts);
	await s.init();
	const { words } = await s.register({ obtainProof: passport(undefined, uidOf), key: 'words', confirm: answers });
	w.ingest.checkpoint();
	await s.refresh();
	expect(s.state().phase).toBe('ready');
	return { s, words: words! };
}

/** The stored key (tests look inside). */
export function stored(s: Session): StoredKey {
	return (s as unknown as { key(): StoredKey }).key();
}
