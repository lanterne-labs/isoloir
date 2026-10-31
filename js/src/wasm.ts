// The wasm core (crates/wasm): every protocol rule the browser applies.
// `IsoloirWasm` is the raw module (strings in, strings out, throws on a
// refusal); `Core` parses its JSON into typed values. The module is
// given to the session by the app (loadWasm in a browser, the nodejs
// build in tests), so this package never guesses how wasm is served.

import type { Ack, Checkpoint, Choice, Draft, KindInfo, NostrEvent, PollSetup, TallyVerdict, Results } from './types.js';

export interface IsoloirWasm {
	protocol(): string;
	kinds(): string;
	canonical(json: string): string;
	body_hash(body: string): string;
	decode_body(kind: string, text: string): string;
	leaf(registry: number, s: string): string;
	nullifier(poll: number, s: string): string;
	ident(poll: number, s: string, i: number): string;
	delta_leaf(ident: string, cmt: string): string;
	secret_from_prf(prf_hex: string): string;
	new_words(lang: string): string;
	normalize_words(words: string, lang: string): string;
	secret_from_words(words: string, lang: string): string;
	relay_ranking(s: string, urls_json: string): string;
	new_reg_secret(): string;
	reg_pubkey(sk_hex: string): string;
	registration_binding(registry: number, pubkey_hex: string): string;
	register_body(req_json: string): string;
	verify_register(body: string): string;
	kind_info(poll_json: string): string;
	choice_values(poll_json: string, choice_json: string): string;
	draft_ballot(req_json: string): string;
	finish_ballot(draft_body_json: string, proof: Uint8Array): string;
	public_inputs(body: string, poll_json: string): string;
	delta_recover(poll_json: string, s: string, leaves_json: string): string;
	tree_root(depth: number, leaves_json: string): string;
	tree_path(depth: number, leaves_json: string, position: number): string;
	root_of(leaf: string, position: number, path_json: string): string;
	verify_note(note: string, verifier_key: string): string;
	sign_event(sk_hex: string, created_at: number, kind: number, tags_json: string, content: string): string;
	verify_event(event_json: string): boolean;
	decode_ack(content: string): string;
	read_ack(event_json: string, ingest_pubkey: string): string;
	complaint_body(ack_event_json: string, body: string): string;
	verify_tally(poll_json: string, tally: string): string;
	tally_results(poll_json: string, values_json: string, counted: number): string;
	aggregate(cts_json: string): string;
	link_receiver(): string;
	link_seal(receiver_public: string, payload: string): string;
	link_open(receiver_secret: string, sealed: string): string;
}

/** The Nostr kinds of SPEC §11.1. */
export interface Kinds {
	register: number;
	ballot: number;
	ack: number;
	checkpoint: number;
	link: number;
	tally: number;
	complaint: number;
}

export interface TreePath {
	root: string;
	leaf: string;
	index: number;
	path: string[];
}

export interface DeltaChain {
	/** The number of the next ballot of the chain. */
	next: number;
	/** The last ballot found: its number, choice and position in the ballot tree. */
	previous: { i: number; choice: Choice; index: number } | null;
}

/** The message of whatever wasm threw. */
export function messageOf(e: unknown): string {
	if (e instanceof Error) return e.message;
	if (e && typeof e === 'object' && 'message' in e) return String((e as { message: unknown }).message);
	return String(e);
}

/**
 * Loads the browser build (wasm-pack --target web) shipped in this
 * package. By default the .wasm file is fetched next to the module
 * (bundlers that handle `new URL(..., import.meta.url)` serve it); an app
 * that serves it elsewhere passes its URL, a Response or its bytes.
 */
export async function loadWasm(input?: URL | string | Response | BufferSource): Promise<IsoloirWasm> {
	const m = await import('../wasm/web/isoloir_wasm.js');
	await m.default(input === undefined ? undefined : { module_or_path: input });
	return m;
}

const json = JSON.stringify;

/** The wasm core with typed results. */
export class Core {
	readonly kinds: Kinds;

	constructor(readonly w: IsoloirWasm) {
		this.kinds = JSON.parse(w.kinds()) as Kinds;
	}

	canonical(v: unknown): string {
		return this.w.canonical(json(v));
	}
	bodyHash(body: string): string {
		return this.w.body_hash(body);
	}
	decodeBody<T>(kind: string, text: string): T {
		return JSON.parse(this.w.decode_body(kind, text)) as T;
	}
	leaf(registry: number, s: string): string {
		return this.w.leaf(registry, s);
	}
	nullifier(poll: number, s: string): string {
		return this.w.nullifier(poll, s);
	}
	deltaLeaf(ident: string, cmt: string): string {
		return this.w.delta_leaf(ident, cmt);
	}
	secretFromPrf(prf: Uint8Array): string {
		return this.w.secret_from_prf(toHex(prf));
	}
	newWords(lang: string): string {
		return this.w.new_words(lang);
	}
	normalizeWords(words: string, lang: string): string {
		return this.w.normalize_words(words, lang);
	}
	secretFromWords(words: string, lang: string): string {
		return this.w.secret_from_words(words, lang);
	}
	relayRanking(s: string, urls: string[]): string[] {
		return JSON.parse(this.w.relay_ranking(s, json(urls))) as string[];
	}
	newRegSecret(): string {
		return this.w.new_reg_secret();
	}
	regPubkey(sk: string): string {
		return this.w.reg_pubkey(sk);
	}
	registrationBinding(registry: number, pubkey: string): string {
		return this.w.registration_binding(registry, pubkey);
	}
	registerBody(req: { registry: number; s: string; uid: string; proof: unknown; proof_date: number; reg_secret: string }): string {
		return this.w.register_body(json(req));
	}
	kindInfo(poll: PollSetup): KindInfo {
		return JSON.parse(this.w.kind_info(json(poll))) as KindInfo;
	}
	choiceValues(poll: PollSetup, choice: Choice): number[] {
		return JSON.parse(this.w.choice_values(json(poll), json(choice))) as number[];
	}
	draftBallot(req: unknown): Draft {
		return JSON.parse(this.w.draft_ballot(json(req))) as Draft;
	}
	finishBallot(body: Record<string, unknown>, proof: Uint8Array): string {
		return this.w.finish_ballot(json(body), proof);
	}
	publicInputs(body: string, poll: PollSetup): string[] {
		return JSON.parse(this.w.public_inputs(body, json(poll))) as string[];
	}
	deltaRecover(poll: PollSetup, s: string, leaves: string[]): DeltaChain {
		return JSON.parse(this.w.delta_recover(json(poll), s, json(leaves))) as DeltaChain;
	}
	treeRoot(depth: number, leaves: string[]): string {
		return this.w.tree_root(depth, json(leaves));
	}
	treePath(depth: number, leaves: string[], position: number): TreePath {
		return JSON.parse(this.w.tree_path(depth, json(leaves), position)) as TreePath;
	}
	verifyNote(note: string, verifierKey: string): Checkpoint {
		return JSON.parse(this.w.verify_note(note, verifierKey)) as Checkpoint;
	}
	signEvent(sk: string, createdAt: number, kind: number, tags: string[][], content: string): NostrEvent {
		return JSON.parse(this.w.sign_event(sk, createdAt, kind, json(tags), content)) as NostrEvent;
	}
	verifyEvent(e: NostrEvent): boolean {
		return this.w.verify_event(json(e));
	}
	readAck(e: NostrEvent, ingest: string): Ack {
		return JSON.parse(this.w.read_ack(json(e), ingest)) as Ack;
	}
	complaintBody(ack: NostrEvent, body: string): string {
		return this.w.complaint_body(json(ack), body);
	}
	verifyTally(poll: PollSetup, tally: string): TallyVerdict {
		return JSON.parse(this.w.verify_tally(json(poll), tally)) as TallyVerdict;
	}
	tallyResults(poll: PollSetup, values: number[], counted: number): Results {
		return JSON.parse(this.w.tally_results(json(poll), json(values), counted)) as Results;
	}
	linkReceiver(): { secret: string; public: string } {
		return JSON.parse(this.w.link_receiver()) as { secret: string; public: string };
	}
	linkSeal(receiverPublic: string, payload: string): { sealed: string; code: string } {
		return JSON.parse(this.w.link_seal(receiverPublic, payload)) as { sealed: string; code: string };
	}
	linkOpen(receiverSecret: string, sealed: string): { payload: string; code: string } {
		return JSON.parse(this.w.link_open(receiverSecret, sealed)) as { payload: string; code: string };
	}
}

export function toHex(b: Uint8Array): string {
	let s = '';
	for (const x of b) s += x.toString(16).padStart(2, '0');
	return s;
}
