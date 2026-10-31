// The voter secret from a passkey (SPEC §14): the WebAuthn PRF extension
// evaluated on `isoloir/1/<origin>/<registry>` gives 32 bytes, and the
// wasm core derives `s = H(T_prf, lo, hi)`. The same passkey on another
// device of the same ecosystem gives the same secret: nothing to back up.

import { IsoloirError } from './errors.js';

/** The subset of navigator.credentials the session uses (tests stub it). */
export interface CredentialsApi {
	create(options: CredentialCreationOptions): Promise<Credential | null>;
	get(options: CredentialRequestOptions): Promise<Credential | null>;
}

export interface PasskeyOptions {
	/** The relying party: the page's host by default. */
	rpId?: string;
	rpName?: string;
	userName?: string;
	credentials?: CredentialsApi;
	random?: (n: number) => Uint8Array;
}

export function prfInput(origin: string, registry: number): Uint8Array {
	return new TextEncoder().encode(`isoloir/1/${origin}/${registry}`);
}

function rnd(opts: PasskeyOptions, n: number): Uint8Array {
	return opts.random ? opts.random(n) : crypto.getRandomValues(new Uint8Array(n));
}

function credentials(opts: PasskeyOptions): CredentialsApi {
	if (opts.credentials) return opts.credentials;
	const c = (globalThis as { navigator?: { credentials?: CredentialsApi } }).navigator?.credentials;
	if (!c) throw new IsoloirError('passkey_unsupported');
	return c;
}

function rpId(opts: PasskeyOptions): string {
	return opts.rpId ?? (globalThis as { location?: { hostname: string } }).location?.hostname ?? 'localhost';
}

function passkeyError(e: unknown): IsoloirError {
	const name = e && typeof e === 'object' && 'name' in e ? String((e as { name: unknown }).name) : '';
	if (name === 'NotAllowedError' || name === 'AbortError') return new IsoloirError('passkey_cancelled');
	if (name === 'NotSupportedError' || name === 'SecurityError') return new IsoloirError('passkey_unsupported', name);
	return new IsoloirError('passkey_failed', e instanceof Error ? e.message : String(e));
}

interface PrfResults {
	prf?: { enabled?: boolean; results?: { first?: ArrayBuffer | ArrayBufferView } };
}

function bytesOf(b: ArrayBuffer | ArrayBufferView): Uint8Array {
	return b instanceof ArrayBuffer ? new Uint8Array(b) : new Uint8Array(b.buffer, b.byteOffset, b.byteLength);
}

function b64url(b: Uint8Array): string {
	let s = '';
	for (const x of b) s += String.fromCharCode(x);
	return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

function b64urlDecode(s: string): Uint8Array {
	const bin = atob(s.replace(/-/g, '+').replace(/_/g, '/'));
	return Uint8Array.from(bin, (c) => c.charCodeAt(0));
}

/** Whether the platform says it supports the PRF extension (null: it cannot tell). */
export async function prfCapability(): Promise<boolean | null> {
	const pkc = (globalThis as { PublicKeyCredential?: { getClientCapabilities?: () => Promise<Record<string, boolean>> } }).PublicKeyCredential;
	if (!pkc) return false;
	if (typeof pkc.getClientCapabilities !== 'function') return null;
	try {
		const caps = await pkc.getClientCapabilities();
		return typeof caps['extension:prf'] === 'boolean' ? caps['extension:prf'] : null;
	} catch {
		return null;
	}
}

/**
 * Asks a passkey for its PRF output on the input; with no credential id,
 * any passkey of this relying party (a restore).
 */
export async function assertPrf(input: Uint8Array, opts: PasskeyOptions = {}, credentialId?: string): Promise<Uint8Array> {
	let cred: Credential | null;
	try {
		cred = await credentials(opts).get({
			publicKey: {
				challenge: rnd(opts, 32) as BufferSource,
				rpId: rpId(opts),
				userVerification: 'required',
				allowCredentials: credentialId ? [{ type: 'public-key', id: b64urlDecode(credentialId) as BufferSource }] : [],
				extensions: { prf: { eval: { first: input as BufferSource } } } as AuthenticationExtensionsClientInputs
			}
		});
	} catch (e) {
		throw passkeyError(e);
	}
	if (!cred) throw new IsoloirError('passkey_cancelled');
	const ext = (cred as PublicKeyCredential).getClientExtensionResults() as PrfResults;
	const first = ext.prf?.results?.first;
	if (!first) throw new IsoloirError('passkey_noprf');
	return bytesOf(first);
}

/**
 * Creates a passkey and reads its PRF output (one prompt where the
 * platform evaluates PRF at creation, else a second for an assertion).
 * Throws passkey_noprf when the platform gives none: the words are then
 * the way.
 */
export async function createPrf(input: Uint8Array, opts: PasskeyOptions = {}): Promise<{ prf: Uint8Array; credentialId: string }> {
	let cred: Credential | null;
	try {
		cred = await credentials(opts).create({
			publicKey: {
				challenge: rnd(opts, 32) as BufferSource,
				rp: { name: opts.rpName ?? 'isoloir', id: rpId(opts) },
				user: { id: rnd(opts, 16) as BufferSource, name: opts.userName ?? 'isoloir', displayName: opts.userName ?? 'isoloir' },
				pubKeyCredParams: [
					{ type: 'public-key', alg: -7 },
					{ type: 'public-key', alg: -257 }
				],
				authenticatorSelection: { residentKey: 'required', userVerification: 'required' },
				extensions: { prf: { eval: { first: input as BufferSource } } } as AuthenticationExtensionsClientInputs
			}
		});
	} catch (e) {
		throw passkeyError(e);
	}
	if (!cred) throw new IsoloirError('passkey_cancelled');
	const pk = cred as PublicKeyCredential;
	const ext = pk.getClientExtensionResults() as PrfResults;
	if (!ext.prf?.enabled && !ext.prf?.results?.first) throw new IsoloirError('passkey_noprf');
	const credentialId = b64url(new Uint8Array(pk.rawId));
	const first = ext.prf.results?.first;
	return { prf: first ? bytesOf(first) : await assertPrf(input, opts, credentialId), credentialId };
}
