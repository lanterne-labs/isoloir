import { describe, expect, it } from 'vitest';
import { IsoloirError } from '../src/errors.js';
import { fetchPinned, srsPoints, workerError, workerFailure, WorkerProver, type Prover, type WorkerLike, type WorkerRequest, type WorkerResponse } from '../src/prover.js';
import { world } from './fakes.js';
import { voter } from './helpers.js';

async function sha256(b: Uint8Array): Promise<string> {
	const d = new Uint8Array(await crypto.subtle.digest('SHA-256', b as BufferSource));
	return Array.from(d, (x) => x.toString(16).padStart(2, '0')).join('');
}

const URL_ = 'https://cdn.test/srs/g2.dat';
const bytes = crypto.getRandomValues(new Uint8Array(128));

function serving(body: Uint8Array, status = 200): typeof fetch {
	return (async (input: RequestInfo | URL) => {
		expect(String(input)).toBe(URL_);
		return new Response(body as BufferSource, { status });
	}) as typeof fetch;
}

describe('pinned files', () => {
	it('gives the bytes of a file whose SHA-256 is the pinned one (any case)', async () => {
		const h = await sha256(bytes);
		expect(await fetchPinned({ url: URL_, sha256: h }, serving(bytes))).toEqual(bytes);
		expect(await fetchPinned({ url: URL_, sha256: h.toUpperCase() }, serving(bytes))).toEqual(bytes);
	});

	it('refuses a file whose SHA-256 differs, with the hashes', async () => {
		const h = await sha256(bytes);
		const other = bytes.slice();
		other[0] ^= 1;
		const e = await fetchPinned({ url: URL_, sha256: h }, serving(other)).catch((x: unknown) => x);
		expect(e).toBeInstanceOf(IsoloirError);
		expect(e).toMatchObject({ code: 'pin_mismatch', data: { url: URL_, expected: h, actual: await sha256(other) } });
	});

	it('refuses a malformed pin and an unreachable file', async () => {
		await expect(fetchPinned({ url: URL_, sha256: 'abc' }, serving(bytes))).rejects.toMatchObject({ code: 'prover' });
		await expect(fetchPinned({ url: URL_, sha256: await sha256(bytes) }, serving(bytes, 404))).rejects.toMatchObject({ code: 'prover', detail: `${URL_}: HTTP 404` });
		const down = (async () => {
			throw new TypeError('fetch failed');
		}) as typeof fetch;
		await expect(fetchPinned({ url: URL_, sha256: await sha256(bytes) }, down)).rejects.toMatchObject({ code: 'prover' });
	});

	it('counts the SRS points in bb.js formats: G1 in blocks of 2^17, Grumpkin optional', () => {
		const block = new Uint8Array(4_194_304);
		const g2 = new Uint8Array(128);
		expect(srsPoints(block, g2, new Uint8Array(4_194_304))).toEqual({ g1: 1 << 17, grumpkin: 1 << 16 });
		expect(srsPoints(new Uint8Array(2 * 4_194_304), g2)).toEqual({ g1: 1 << 18, grumpkin: 0 });
		// srs.sh's 17,825,792 B is not whole blocks: bb.js would refuse it.
		expect(() => srsPoints(new Uint8Array(17_825_792), g2)).toThrow(/G1/);
		expect(() => srsPoints(new Uint8Array(32), g2)).toThrow(/G1/);
		expect(() => srsPoints(block, new Uint8Array(64))).toThrow(/G2/);
		expect(() => srsPoints(block, g2, new Uint8Array(32))).toThrow(/Grumpkin/);
	});
});

/** A worker that answers every request with a pin_mismatch, as prove.worker does. */
class RefusingWorker implements WorkerLike {
	seen: WorkerRequest[] = [];
	onmessage: ((ev: { data: WorkerResponse }) => void) | null = null;
	onerror: ((ev: unknown) => void) | null = null;
	postMessage(m: WorkerRequest): void {
		this.seen.push(m);
		const e = new IsoloirError('pin_mismatch', 'https://cdn.test/g1.dat is not the file pinned', { url: 'https://cdn.test/g1.dat', expected: '00', actual: '11' });
		queueMicrotask(() => this.onmessage?.({ data: workerFailure(m.id, e) }));
	}
	terminate(): void {}
}

describe('the worker prover', () => {
	const options = { srs: { g1: { url: 'https://cdn.test/g1.dat', sha256: '0'.repeat(64) }, g2: { url: 'https://cdn.test/g2.dat', sha256: '1'.repeat(64) }, grumpkin: { url: 'https://cdn.test/grumpkin.dat', sha256: '2'.repeat(64) } } };

	it('hands the options to the worker and keeps the error typed across it', async () => {
		const w = new RefusingWorker();
		const p = new WorkerProver(() => w, async () => '{}', options);
		await expect(p.warm('c')).rejects.toMatchObject({ code: 'pin_mismatch', data: { url: 'https://cdn.test/g1.dat' } });
		await expect(p.prove('c', {})).rejects.toBeInstanceOf(IsoloirError);
		expect(w.seen.map((m) => m.options)).toEqual([options, options]);
	});

	it('keeps an untyped failure as an Error', () => {
		const e = workerError(workerFailure(1, new Error('boom')) as Extract<WorkerResponse, { ok: false }>);
		expect(e).not.toBeInstanceOf(IsoloirError);
		expect(e.message).toBe('boom');
	});

	it('a ballot whose prover refuses a pinned file fails with pin_mismatch, not prover', async () => {
		const w = world();
		const refusing: Prover = {
			prove: async () => {
				throw new IsoloirError('pin_mismatch', 'x is not the file pinned', { url: 'x' });
			}
		};
		const { s } = await voter(w, { prover: refusing });
		await expect(s.cast({ pick: 0 })).rejects.toMatchObject({ code: 'pin_mismatch' });
		expect(s.state().prover).toBe('failed');
	});
});
