import { describe, expect, it } from 'vitest';
import { reasonOf } from '../src/errors.js';

describe('ingest reasons', () => {
	it('names every reason of SPEC §12', () => {
		for (const r of ['malformed', 'version', 'unknown', 'not_open', 'closed', 'bad_sig', 'stale_date', 'uid_used', 'id_used', 'full', 'bad_proof', 'old_root', 'revote_off', 'stale_seq', 'seq_gap', 'duplicate', 'not_due', 'bad_tally']) {
			expect(reasonOf(r)).toBe(r);
		}
		expect(reasonOf('nonsense')).toBe('rejected');
		expect(reasonOf(undefined)).toBe('rejected');
	});
});
