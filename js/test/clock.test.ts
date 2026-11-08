import { describe, expect, it } from 'vitest';
import { ServerClock } from '../src/events.js';

describe('the server clock', () => {
	it('keeps the freshest live checkpoint: a stale one a relay kept does not set it back', () => {
		let local = 1_000_000_000_000;
		const c = new ServerClock(() => local);
		// A checkpoint signed now, received live: the offset is about 0.
		c.note(local / 1000, true);
		expect(Math.abs(c.now() - local)).toBeLessThan(1000);
		// A relay hands a new subscription a checkpoint signed 9 minutes ago.
		c.note(local / 1000 - 540, true);
		expect(Math.abs(c.now() - local)).toBeLessThan(1000);
	});

	it('corrects a local clock that is ahead, from a live checkpoint', () => {
		const local = 1_000_000_000_000;
		const c = new ServerClock(() => local);
		c.note(local / 1000 - 300, true);
		expect(c.now()).toBe(local - 300_000);
	});
});
