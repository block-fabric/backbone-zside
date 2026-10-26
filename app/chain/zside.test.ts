// zSide's own pages over a pretend node: a payment to a shielded address goes as create_shielded_transfer [dest, value,
// fee] (a memo as a 4th, only when there is one), to a transparent one as create_transparent_transfer; shielding and
// unshielding as create_shield / create_unshield [value, fee]; all only through rpc.confirmed; memos as data (the CSV
// neutralised, the dialog's facts as text); no words of a phrase; and no request outside the manifest.
import { fireEvent, render, waitFor } from '@testing-library/svelte';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { setTransport, type BridgeRequest } from '../lib/bridge';
import { memoProblem, memosCsv } from './zs/api';

const manifest = JSON.parse(readFileSync(join(__dirname, 'manifest.json'), 'utf8')) as { reads: string[]; confirmed: string[]; host: string[] };
const APP_METHODS = new Set(['app.hello', 'app.info', 'app.locale', 'app.languages', 'prefs.get', 'prefs.set', 'node.state', 'rpc.confirmed', 'rpc.confirmedMethods', 'window.state', 'clipboard.write', 'app.notify', 'file.choose', 'file.write']);
const ZADDR = 't-shld1' + 'q'.repeat(70);
const TADDR = '4XrMw8bmnhchFspSyP4XRUuB5vaR';

let calls: BridgeRequest[] = [];
let answers: Record<string, (r: BridgeRequest) => unknown> = {};

beforeEach(() => {
  calls = [];
  answers = {
    'dropin.overview': () => ({
      wallet: { hasSeed: true, available: 300_000_000, withdrawing: 0, pendingIn: 0, pendingOut: 0, shielded: { available: 200_000_000, total: 200_000_000, spendable: 150_000_000, pendingIn: 0 } },
      chain: { height: 40, tip: 'ab'.repeat(32), peers: 1, wealth: 1_000_000_000, slot: 98, network: 'regtest' },
      mainchain: { slot: 98, connected: true, state: 'ok', node: 'http://127.0.0.1:50051', height: 120, tipheight: 120 },
    }),
    'dropin.seed.status': () => ({ hasSeed: true, phraseKept: true, from: 'app', fingerprint: '00', derivation: 'v0.18.1' }),
    'dropin.history': () => [],
    'dropin.checkAddress': (r) => {
      const a = String((r.params as { address: string }).address);
      return a.startsWith('t-shld1') ? { valid: true, kind: 'shielded', mine: false } : a.startsWith('4X') ? { valid: true, kind: 'transparent', mine: false } : { valid: false, error: 'not a zSide address' };
    },
    'dropin.newAddress': () => ({ address: TADDR, depositAddress: TADDR }),
    'dropin.addresses': () => [{ address: TADDR, depositAddress: TADDR, balance: 1, received: 2 }],
    'zside.shielded': () => ({
      hasSeed: true,
      balance: { available: 200_000_000, total: 200_000_000, spendable: 150_000_000, pendingIn: 0 },
      notes: [{ txid: 'cd'.repeat(32), height: 30, value: 150_000_000, address: ZADDR, change: false, state: 'unspent', memo: 'lunch' }],
      addresses: [{ address: ZADDR, received: 150_000_000 }],
    }),
    'zside.newShieldedAddress': () => ({ address: ZADDR }),
    'zside.memos': () => [{ txid: 'cd'.repeat(32), direction: 'in', value: 25_000_000, address: ZADDR, height: 30, pending: false, time: 1_760_000_000, text: '=HYPERLINK("x")' }],
    'zside.pool': () => ({ root: 'ef'.repeat(32), nullifiers: 3, historicalRoots: 4, commitments: 10, bundles: 4, shields: 2, unshields: 1, privateOnly: 1, value: 200_000_000, wealth: 1_000_000_000, height: 40, recent: [{ height: 30, block: 'aa'.repeat(32), txid: 'cd'.repeat(32), actions: 2, valueBalance: -200_000_000, kind: 'shield' }], blocks: [{ height: 40, actions: 2 }] }),
    'rpc.confirmed': () => 'cd'.repeat(32),
  };
  setTransport(async (req) => {
    calls.push(req);
    const answer = answers[req.kind === 'host' ? (req.method ?? '') : `rpc:${req.method}`];
    return answer ? answer(req) : null;
  });
});
afterEach(() => setTransport(null));

const confirmedCalls = () => calls.filter((c) => c.kind === 'host' && c.method === 'rpc.confirmed').map((c) => c.params as { method: string; params: unknown[] });

async function fillSend(container: HTMLElement, to: string, amount: string, memo?: string) {
  await fireEvent.input(container.querySelector('#send-to') as HTMLInputElement, { target: { value: to } });
  await waitFor(() => expect(container.querySelector('.state.good')).toBeTruthy(), { timeout: 3000 });
  await fireEvent.input(container.querySelector('#send-amount') as HTMLInputElement, { target: { value: amount } });
  if (memo !== undefined) await fireEvent.input(container.querySelector('#send-memo') as HTMLTextAreaElement, { target: { value: memo } });
  const submit = container.querySelector('button[type="submit"]') as HTMLButtonElement;
  await waitFor(() => expect(submit.disabled).toBe(false), { timeout: 3000 });
  await fireEvent.click(submit);
}

describe('zSide pages', () => {
  it('a shielded address: create_shielded_transfer [dest, value, fee, memo] out of the shielded balance, through rpc.confirmed only', async () => {
    const { refresh } = await import('./dropin/store.svelte');
    await refresh();
    const ZSend = (await import('./pages/ZSend.svelte')).default;
    const { container } = render(ZSend);
    await fillSend(container, ZADDR, '1', 'for lunch');
    await waitFor(() => expect(confirmedCalls().length).toBe(1));
    expect(confirmedCalls()[0]).toEqual({ method: 'create_shielded_transfer', params: [ZADDR, 100_000_000, 1000, 'for lunch'] });
  });

  it('no memo: LayerTwo’s three parameters; more than the spendable notes: refused in the page', async () => {
    const ZSend = (await import('./pages/ZSend.svelte')).default;
    const { container } = render(ZSend);
    await fillSend(container, ZADDR, '0.5');
    await waitFor(() => expect(confirmedCalls().length).toBe(1));
    expect(confirmedCalls()[0]).toEqual({ method: 'create_shielded_transfer', params: [ZADDR, 50_000_000, 1000] });
    // 1.6 ECX is more than the 1.5 the shielded notes can spend now (2 available, 0.5 settling).
    await fireEvent.input(container.querySelector('#send-to') as HTMLInputElement, { target: { value: ZADDR } });
    await waitFor(() => expect(container.querySelector('.state.good')).toBeTruthy(), { timeout: 3000 });
    await fireEvent.input(container.querySelector('#send-amount') as HTMLInputElement, { target: { value: '1.6' } });
    await new Promise((r) => setTimeout(r, 300));
    expect((container.querySelector('button[type="submit"]') as HTMLButtonElement).disabled).toBe(true);
  });

  it('a memo that is not one line of text cannot be sent', async () => {
    const ZSend = (await import('./pages/ZSend.svelte')).default;
    const { container } = render(ZSend);
    await fireEvent.input(container.querySelector('#send-to') as HTMLInputElement, { target: { value: ZADDR } });
    await waitFor(() => expect(container.querySelector('#send-memo')).toBeTruthy(), { timeout: 3000 });
    await fireEvent.input(container.querySelector('#send-amount') as HTMLInputElement, { target: { value: '0.1' } });
    await fireEvent.input(container.querySelector('#send-memo') as HTMLTextAreaElement, { target: { value: 'two\nlines' } });
    await new Promise((r) => setTimeout(r, 300));
    expect((container.querySelector('button[type="submit"]') as HTMLButtonElement).disabled).toBe(true);
    expect(confirmedCalls()).toEqual([]);
  });

  it('a transparent address: create_transparent_transfer [dest, value, fee], no memo field', async () => {
    const ZSend = (await import('./pages/ZSend.svelte')).default;
    const { container } = render(ZSend);
    await fillSend(container, TADDR, '2');
    await waitFor(() => expect(confirmedCalls().length).toBe(1));
    expect(container.querySelector('#send-memo')).toBeNull();
    expect(confirmedCalls()[0]).toEqual({ method: 'create_transparent_transfer', params: [TADDR, 200_000_000, 1000] });
  });

  it('shield and unshield: create_shield / create_unshield [value, fee]', async () => {
    const { nav } = await import('../lib/nav.svelte');
    nav.tab = 'move';
    const { refresh } = await import('./dropin/store.svelte');
    await refresh();
    const Private = (await import('./pages/Private.svelte')).default;
    const { container } = render(Private);
    await waitFor(() => expect(container.querySelector('#shield-amount')).toBeTruthy());
    await fireEvent.input(container.querySelector('#shield-amount') as HTMLInputElement, { target: { value: '1.25' } });
    const buttons = () => [...container.querySelectorAll('button[type="submit"]')] as HTMLButtonElement[];
    await waitFor(() => expect(buttons()[0].disabled).toBe(false), { timeout: 3000 });
    await fireEvent.click(buttons()[0]);
    await waitFor(() => expect(confirmedCalls().length).toBe(1));
    await fireEvent.input(container.querySelector('#unshield-amount') as HTMLInputElement, { target: { value: '0.75' } });
    await waitFor(() => expect(buttons()[1].disabled).toBe(false), { timeout: 3000 });
    await fireEvent.click(buttons()[1]);
    await waitFor(() => expect(confirmedCalls().length).toBe(2));
    expect(confirmedCalls()).toEqual([
      { method: 'create_shield', params: [125_000_000, 1000] },
      { method: 'create_unshield', params: [75_000_000, 1000] },
    ]);
  });

  it('call nothing of the node outside the manifest, and no words of a phrase', async () => {
    for (const page of ['ZSend', 'ZReceive', 'ZOverview', 'Private', 'Memos', 'Pool']) render((await import(`./pages/${page}.svelte`)).default);
    render((await import('./LocalCards.svelte')).default);
    await new Promise((r) => setTimeout(r, 500));
    const allowed = new Set([...manifest.host, ...APP_METHODS]);
    const bad = calls.filter((c) => (c.kind === 'host' ? !allowed.has(c.method ?? '') : !manifest.reads.includes(c.method ?? '')));
    expect(bad.map((c) => `${c.kind}:${c.method}`)).toEqual([]);
    for (const c of confirmedCalls()) expect(manifest.confirmed).toContain(c.method);
    expect(JSON.stringify(calls)).not.toMatch(/phrase|mnemonic|abandon/);
  });

  it('memos are data: what a memo may be, the CSV neutralised, the dialog’s facts and the activity’s words', async () => {
    expect(memoProblem('lunch 🍜')).toBe('');
    expect(memoProblem('x'.repeat(513))).toBe('At most 512 bytes');
    expect(memoProblem('é'.repeat(257))).toBe('At most 512 bytes');
    expect(memoProblem('a\nb')).toBe('No control, format or invisible character (U+000A)');
    expect(memoProblem('a\u202eb')).toBe('No control, format or invisible character (U+202E)');
    expect(memoProblem('a\u3164b')).not.toBe('');
    expect(memoProblem('a\u{E0001}b')).not.toBe('');
    const csv = memosCsv([{ txid: 'cd', direction: 'in', value: 25_000_000, address: ZADDR, height: 3, pending: false, text: '=HYPERLINK("x")' }], (s) => (Number(s) / 1e8).toFixed(8));
    expect(csv).toContain(`"'=HYPERLINK(""x"")"`);
    expect(csv).toContain('"0.25000000"');
    const { kindText, counterparty } = await import('./dropin/kinds');
    const { rowFacts } = await import('./dropin/spend');
    const row = { id: 'x', kind: 'shield', amount: -1000, received: 0, sent: 0, to: [], recipients: 0, pending: false, height: 3, time: null, approxTime: false, moved: 125_000_000 };
    expect(kindText(row)).toBe('Shielded');
    expect(counterparty(row)).toContain('1.25');
    const zreceive = { ...row, kind: 'zreceive', ownAddress: ZADDR, memo: 'thanks', memoSent: false };
    expect(rowFacts(zreceive)).toContainEqual({ label: 'Memo', value: 'thanks' });
    expect(counterparty(zreceive)).toBe(ZADDR);
  });
});
