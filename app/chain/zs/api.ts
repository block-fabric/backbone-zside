// zSide's own host methods (zside.*): the shielded account (balances, notes, addresses), a new shielded address, the
// memos it got and sent, the shielded pool of the chain; and what a memo may be (as the node's describer checks it).
import { request } from '../../lib/bridge';
import type { HistoryRow } from '../dropin/api';
import { toCsv } from '../../lib/wallet';
import { displayTextProblem } from '../dropin/text';

export interface ShieldedBalance {
  /** Unspent, not spent by a transaction waiting for its block. */
  available: number;
  /** Unspent (what a waiting spend takes too). */
  total: number;
  /** Of available, what can be spent now: notes 3 blocks deep (their wallet spends against the root 3 blocks under the tip). */
  spendable: number;
  /** Coming in: notes to this wallet in transactions waiting for their block. */
  pendingIn: number;
}

export interface Note {
  txid: string;
  height: number | null;
  value: number;
  address: string;
  change: boolean;
  state: 'unspent' | 'spending' | 'incoming';
  memo?: string;
  memoHex?: string;
}

export interface Shielded {
  hasSeed: boolean;
  balance?: ShieldedBalance;
  notes?: Note[];
  addresses?: { address: string; received: number }[];
}

export interface Memo {
  txid: string;
  direction: 'in' | 'out';
  value: number;
  address: string;
  height: number | null;
  pending: boolean;
  time?: number;
  text?: string;
  hex?: string;
}

export interface Pool {
  root: string;
  nullifiers: number;
  historicalRoots: number;
  commitments: number;
  bundles: number;
  shields: number;
  unshields: number;
  privateOnly: number;
  /** What the pool holds (satoshis): what went in less what came out. */
  value: number;
  wealth: number;
  height: number;
  recent: { height: number; block?: string; txid: string; actions: number; valueBalance: number; kind: 'shield' | 'unshield' | 'private'; time?: number }[];
  blocks: { height: number; actions: number }[];
}

/** A row of the activity as zSide's node writes it (dropin.history): the shielded part, a move, a memo. */
export interface ZRow extends HistoryRow {
  shielded?: { received: number; spent: number; valueBalance?: number };
  moved?: number;
  memo?: string;
  memoHex?: string;
  memoSent?: boolean;
}

const host = <T>(method: string, params: Record<string, unknown> = {}) => request<T>('host', method, params);

export const zs = {
  shielded: () => host<Shielded>('zside.shielded'),
  newShieldedAddress: () => host<{ address: string }>('zside.newShieldedAddress'),
  memos: (limit = 500) => host<Memo[]>('zside.memos', { limit }),
  pool: () => host<Pool>('zside.pool'),
};

/** At most this many bytes of memo (an Orchard note's). */
export const MEMO_BYTES = 512;

export function memoBytes(text: string): number {
  return new TextEncoder().encode(text).length;
}

/** What a memo may be (the node checks it again): at most 512 bytes of text that reads as it is (core's displayTextProblem). */
export function memoProblem(text: string): string {
  if (memoBytes(text) > MEMO_BYTES) return `At most ${MEMO_BYTES} bytes`;
  return displayTextProblem(text);
}

/** A shielded address (Bech32m, t-shld1…) by its look; the node says whether it is one. */
export function looksShielded(text: string): boolean {
  return text.trim().toLowerCase().startsWith('t-shld1');
}

/** The memos as a CSV file: every cell through the kit's toCsv (a memo is anyone's text: never a formula in a spreadsheet). */
export function memosCsv(rows: readonly Memo[], format: (sats: bigint) => string): string {
  return toCsv(
    ['Date', 'Direction', 'Amount', 'Memo', 'Shielded address', 'Transaction', 'Block'],
    rows.map((m) => [
      m.time ? new Date(m.time * 1000).toISOString() : '',
      m.direction === 'in' ? 'received' : 'sent',
      format(BigInt(Math.trunc(m.value))),
      m.text ?? (m.hex ? `0x${m.hex}` : ''),
      m.address,
      m.txid,
      m.height !== null ? String(m.height) : 'pending',
    ]),
  );
}
