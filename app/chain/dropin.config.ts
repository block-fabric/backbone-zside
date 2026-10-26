// What the drop-in pages (chain/dropin) need to know of zSide: its slot, the fees a form proposes, its spends' LayerTwo
// names (a payment of the shared pages is a transparent one: create_transparent_transfer), its own kinds of activity rows
// (moves between its two balances, payments in and out of the shielded one) and what a row of them says in its dialog.
import { t } from '../lib/i18n.svelte';
import { prefs } from '../lib/state.svelte';
import { formatAmount } from '../lib/units';
import type { HistoryRow } from './dropin/api';
import type { ZRow } from './zs/api';

const amount = (sats: number | undefined) => formatAmount(BigInt(Math.trunc(sats ?? 0)), prefs.unit);

export const DROPIN = {
  /** Its slot on eCash. */
  slot: 98,
  /** The fee a payment proposes (satoshis): the node takes any; LayerTwo's app proposes about this. */
  defaultFee: 1000,
  /** The fee on eCash a deposit or a withdrawal proposes. */
  defaultMainFee: 1000,
  /** What a transparent address looks like, for the placeholder. */
  addressExample: '4XrMw8bmnhchFspSyP4XRUuB5vaR',
  /** The shared pages' spends, by LayerTwo's names (the parameters in the same order). */
  spend: { transfer: 'create_transparent_transfer', deposit: 'create_deposit', withdraw: 'create_withdrawal' },
  /** Home's balance card: the transparent balance (the shielded one has its card beside it). */
  balanceTitle: 'Transparent balance',
  /** Under the deposit address: zSide credits a deposit only to the bare address (an s98_… text burns it). */
  depositNote: 'This is a transparent address of this wallet, as it is: give exactly this, never an “s98_…” text. zSide credits a deposit only to the plain address; one made to anything else is lost.',
  kinds: {
    shield: { text: 'Shielded', icon: 'shield', filter: 'Shielded', line: (r: HistoryRow) => t('%1 into the shielded balance', amount((r as ZRow).moved)) },
    unshield: { text: 'Unshielded', icon: 'eye', filter: 'Unshielded', line: (r: HistoryRow) => t('%1 into the transparent balance', amount((r as ZRow).moved)) },
    // Their other side is an address (the shielded recipient; the wallet's shielded address it came to): the shared rule.
    zsend: { text: 'Sent privately', icon: 'send', filter: 'Sent privately' },
    zreceive: { text: 'Received privately', icon: 'receive', filter: 'Received privately' },
    zself: { text: 'Within the shielded balance', icon: 'shield', line: () => t('to yourself') },
  },
  /** What a row of zSide's says in the transaction dialog besides the shared facts: the memo, the move, the shielded part. */
  rowFacts: (row: HistoryRow) => {
    const r = row as ZRow;
    const out: { label: string; value: string; mono?: boolean }[] = [];
    if (r.moved !== undefined) out.push({ label: r.kind === 'shield' ? 'Into the shielded balance' : 'Into the transparent balance', value: amount(r.moved) });
    if (r.kind === 'zsend' || r.kind === 'zreceive' || r.kind === 'zself') {
      for (const to of r.to.slice(0, 5)) out.push({ label: 'To (shielded)', value: `${to.address} · ${amount(to.amount)}`, mono: true });
      if (r.kind === 'zreceive' && r.ownAddress) out.push({ label: 'At (yours, shielded)', value: r.ownAddress, mono: true });
    }
    if (r.memo !== undefined) out.push({ label: r.memoSent ? 'Memo sent' : 'Memo', value: r.memo });
    else if (r.memoHex) out.push({ label: r.memoSent ? 'Memo sent (not text)' : 'Memo (not text)', value: r.memoHex, mono: true });
    return out;
  },
};
