<script lang="ts">
  // Send on zSide: to a shielded address (t-shld1…) out of the shielded balance, privately, with a memo only the
  // recipient reads (create_shielded_transfer); to a transparent address out of the transparent balance, in public
  // (create_transparent_transfer). The kind of the address decides; the node checks it. Asked in the app's trusted
  // dialog (rpc.confirmed), never sent from here.
  import Amount from '../../components/Amount.svelte';
  import AmountInput from '../../components/AmountInput.svelte';
  import Icon from '../../components/Icon.svelte';
  import { CHAIN } from '../config';
  import { DROPIN } from '../dropin.config';
  import { declined, errorText } from '../../lib/dialogs.svelte';
  import { t } from '../../lib/i18n.svelte';
  import { go } from '../../lib/nav.svelte';
  import { toast } from '../../lib/state.svelte';
  import SetupWallet from '../dropin/SetupWallet.svelte';
  import { confirmed, sats, satsNumber } from '../dropin/api';
  import { drop, follow, refresh } from '../dropin/store.svelte';
  import { MEMO_BYTES, memoBytes, memoProblem } from '../zs/api';
  import Privacy from '../zs/Privacy.svelte';
  import { readShielded, shielded } from '../zs/store.svelte';
  import ZAddressField from '../zs/ZAddressField.svelte';
  import '../zs/zs.css';

  $effect(() => follow());
  $effect(() => {
    void drop.version;
    if (drop.seed?.hasSeed) void readShielded();
  });

  let to = $state('');
  let toValid = $state(false);
  let kind = $state<'' | 'transparent' | 'shielded'>('');
  let amount = $state<bigint | null>(null);
  let fee = $state<bigint | null>(BigInt(DROPIN.defaultFee));
  let memo = $state('');
  let busy = $state(false);
  let error = $state('');
  let formKey = $state(0);
  let last: { txid: string; amount: bigint; to: string; private: boolean } | null = $state(null);

  const isPrivate = $derived(kind === 'shielded');
  const z = $derived(shielded.data?.balance);
  /** What this payment can spend: the shielded notes 3 blocks deep, or the transparent coins. */
  const available = $derived(isPrivate ? sats(z?.spendable) : sats(drop.overview?.wallet.available));
  const settling = $derived(isPrivate && z && z.available > z.spendable ? sats(z.available - z.spendable) : 0n);
  const total = $derived((amount ?? 0n) + (fee ?? 0n));
  const tooMuch = $derived(total > available);
  const memoError = $derived(isPrivate ? memoProblem(memo) : '');
  const ready = $derived(toValid && kind !== '' && amount !== null && amount > 0n && fee !== null && !tooMuch && !memoError && !busy);

  function useAll() {
    const f = fee ?? 0n;
    amount = available > f ? available - f : 0n;
    formKey++;
  }

  async function send() {
    if (!ready || amount === null || fee === null) return;
    busy = true;
    error = '';
    try {
      const dest = to.trim();
      const txid = isPrivate
        ? await confirmed<string>('create_shielded_transfer', memo.trim() ? [dest, satsNumber(amount), satsNumber(fee), memo.trim()] : [dest, satsNumber(amount), satsNumber(fee)])
        : await confirmed<string>('create_transparent_transfer', [dest, satsNumber(amount), satsNumber(fee)]);
      last = { txid, amount, to: dest, private: isPrivate };
      toast('success', isPrivate ? t('Sent privately') : t('Sent'), t('The payment confirms with the next block of %1.', CHAIN.name));
      to = '';
      amount = null;
      memo = '';
      formKey++;
      await refresh();
      await readShielded(true);
    } catch (e) {
      if (!declined(e)) error = errorText(e);
    } finally {
      busy = false;
    }
  }
</script>

<div class="page zs zs-send">
  <header class="page-head"><h1>{t('Send')}</h1></header>
  {#if drop.seed && !drop.seed.hasSeed}
    <SetupWallet compact />
  {:else}
    <div class="layout">
      <section class="panel" aria-labelledby="send-title">
        <div class="panel-head row">
          <h2 id="send-title" class="grow">{t('Pay an address on %1', CHAIN.name)}</h2>
          {#if kind}<Privacy kind={isPrivate ? 'private' : 'public'} />{/if}
        </div>
        <form
          class="panel-body stack"
          onsubmit={(e) => {
            e.preventDefault();
            send();
          }}
        >
          <ZAddressField id="send-to" label={t('Pay to')} bind:value={to} bind:valid={toValid} bind:kind placeholder="t-shld1…  {t('or')}  {DROPIN.addressExample}" />
          {#if kind}
            <div class="zs-note {isPrivate ? 'private' : 'public'}">
              <Icon name={isPrivate ? 'shield' : 'eye'} size={16} />
              <span>{isPrivate ? t('From your shielded balance. Only the recipient sees the amount and the memo; the chain shows neither who paid nor who was paid.') : t('From your transparent balance. The payment, its amount and both addresses are public on the chain. To pay privately, pay a shielded address (t-shld1…).')}</span>
            </div>
          {/if}
          {#key formKey}
            <AmountInput id="send-amount" label={t('Amount')} bind:value={amount} required max={available} />
          {/key}
          <div class="row avail">
            <span class="muted">{isPrivate ? t('Shielded, spendable now') : t('Transparent, available')}: <Amount sats={available} /></span>
            <button type="button" class="btn ghost small" onclick={useAll} disabled={available === 0n || !kind}>{t('Use all')}</button>
          </div>
          {#if settling > 0n}<p class="hint"><Amount sats={settling} /> {t('more can be spent once its notes are 3 blocks deep.')}</p>{/if}
          {#if isPrivate}
            <div class="field">
              <label for="send-memo">{t('Memo (optional)')}</label>
              <textarea id="send-memo" rows="2" maxlength="512" bind:value={memo} placeholder={t('Only the recipient reads it')} aria-invalid={!!memoError}></textarea>
              <span class="zs-counter" class:over={memoBytes(memo) > MEMO_BYTES}>{memoError ? t(memoError) : `${memoBytes(memo)} / ${MEMO_BYTES}`}</span>
            </div>
          {/if}
          <AmountInput id="send-fee" label={t('Fee')} bind:value={fee} required title={t('Paid to whoever makes the block that takes this payment.')} />
          <div class="summary">
            <span>{t('Total')}</span>
            <strong><Amount sats={total} /></strong>
          </div>
          {#if tooMuch && kind}<p class="warn"><Icon name="alert" size={14} /> {isPrivate ? t('More than the shielded balance can spend now.') : t('More than the transparent balance has available.')}</p>{/if}
          {#if error}<p class="error" role="alert"><Icon name="alert" size={14} /> {error}</p>{/if}
          <div class="row">
            <button type="submit" class="btn primary" disabled={!ready}><Icon name={isPrivate ? 'shield' : 'send'} size={16} /> {isPrivate ? t('Review and send privately…') : t('Review and send…')}</button>
          </div>
          <p class="hint">{t('You check the payment in the app’s own window before it goes. A payment cannot be taken back.')}</p>
        </form>
      </section>
      <aside class="panel side">
        <div class="panel-body">
          {#if last}
            <h3><Icon name="check" size={16} /> {last.private ? t('Sent privately') : t('Sent')}</h3>
            <p><Amount sats={last.amount} /> {t('to')} <span class="mono break">{last.to}</span></p>
            <p class="mono faint break">{last.txid}</p>
            <button type="button" class="btn small" onclick={() => go('transactions')}>{t('See the activity')}</button>
          {:else}
            <h3>{t('Two kinds of payment')}</h3>
            <p class="muted"><strong>{t('Private')}</strong> — {t('to a shielded address (t-shld1…), out of the shielded balance, with a memo if you like. Shield coins first on the Private page.')}</p>
            <p class="muted"><strong>{t('Public')}</strong> — {t('to a transparent address, out of the transparent balance, like on eCash.')}</p>
            <p class="muted">{t('A payment is confirmed when the next block of %1 is merge-mined on eCash. To send ECX back to eCash, use Withdraw on the Drivechains page.', CHAIN.name)}</p>
          {/if}
        </div>
      </aside>
    </div>
  {/if}
</div>

<style>
  .zs-send {
    display: flex;
    flex-direction: column;
    gap: 1rem;
  }
  .layout {
    display: grid;
    grid-template-columns: minmax(20rem, 36rem) minmax(0, 1fr);
    gap: 1rem;
    align-items: start;
  }
  .stack {
    display: flex;
    flex-direction: column;
    gap: 0.85rem;
  }
  .avail {
    justify-content: space-between;
    margin-top: -0.4rem;
    font-size: 0.88rem;
  }
  .field {
    display: flex;
    flex-direction: column;
    gap: 0.3rem;
  }
  textarea {
    width: 100%;
    resize: vertical;
    min-height: 3.2rem;
  }
  .summary {
    display: flex;
    justify-content: space-between;
    align-items: baseline;
    padding: 0.6rem 0.8rem;
    border-radius: 0.6rem;
    background: color-mix(in srgb, var(--accent) 7%, transparent);
  }
  .hint {
    color: var(--text-muted);
    font-size: 0.85rem;
    margin: 0;
  }
  .warn,
  .error {
    margin: 0;
    display: flex;
    gap: 0.35rem;
    align-items: center;
  }
  .warn {
    color: var(--warning);
  }
  .error {
    color: var(--negative);
  }
  .side .panel-body {
    padding-top: 1.1rem;
  }
  .side h3 {
    margin: 0 0 0.5rem;
    font-size: 1rem;
    display: flex;
    gap: 0.4rem;
    align-items: center;
  }
  .break {
    word-break: break-all;
  }
  @media (max-width: 980px) {
    .layout {
      grid-template-columns: minmax(0, 1fr);
    }
  }
</style>
