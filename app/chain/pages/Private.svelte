<script lang="ts">
  // Private: zSide's shielded balance.
  //  - Overview: the two balances side by side, how much of the wallet is shielded, the shielded account's latest.
  //  - Shield & unshield: transparent coins into the shielded pool (to a new shielded address of this wallet,
  //    create_shield), and out of it (to a new transparent address of this wallet, create_unshield); each asked in the
  //    app's trusted dialog.
  //  - Notes: the notes the shielded balance is made of, which can be spent now, their memos.
  import Amount from '../../components/Amount.svelte';
  import AmountInput from '../../components/AmountInput.svelte';
  import DataTable from '../../components/DataTable.svelte';
  import Icon from '../../components/Icon.svelte';
  import SafeText from '../../components/SafeText.svelte';
  import TabRow from '../../components/TabRow.svelte';
  import { DROPIN } from '../dropin.config';
  import { declined, errorText } from '../../lib/dialogs.svelte';
  import { formatCount } from '../../lib/format';
  import { t } from '../../lib/i18n.svelte';
  import { go, nav } from '../../lib/nav.svelte';
  import { prefs, toast } from '../../lib/state.svelte';
  import type { Column } from '../../lib/table';
  import { unitInfo } from '../../lib/units';
  import ActivityList from '../dropin/ActivityList.svelte';
  import SetupWallet from '../dropin/SetupWallet.svelte';
  import { confirmed, sats, satsNumber } from '../dropin/api';
  import { drop, follow, refresh, wantHistory } from '../dropin/store.svelte';
  import type { Note } from '../zs/api';
  import Privacy from '../zs/Privacy.svelte';
  import Ring from '../zs/Ring.svelte';
  import { readShielded, shielded } from '../zs/store.svelte';
  import '../zs/zs.css';

  $effect(() => follow());
  $effect(() => wantHistory(200));
  $effect(() => {
    void drop.version;
    if (drop.seed?.hasSeed) void readShielded();
  });

  const TABS = [
    { id: 'overview', label: 'Overview' },
    { id: 'move', label: 'Shield & unshield' },
    { id: 'notes', label: 'Notes' },
  ];
  const tab = $derived(TABS.some((x) => x.id === nav.tab) ? nav.tab : 'overview');

  const z = $derived(shielded.data?.balance);
  const transparent = $derived(sats(drop.overview?.wallet.available));
  const shieldedAvail = $derived(sats(z?.available));
  const spendable = $derived(sats(z?.spendable));
  const settling = $derived(shieldedAvail > spendable ? shieldedAvail - spendable : 0n);
  const share = $derived(shieldedAvail + transparent > 0n ? Number(shieldedAvail) / Number(shieldedAvail + transparent) : 0);
  const PRIVATE_KINDS = new Set(['shield', 'unshield', 'zsend', 'zreceive', 'zself']);
  const latest = $derived(drop.history.filter((r) => PRIVATE_KINDS.has(r.kind)).slice(0, 8));

  // ---- shield
  let shieldAmount = $state<bigint | null>(null);
  let shieldFee = $state<bigint | null>(BigInt(DROPIN.defaultFee));
  let shieldKey = $state(0);
  let shieldBusy = $state(false);
  let shieldError = $state('');
  const shieldTotal = $derived((shieldAmount ?? 0n) + (shieldFee ?? 0n));
  const shieldReady = $derived(shieldAmount !== null && shieldAmount > 0n && shieldFee !== null && shieldTotal <= transparent && !shieldBusy);
  function shieldAll() {
    const f = shieldFee ?? 0n;
    shieldAmount = transparent > f ? transparent - f : 0n;
    shieldKey++;
  }
  async function shield() {
    if (!shieldReady || shieldAmount === null || shieldFee === null) return;
    shieldBusy = true;
    shieldError = '';
    try {
      await confirmed<string>('create_shield', [satsNumber(shieldAmount), satsNumber(shieldFee)]);
      toast('success', t('Shielding'), t('In your shielded balance with the next block; spendable 3 blocks after it.'));
      shieldAmount = null;
      shieldKey++;
      await refresh();
      await readShielded(true);
    } catch (e) {
      if (!declined(e)) shieldError = errorText(e);
    } finally {
      shieldBusy = false;
    }
  }

  // ---- unshield
  let unshieldAmount = $state<bigint | null>(null);
  let unshieldFee = $state<bigint | null>(BigInt(DROPIN.defaultFee));
  let unshieldKey = $state(0);
  let unshieldBusy = $state(false);
  let unshieldError = $state('');
  const unshieldTotal = $derived((unshieldAmount ?? 0n) + (unshieldFee ?? 0n));
  const unshieldReady = $derived(unshieldAmount !== null && unshieldAmount > 0n && unshieldFee !== null && unshieldTotal <= spendable && !unshieldBusy);
  function unshieldAll() {
    const f = unshieldFee ?? 0n;
    unshieldAmount = spendable > f ? spendable - f : 0n;
    unshieldKey++;
  }
  async function unshield() {
    if (!unshieldReady || unshieldAmount === null || unshieldFee === null) return;
    unshieldBusy = true;
    unshieldError = '';
    try {
      await confirmed<string>('create_unshield', [satsNumber(unshieldAmount), satsNumber(unshieldFee)]);
      toast('success', t('Unshielding'), t('In your transparent balance with the next block.'));
      unshieldAmount = null;
      unshieldKey++;
      await refresh();
      await readShielded(true);
    } catch (e) {
      if (!declined(e)) unshieldError = errorText(e);
    } finally {
      unshieldBusy = false;
    }
  }

  // ---- notes
  const height = $derived(drop.overview?.chain.height ?? -1);
  const noteState = (n: Note) =>
    n.state === 'incoming' ? t('Coming in') : n.state === 'spending' ? t('Being spent') : n.height !== null && height - n.height >= 3 ? t('Spendable') : t('Settling');
  let filter = $state('');
  let selected = $state<string | null>(null);
  let sortKey = $state<string | null>('height');
  let sortDir = $state<'asc' | 'desc'>('desc');
  const columns: Column<Note>[] = $derived([
    { key: 'height', label: 'Block', value: (n) => n.height ?? Number.MAX_SAFE_INTEGER, width: '6.5rem', align: 'end' },
    { key: 'value', label: `Value (${unitInfo(prefs.unit).short})`, value: (n) => n.value, width: '10rem', align: 'end' },
    { key: 'state', label: 'State', value: (n) => noteState(n), width: '8rem', words: true },
    { key: 'memo', label: 'Memo', value: (n) => n.memo ?? n.memoHex ?? '', width: 'minmax(8rem, 1fr)' },
    { key: 'address', label: 'At', value: (n) => (n.change ? 'change' : n.address), width: 'minmax(10rem, 1fr)', mono: true },
  ]);
</script>

<div class="page zs zs-private">
  <header class="page-head row">
    <h1 class="grow">{t('Private')}</h1>
    <Privacy kind="private" />
  </header>
  <TabRow label="Private" tabs={TABS} current={tab} select={(id) => (nav.tab = id)} />

  {#if drop.seed && !drop.seed.hasSeed}
    <SetupWallet compact />
  {:else if tab === 'move'}
    <div class="zs-cols">
      <section class="panel" aria-labelledby="sh-title">
        <div class="panel-head row"><span class="mark in"><Icon name="shieldin" size={18} /></span><h2 id="sh-title" class="grow">{t('Shield')}</h2></div>
        <form class="panel-body zs-form" onsubmit={(e) => (e.preventDefault(), shield())}>
          <p class="muted">{t('Transparent coins of this wallet go into the shielded pool, to a new shielded address of this wallet.')}</p>
          {#key shieldKey}<AmountInput id="shield-amount" label={t('Amount to shield')} bind:value={shieldAmount} required max={transparent} />{/key}
          <div class="row avail"><span class="muted">{t('Transparent, available')}: <Amount sats={transparent} /></span><button type="button" class="btn ghost small" onclick={shieldAll} disabled={transparent === 0n}>{t('Use all')}</button></div>
          <AmountInput id="shield-fee" label={t('Fee')} bind:value={shieldFee} required />
          <div class="zs-note public"><Icon name="eye" size={16} /><span>{t('The move into the pool is public: the amount shows on the chain. What you do with the coins after is not.')}</span></div>
          {#if shieldTotal > transparent && shieldAmount}<p class="warn"><Icon name="alert" size={14} /> {t('More than the transparent balance has available.')}</p>{/if}
          {#if shieldError}<p class="error" role="alert"><Icon name="alert" size={14} /> {shieldError}</p>{/if}
          <div class="zs-actions"><button type="submit" class="btn primary" disabled={!shieldReady}><Icon name="shieldin" size={16} /> {t('Review and shield…')}</button></div>
        </form>
      </section>
      <section class="panel" aria-labelledby="un-title">
        <div class="panel-head row"><span class="mark out"><Icon name="shieldout" size={18} /></span><h2 id="un-title" class="grow">{t('Unshield')}</h2></div>
        <form class="panel-body zs-form" onsubmit={(e) => (e.preventDefault(), unshield())}>
          <p class="muted">{t('Coins leave the shielded pool to a new transparent address of this wallet: to withdraw them to eCash, or pay a transparent address.')}</p>
          {#key unshieldKey}<AmountInput id="unshield-amount" label={t('Amount to unshield')} bind:value={unshieldAmount} required max={spendable} />{/key}
          <div class="row avail"><span class="muted">{t('Shielded, spendable now')}: <Amount sats={spendable} /></span><button type="button" class="btn ghost small" onclick={unshieldAll} disabled={spendable === 0n}>{t('Use all')}</button></div>
          {#if settling > 0n}<p class="hint"><Amount sats={settling} /> {t('more once its notes are 3 blocks deep.')}</p>{/if}
          <AmountInput id="unshield-fee" label={t('Fee')} bind:value={unshieldFee} required />
          <div class="zs-note public"><Icon name="eye" size={16} /><span>{t('The amount is public as it comes out; where the coins came from is not.')}</span></div>
          {#if unshieldTotal > spendable && unshieldAmount}<p class="warn"><Icon name="alert" size={14} /> {t('More than the shielded balance can spend now.')}</p>{/if}
          {#if unshieldError}<p class="error" role="alert"><Icon name="alert" size={14} /> {unshieldError}</p>{/if}
          <div class="zs-actions"><button type="submit" class="btn" disabled={!unshieldReady}><Icon name="shieldout" size={16} /> {t('Review and unshield…')}</button></div>
        </form>
      </section>
    </div>
  {:else if tab === 'notes'}
    <div class="row head">
      <h2 class="grow">{t('Notes of the shielded balance')}</h2>
      <input type="search" placeholder={t('Search')} aria-label={t('Search the notes')} bind:value={filter} />
    </div>
    <div class="holder">
      <DataTable rows={shielded.data?.notes ?? []} {columns} key={(n) => n.txid + n.address + n.value} {filter} bind:selected bind:sortKey bind:sortDir label={t('Notes')} fit empty={shielded.data ? t('No note yet: shield coins, or get paid at a shielded address.') : t('Reading…')}>
        {#snippet cell(n, column)}
          {#if column.key === 'height'}{#if n.height === null}<span class="badge warning">{t('pending')}</span>{:else}<span class="num">{formatCount(n.height)}</span>{/if}
          {:else if column.key === 'value'}<Amount sats={sats(n.value)} showUnit={false} />
          {:else if column.key === 'state'}{noteState(n)}
          {:else if column.key === 'memo'}{#if n.memo}<SafeText class="clip" title={n.memo} text={n.memo} />{:else if n.memoHex}<span class="faint mono clip">{n.memoHex}</span>{:else}<span class="faint">–</span>{/if}
          {:else if n.change}<span class="faint">{t('change')}</span>
          {:else}<span class="mono clip" title={n.address}>{n.address}</span>{/if}
        {/snippet}
      </DataTable>
    </div>
  {:else}
    <div class="zs-split">
      <section class="zs-vault public">
        <div class="head"><span class="label">{t('Transparent balance')}</span><Privacy kind="public" /></div>
        <span class="big"><Amount sats={transparent} /></span>
        <span class="sub">{t('On the chain for anyone to see.')}</span>
      </section>
      <div class="zs-moves">
        <button type="button" class="btn primary" onclick={() => (nav.tab = 'move')}><Icon name="shieldin" size={16} /> {t('Shield')}</button>
        <button type="button" class="btn ghost" onclick={() => (nav.tab = 'move')}><Icon name="shieldout" size={16} /> {t('Unshield')}</button>
      </div>
      <section class="zs-vault private">
        <div class="head"><span class="label">{t('Shielded balance')}</span><Privacy kind="private" /></div>
        <span class="big"><Amount sats={shieldedAvail} /></span>
        <span class="sub">{#if settling > 0n}<Amount sats={settling} /> {t('of it settling: spendable 3 blocks after it arrived.')}{:else}{t('Nobody but you sees what it holds or whom it pays.')}{/if}</span>
      </section>
    </div>
    <div class="zs-tiles">
      <div class="zs-tile share">
        <Ring {share} size={56} label={t('%1% of the wallet is shielded', Math.round(share * 100))} />
        <div><span class="k">{t('Shielded')}</span><span class="n">{t('Of what the wallet holds.')}</span></div>
      </div>
      <div class="zs-tile"><span class="k">{t('Spendable now')}</span><span class="v"><Amount sats={spendable} /></span><span class="n">{t('Notes 3 blocks deep.')}</span></div>
      <div class="zs-tile"><span class="k">{t('Coming in')}</span><span class="v"><Amount sats={sats(z?.pendingIn)} /></span><span class="n">{t('In payments waiting for the next block.')}</span></div>
      <div class="zs-tile"><span class="k">{t('Notes')}</span><span class="v num">{formatCount((shielded.data?.notes ?? []).length)}</span><span class="n">{t('%1 shielded addresses', (shielded.data?.addresses ?? []).length)}</span></div>
    </div>
    <section class="panel">
      <div class="panel-head row">
        <h2 class="grow">{t('Latest of the shielded balance')}</h2>
        <button type="button" class="btn ghost small" onclick={() => go('send')}><Icon name="send" size={14} /> {t('Send privately')}</button>
        <button type="button" class="btn ghost small" onclick={() => go('receive')}><Icon name="receive" size={14} /> {t('Receive privately')}</button>
      </div>
      <ActivityList rows={latest} empty={drop.historyLoaded ? t('Nothing private yet: shield coins to start.') : t('Reading…')} />
    </section>
    {#if shielded.error}<p class="error">{shielded.error}</p>{/if}
  {/if}
</div>

<style>
  .zs-private {
    display: flex;
    flex-direction: column;
    gap: 1rem;
    height: 100%;
  }
  .mark {
    display: grid;
    place-items: center;
    width: 2rem;
    height: 2rem;
    border-radius: 0.6rem;
    background: color-mix(in srgb, var(--brand, var(--accent)) 14%, transparent);
    color: var(--brand, var(--accent));
  }
  .mark.out {
    background: color-mix(in srgb, var(--warning) 14%, transparent);
    color: var(--warning);
  }
  .avail {
    justify-content: space-between;
    margin-top: -0.4rem;
    font-size: 0.88rem;
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
  .share {
    flex-direction: row;
    align-items: center;
    gap: 0.8rem;
  }
  .share > div {
    display: flex;
    flex-direction: column;
    gap: 0.2rem;
  }
  .head input {
    width: 14rem;
  }
  .holder {
    flex: 1;
    min-height: 16rem;
  }
  .holder :global(.clip) {
    display: block;
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }
</style>
