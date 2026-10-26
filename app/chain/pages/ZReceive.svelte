<script lang="ts">
  // Receive on zSide: a shielded address (t-shld1…: paid privately, into the shielded balance; every new one pays the
  // same account and none can be linked to another), or a transparent one (paid in public; what a deposit from eCash
  // names). Its Addresses tab: every address of the wallet, of both kinds, and what each received.
  import Amount from '../../components/Amount.svelte';
  import CopyButton from '../../components/CopyButton.svelte';
  import DataTable from '../../components/DataTable.svelte';
  import Icon from '../../components/Icon.svelte';
  import QrCode from '../../components/QrCode.svelte';
  import TabRow from '../../components/TabRow.svelte';
  import { CHAIN } from '../config';
  import { errorText } from '../../lib/dialogs.svelte';
  import { t } from '../../lib/i18n.svelte';
  import { go, nav } from '../../lib/nav.svelte';
  import { prefs } from '../../lib/state.svelte';
  import type { Column } from '../../lib/table';
  import { unitInfo } from '../../lib/units';
  import SetupWallet from '../dropin/SetupWallet.svelte';
  import { dropin, sats } from '../dropin/api';
  import { drop, follow } from '../dropin/store.svelte';
  import { zs } from '../zs/api';
  import Privacy from '../zs/Privacy.svelte';
  import { readShielded, shielded } from '../zs/store.svelte';
  import '../zs/zs.css';

  $effect(() => follow());

  const TABS = [
    { id: '', label: 'Private' },
    { id: 'transparent', label: 'Transparent' },
    { id: 'addresses', label: 'Addresses' },
  ];
  const tab = $derived(TABS.some((x) => x.id === nav.tab) ? nav.tab : '');
  const hasSeed = $derived(!!drop.seed?.hasSeed);

  let zaddr = $state<string | null>(null);
  let taddr = $state<string | null>(null);
  let error = $state('');
  let busy = $state(false);

  $effect(() => {
    void drop.version;
    if (hasSeed) void readShielded();
  });
  // The shielded address shown: one of the wallet's (made now when it has none).
  $effect(() => {
    if (!hasSeed || zaddr || busy || !shielded.data) return;
    const known = shielded.data.addresses ?? [];
    if (known.length) zaddr = known[0].address;
    else void newShielded();
  });
  $effect(() => {
    if (hasSeed && tab === 'transparent' && !taddr) void newTransparent();
  });

  async function newShielded() {
    busy = true;
    error = '';
    try {
      zaddr = (await zs.newShieldedAddress()).address;
      void readShielded(true);
    } catch (e) {
      error = errorText(e);
    } finally {
      busy = false;
    }
  }
  async function newTransparent() {
    busy = true;
    error = '';
    try {
      taddr = (await dropin.newAddress()).address;
    } catch (e) {
      error = errorText(e);
    } finally {
      busy = false;
    }
  }

  type Addr = { address: string; kind: 'shielded' | 'transparent'; received: number; balance: number | null };
  let transparentList = $state<{ address: string; balance: number; received: number }[]>([]);
  $effect(() => {
    void drop.version;
    if (hasSeed && tab === 'addresses')
      dropin
        .addresses()
        .then((a) => (transparentList = a))
        .catch((e) => (error = errorText(e)));
  });
  const rows = $derived<Addr[]>([
    ...(shielded.data?.addresses ?? []).map((a) => ({ address: a.address, kind: 'shielded' as const, received: a.received, balance: null })),
    ...transparentList.map((a) => ({ address: a.address, kind: 'transparent' as const, received: a.received, balance: a.balance })),
  ]);
  let filter = $state('');
  let selected = $state<string | null>(null);
  let sortKey = $state<string | null>('received');
  let sortDir = $state<'asc' | 'desc'>('desc');
  const columns: Column<Addr>[] = $derived([
    { key: 'kind', label: 'Kind', value: (r) => r.kind, width: '8.5rem' },
    { key: 'address', label: 'Address', value: (r) => r.address, width: 'minmax(14rem, 1fr)', mono: true },
    { key: 'received', label: `Received (${unitInfo(prefs.unit).short})`, value: (r) => r.received, width: '11rem', align: 'end' },
    { key: 'balance', label: `Holds (${unitInfo(prefs.unit).short})`, value: (r) => r.balance ?? -1, width: '10rem', align: 'end' },
  ]);
</script>

<div class="page zs zs-receive">
  <header class="page-head"><h1>{t('Receive')}</h1></header>
  <TabRow label="Receive" tabs={TABS} current={tab} select={(id) => (nav.tab = id)} />

  {#if drop.seed && !hasSeed}
    <SetupWallet compact />
  {:else if tab === 'addresses'}
    <div class="row head">
      <h2 class="grow">{t('Addresses of this wallet')}</h2>
      <input type="search" placeholder={t('Search')} aria-label={t('Search the addresses')} bind:value={filter} />
    </div>
    <div class="holder">
      <DataTable {rows} {columns} key={(r) => r.address} {filter} bind:selected bind:sortKey bind:sortDir label={t('Addresses')} fit empty={t('No address yet')}>
        {#snippet cell(row, column)}
          {#if column.key === 'kind'}<Privacy kind={row.kind === 'shielded' ? 'private' : 'public'} />
          {:else if column.key === 'address'}<span class="mono clip" title={row.address}>{row.address}</span>
          {:else if column.key === 'received'}<Amount sats={sats(row.received)} showUnit={false} />
          {:else if row.balance === null}<span class="faint" title={t('The shielded balance is the account’s, not an address’s')}>–</span>
          {:else}<Amount sats={sats(row.balance)} showUnit={false} />{/if}
        {/snippet}
      </DataTable>
    </div>
  {:else if tab === 'transparent'}
    <div class="layout">
      <section class="panel addr" aria-labelledby="taddr-title">
        <div class="panel-head row"><h2 id="taddr-title" class="grow">{t('Your transparent address')}</h2><Privacy kind="public" /></div>
        <div class="panel-body">
          {#if taddr}
            <div class="qr"><QrCode text={taddr} size={196} label={t('QR code of the address')} /></div>
            <div class="row copyrow"><span id="taddr-text" class="mono big break">{taddr}</span><CopyButton text={taddr} label={t('Copy the address')} /></div>
            <p class="hint">{t('Payments to it are public: anyone sees the amount and the address. A new one each time keeps your payments apart.')}</p>
          {:else}
            <p class="muted">{busy ? t('Making an address…') : error}</p>
          {/if}
          <div class="row"><button type="button" class="btn" disabled={busy} onclick={newTransparent}><Icon name="plus" size={16} /> {t('New address')}</button></div>
        </div>
      </section>
      <section class="panel" aria-labelledby="dep-title">
        <div class="panel-head"><h2 id="dep-title">{t('From eCash')}</h2></div>
        <div class="panel-body">
          <p class="muted">{t('A deposit from eCash names a transparent address of %1, exactly as it is (this one, or any of the wallet’s): its coins arrive in the transparent balance with the next block. Pay it from an eCash wallet that makes drivechain deposits (the Backbone app: Sidechains → %1, slot 98), or deposit through this node on the Drivechains page.', CHAIN.name)}</p>
          <div class="zs-note public"><Icon name="alert" size={16} /><span>{t('Give the plain address above, never an “s98_…” deposit text: zSide credits a deposit only to the plain address, and loses one made to anything else.')}</span></div>
          <button type="button" class="btn small" onclick={() => go('peg', 'deposit')}><Icon name="down" size={15} /> {t('Deposit…')}</button>
        </div>
      </section>
    </div>
  {:else}
    <div class="layout">
      <section class="panel addr" aria-labelledby="zaddr-title">
        <div class="panel-head row"><h2 id="zaddr-title" class="grow">{t('Your shielded address')}</h2><Privacy kind="private" /></div>
        <div class="panel-body">
          {#if zaddr}
            <div class="qr"><QrCode text={zaddr} size={196} label={t('QR code of the shielded address')} /></div>
            <div class="row copyrow"><span id="zaddr-text" class="mono big break">{zaddr}</span><CopyButton text={zaddr} label={t('Copy the shielded address')} /></div>
            <p class="hint">{t('Payments to it go into your shielded balance: the chain shows neither the amount nor who paid you. A memo the payer writes is for you alone.')}</p>
          {:else}
            <p class="muted">{busy ? t('Making an address…') : error || t('Reading the wallet…')}</p>
          {/if}
          <div class="row"><button type="button" class="btn" disabled={busy} onclick={newShielded}><Icon name="plus" size={16} /> {t('New shielded address')}</button></div>
        </div>
      </section>
      <section class="panel" aria-labelledby="why-title">
        <div class="panel-head"><h2 id="why-title">{t('One account, many addresses')}</h2></div>
        <div class="panel-body">
          <p class="muted">{t('Every shielded address of this wallet pays the same shielded balance, and nobody can tell that two of them are the same wallet’s: give each payer its own.')}</p>
          <p class="muted">{t('Coins from eCash arrive in the transparent balance; shield them to make them private.')}</p>
          <div class="row">
            <button type="button" class="btn small" onclick={() => (nav.tab = 'transparent')}><Icon name="eye" size={15} /> {t('A transparent address')}</button>
            <button type="button" class="btn small" onclick={() => go('private' as never, 'move')}><Icon name="shieldin" size={15} /> {t('Shield coins')}</button>
          </div>
        </div>
      </section>
    </div>
  {/if}
</div>

<style>
  .zs-receive {
    display: flex;
    flex-direction: column;
    gap: 1rem;
    height: 100%;
  }
  .layout {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(20rem, 1fr));
    gap: 1rem;
    align-items: start;
  }
  .panel-body {
    display: flex;
    flex-direction: column;
    gap: 0.8rem;
  }
  .panel-head {
    gap: 0.6rem;
  }
  .qr {
    display: grid;
    place-items: center;
    padding: 0.6rem;
    background: #fff;
    border-radius: 0.75rem;
    width: max-content;
    align-self: center;
  }
  .copyrow {
    display: grid;
    grid-template-columns: minmax(0, 1fr) auto;
    gap: 0.4rem;
    align-items: center;
  }
  .big {
    font-size: 0.95rem;
    line-height: 1.45;
  }
  .break {
    word-break: break-all;
  }
  .hint {
    color: var(--text-muted);
    font-size: 0.85rem;
    margin: 0;
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
