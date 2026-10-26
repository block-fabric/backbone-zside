<script lang="ts">
  // Memos: what shielded payments said, received (by this wallet's viewing key) and sent (by its outgoing key): the
  // text the payer wrote, shown as data (SafeText); a memo that is not text, in hex. A CSV export to a file the user
  // chooses, each cell neutralised against spreadsheet formulas.
  import Amount from '../../components/Amount.svelte';
  import DataTable from '../../components/DataTable.svelte';
  import Icon from '../../components/Icon.svelte';
  import SafeText from '../../components/SafeText.svelte';
  import { CHAIN } from '../config';
  import { errorText } from '../../lib/dialogs.svelte';
  import { saveTextAs } from '../../lib/files';
  import { formatTime } from '../../lib/format';
  import { t } from '../../lib/i18n.svelte';
  import { go } from '../../lib/nav.svelte';
  import { prefs, toast } from '../../lib/state.svelte';
  import type { Column } from '../../lib/table';
  import { formatAmount, unitInfo } from '../../lib/units';
  import SetupWallet from '../dropin/SetupWallet.svelte';
  import { sats } from '../dropin/api';
  import { drop, follow } from '../dropin/store.svelte';
  import { memosCsv, zs, type Memo } from '../zs/api';
  import '../zs/zs.css';

  $effect(() => follow());
  let memos = $state<Memo[]>([]);
  let loaded = $state(false);
  let error = $state('');
  $effect(() => {
    void drop.version;
    if (!drop.seed?.hasSeed) return;
    zs.memos()
      .then((m) => ((memos = m), (loaded = true), (error = '')))
      .catch((e) => (error = errorText(e)));
  });

  let direction = $state<'' | 'in' | 'out'>('');
  let filter = $state('');
  let selected = $state<string | null>(null);
  let sortKey = $state<string | null>('date');
  let sortDir = $state<'asc' | 'desc'>('desc');
  const rows = $derived(direction ? memos.filter((m) => m.direction === direction) : memos);
  const latestIn = $derived(memos.find((m) => m.direction === 'in' && m.text));
  const columns: Column<Memo>[] = $derived([
    { key: 'date', label: 'Date', value: (m) => (m.pending ? Number.MAX_SAFE_INTEGER : (m.time ?? 0)), width: '10.5rem' },
    { key: 'dir', label: 'Direction', value: (m) => m.direction, width: '7.5rem' },
    { key: 'memo', label: 'Memo', value: (m) => m.text ?? m.hex ?? '', width: 'minmax(12rem, 2fr)' },
    { key: 'amount', label: `Amount (${unitInfo(prefs.unit).short})`, value: (m) => m.value, width: '10rem', align: 'end' },
    { key: 'address', label: 'Shielded address', value: (m) => m.address, width: 'minmax(9rem, 1fr)', mono: true },
  ]);

  async function exportCsv() {
    try {
      const path = await saveTextAs({ title: t('Export the memos'), name: `${CHAIN.bin}-memos.csv`, filters: [{ name: 'CSV', patterns: ['*.csv'] }] }, memosCsv(memos, (s) => formatAmount(s, prefs.unit)));
      if (path) toast('success', t('Exported'), path);
    } catch (e) {
      toast('error', t('Export failed'), errorText(e));
    }
  }
</script>

<div class="page zs zs-memos">
  <header class="page-head"><h1>{t('Memos')}</h1></header>
  {#if drop.seed && !drop.seed.hasSeed}
    <SetupWallet compact />
  {:else}
    {#if latestIn}
      <section class="panel latest" aria-label={t('The latest memo received')}>
        <div class="panel-body row">
          <span class="env"><Icon name="memo" size={22} /></span>
          <div class="grow">
            <div class="who muted">{t('The latest memo received')}{' · '}<Amount sats={sats(latestIn.value)} />{#if latestIn.time}{' · '}{formatTime(latestIn.time)}{/if}</div>
            <p class="zs-memo text"><SafeText text={latestIn.text} /></p>
          </div>
        </div>
      </section>
    {/if}
    <div class="row head">
      <select aria-label={t('Direction')} bind:value={direction}>
        <option value="">{t('All')}</option>
        <option value="in">{t('Received')}</option>
        <option value="out">{t('Sent')}</option>
      </select>
      <input type="search" class="grow" placeholder={t('Search')} aria-label={t('Search the memos')} bind:value={filter} />
      <button type="button" class="btn small" onclick={exportCsv} disabled={memos.length === 0}><Icon name="download" size={15} /> {t('Export…')}</button>
    </div>
    {#if error}<p class="error" role="alert">{error}</p>{/if}
    <div class="holder">
      <DataTable {rows} {columns} key={(m) => m.txid + m.direction + m.address + m.value} {filter} bind:selected bind:sortKey bind:sortDir label={t('Memos')} fit empty={loaded ? t('No memo yet: memos come with shielded payments.') : t('Reading…')}>
        {#snippet cell(m, column)}
          {#if column.key === 'date'}{#if m.pending}<span class="badge warning">{t('pending')}</span>{:else if m.time}{formatTime(m.time)}{:else}<span class="faint">–</span>{/if}
          {:else if column.key === 'dir'}<span class="dir {m.direction}"><Icon name={m.direction === 'in' ? 'receive' : 'send'} size={13} /> {m.direction === 'in' ? t('Received') : t('Sent')}</span>
          {:else if column.key === 'memo'}{#if m.text !== undefined}<SafeText class="clip" title={m.text} text={m.text} />{:else}<span class="faint mono clip" title={t('A memo that is not text')}>0x{m.hex}</span>{/if}
          {:else if column.key === 'amount'}<Amount sats={sats(m.value)} showUnit={false} />
          {:else}<span class="mono clip" title={m.address}>{m.address}</span>{/if}
        {/snippet}
      </DataTable>
    </div>
    <p class="hint">{t('A memo travels inside a shielded payment: only its sender and its recipient can read it.')} <button type="button" class="linkish" onclick={() => go('send')}>{t('Send one')}</button></p>
  {/if}
</div>

<style>
  .zs-memos {
    display: flex;
    flex-direction: column;
    gap: 0.8rem;
    height: 100%;
  }
  .latest .panel-body {
    gap: 0.9rem;
    align-items: flex-start;
    padding: 1rem 1.15rem;
  }
  .env {
    display: grid;
    place-items: center;
    width: 2.6rem;
    height: 2.6rem;
    flex: none;
    border-radius: 0.8rem;
    background: color-mix(in srgb, var(--brand, var(--accent)) 14%, transparent);
    color: var(--brand, var(--accent));
  }
  .who {
    font-size: 0.85rem;
  }
  .text {
    margin: 0.3rem 0 0;
    font-size: 1.05rem;
  }
  .head {
    gap: 0.5rem;
    flex-wrap: nowrap;
  }
  .head select {
    width: 10rem;
    flex: none;
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
  .dir {
    display: inline-flex;
    align-items: center;
    gap: 0.3rem;
  }
  .hint {
    color: var(--text-muted);
    font-size: 0.85rem;
    margin: 0;
  }
  .linkish {
    background: none;
    border: 0;
    padding: 0;
    color: var(--accent);
    cursor: pointer;
    font: inherit;
  }
  .error {
    color: var(--negative);
  }
</style>
