<script lang="ts">
  // The shielded pool of zSide (the chain's, no wallet in it): what it holds (what went in less what came out), its notes
  // (every Orchard note commitment) and the spent ones (nullifiers), the root of its note commitment tree, how busy it is
  // (actions per block) and its latest shielded transactions, each opening its block in the explorer.
  import Amount from '../../components/Amount.svelte';
  import Icon from '../../components/Icon.svelte';
  import Sparkline from '../../components/Sparkline.svelte';
  import CopyButton from '../../components/CopyButton.svelte';
  import { errorText } from '../../lib/dialogs.svelte';
  import { formatCount, formatTime, shortHash } from '../../lib/format';
  import { t } from '../../lib/i18n.svelte';
  import { goTo } from '../../lib/nav.svelte';
  import { sats } from '../dropin/api';
  import { drop, follow } from '../dropin/store.svelte';
  import { zs, type Pool } from '../zs/api';
  import '../zs/zs.css';

  $effect(() => follow());
  let pool = $state<Pool | null>(null);
  let error = $state('');
  $effect(() => {
    void drop.version;
    zs.pool()
      .then((p) => ((pool = p), (error = '')))
      .catch((e) => (error = errorText(e)));
  });
  const share = $derived(pool && pool.wealth > 0 ? Math.max(0, Math.min(1, pool.value / pool.wealth)) : 0);
  const kindText = (k: string) => (k === 'shield' ? t('Shield') : k === 'unshield' ? t('Unshield') : t('Private payment'));
</script>

<div class="page zs zs-pool">
  <header class="page-head"><h1>{t('Shielded pool')}</h1></header>
  {#if error}<p class="error" role="alert">{error}</p>{/if}
  <div class="zs-tiles">
    <div class="zs-tile"><span class="k">{t('In the pool')}</span><span class="v"><Amount sats={sats(pool?.value)} /></span><span class="n">{pool ? t('%1% of what zSide holds for eCash', (share * 100).toFixed(1)) : '–'}</span></div>
    <div class="zs-tile"><span class="k">{t('Notes')}</span><span class="v num">{pool ? formatCount(pool.commitments) : '–'}</span><span class="n">{t('Every shielded output ever made (with the padding ones)')}</span></div>
    <div class="zs-tile"><span class="k">{t('Nullifiers')}</span><span class="v num">{pool ? formatCount(pool.nullifiers) : '–'}</span><span class="n">{t('One an action: a spent note shows only as one of these')}</span></div>
    <div class="zs-tile"><span class="k">{t('Shielded transactions')}</span><span class="v num">{pool ? formatCount(pool.bundles) : '–'}</span><span class="n">{pool ? t('in %1 · private %2 · out %3', pool.shields, pool.privateOnly, pool.unshields) : ''}</span></div>
  </div>
  <div class="zs-cols">
    <section class="panel" aria-labelledby="tree-title">
      <div class="panel-head"><h2 id="tree-title">{t('Note commitment tree')}</h2></div>
      <div class="panel-body stack">
        <span class="muted">{t('Its root at the tip (block %1): a payment proves its notes are in the tree at a root like this one, without saying which.', pool ? formatCount(pool.height) : '–')}</span>
        {#if pool}<div class="row copyrow"><code class="zs-code grow">{pool.root}</code><CopyButton text={pool.root} label={t('Copy the root')} /></div>{/if}
        <span class="faint small">{t('%1 roots in its history', pool ? formatCount(pool.historicalRoots) : '–')}</span>
      </div>
    </section>
    <section class="panel" aria-labelledby="act-title">
      <div class="panel-head"><h2 id="act-title">{t('Shielded actions per block')}</h2></div>
      <div class="panel-body stack">
        {#if pool && pool.blocks.length}
          <Sparkline values={pool.blocks.map((b) => b.actions)} width={420} height={64} />
          <span class="faint small">{t('The last %1 blocks: %2 actions', pool.blocks.length, pool.blocks.reduce((s, b) => s + b.actions, 0))}</span>
        {:else}
          <span class="muted">{t('No block yet.')}</span>
        {/if}
      </div>
    </section>
  </div>
  <section class="panel" aria-labelledby="rec-title">
    <div class="panel-head"><h2 id="rec-title">{t('Latest shielded transactions')}</h2></div>
    <div class="panel-body">
      {#if pool && pool.recent.length}
        <ul class="zs-list">
          {#each pool.recent as r (r.txid)}
            <li class="rec">
              <span class="ico {r.kind}"><Icon name={r.kind === 'shield' ? 'shieldin' : r.kind === 'unshield' ? 'shieldout' : 'shield'} size={16} /></span>
              <div class="grow">
                <strong>{kindText(r.kind)}</strong>
                <span class="mono faint">{shortHash(r.txid, 10)}</span>
              </div>
              <span class="muted small">{t('%1 actions', r.actions)}</span>
              <span class="vb">{#if r.kind === 'private'}<span class="faint">{t('amount hidden')}</span>{:else}<Amount sats={sats(Math.abs(r.valueBalance))} />{/if}</span>
              <span class="when muted small">{r.time ? formatTime(r.time) : t('block %1', r.height)}</span>
              {#if r.block}<button type="button" class="btn ghost small" onclick={() => goTo('explorer', '', r.block ?? '')} title={t('Open its block')} aria-label={t('Open its block')}><Icon name="block" size={15} /></button>{/if}
            </li>
          {/each}
        </ul>
      {:else}
        <p class="muted">{pool ? t('No shielded transaction yet.') : t('Reading…')}</p>
      {/if}
    </div>
  </section>
</div>

<style>
  .zs-pool {
    display: flex;
    flex-direction: column;
    gap: 1rem;
  }
  .stack {
    display: flex;
    flex-direction: column;
    gap: 0.6rem;
  }
  .copyrow {
    gap: 0.4rem;
    align-items: center;
  }
  .small {
    font-size: 0.82rem;
  }
  .rec {
    display: flex;
    align-items: center;
    gap: 0.75rem;
    padding: 0.55rem 0.1rem;
  }
  .rec .grow {
    display: flex;
    flex-direction: column;
    min-width: 0;
  }
  .ico {
    display: grid;
    place-items: center;
    width: 2rem;
    height: 2rem;
    border-radius: 0.6rem;
    flex: none;
    background: color-mix(in srgb, var(--brand, var(--accent)) 13%, transparent);
    color: var(--brand, var(--accent));
  }
  .ico.unshield,
  .ico.shield {
    background: color-mix(in srgb, var(--warning) 13%, transparent);
    color: var(--warning);
  }
  .vb {
    min-width: 9rem;
    text-align: end;
  }
  .when {
    min-width: 8.5rem;
    text-align: end;
  }
  .error {
    color: var(--negative);
  }
</style>
