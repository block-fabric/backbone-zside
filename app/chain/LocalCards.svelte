<script lang="ts">
  // zSide's card on Home: the shielded balance beside the transparent one, how much of the wallet is shielded, and the
  // moves (shield; pay privately).
  import Amount from '../components/Amount.svelte';
  import Icon from '../components/Icon.svelte';
  import Card from '../views/home/Card.svelte';
  import { t } from '../lib/i18n.svelte';
  import { go } from '../lib/nav.svelte';
  import { sats } from './dropin/api';
  import { drop } from './dropin/store.svelte';
  import Ring from './zs/Ring.svelte';
  import { readShielded, shielded } from './zs/store.svelte';
  import './zs/zs.css';

  const hasSeed = $derived(!!drop.seed?.hasSeed);
  $effect(() => {
    void drop.version;
    if (hasSeed) void readShielded();
  });
  const b = $derived(shielded.data?.balance);
  const transparent = $derived(sats(drop.overview?.wallet.available) + sats(drop.overview?.wallet.pendingIn));
  const shieldedAll = $derived(sats(b?.available) + sats(b?.pendingIn));
  const share = $derived(shieldedAll + transparent > 0n ? Number(shieldedAll) / Number(shieldedAll + transparent) : 0);
</script>

<Card title={t('Shielded balance')} icon="private" open={() => go('private' as never)} openLabel={t('Open Private')} stat>
  {#if hasSeed && b}
    <div class="row top">
      <div class="big grow"><Amount sats={sats(b.available)} /></div>
      <Ring {share} size={56} label={t('%1% of the wallet is shielded', Math.round(share * 100))} />
    </div>
    <dl class="facts">
      {#if b.pendingIn}<dt>{t('Incoming')}</dt><dd><Amount sats={sats(b.pendingIn)} /></dd>{/if}
      {#if b.available > b.spendable}<dt>{t('Settling (3 blocks)')}</dt><dd><Amount sats={sats(b.available - b.spendable)} /></dd>{/if}
      {#if b.available === b.spendable && !b.pendingIn}<dt>{t('Private')}</dt><dd>{t('%1% of the wallet', Math.round(share * 100))}</dd>{/if}
    </dl>
  {:else}
    <p class="muted">{hasSeed ? t('Reading the wallet…') : t('No wallet yet')}</p>
  {/if}
  {#snippet actions()}
    <button type="button" class="btn small" disabled={!hasSeed} onclick={() => go('private' as never, 'move')}><Icon name="shieldin" size={15} /> {t('Shield')}</button>
    <button type="button" class="btn small" disabled={!hasSeed} onclick={() => go('send')}><Icon name="send" size={15} /> {t('Send privately')}</button>
  {/snippet}
</Card>

<style>
  .top {
    align-items: center;
    gap: 0.8rem;
    margin-top: -0.35rem;
  }
  .big {
    font-size: 1.65rem;
    font-weight: 650;
    min-width: 0;
  }
  .facts {
    display: grid;
    grid-template-columns: max-content 1fr;
    gap: 0.25rem 0.9rem;
    margin: 0;
    font-size: 0.88rem;
  }
  .facts dt {
    color: var(--text-muted);
  }
  .facts dd {
    margin: 0;
    text-align: end;
  }
</style>
