<script lang="ts">
  // The wallet's overview on zSide: its two balances side by side (transparent: public; shielded: private) with the
  // moves between them, what comes in and what is being withdrawn, how much of the wallet is shielded, and its latest
  // activity (both balances').
  import Amount from '../../components/Amount.svelte';
  import Icon from '../../components/Icon.svelte';
  import { t } from '../../lib/i18n.svelte';
  import { go } from '../../lib/nav.svelte';
  import ActivityList from '../dropin/ActivityList.svelte';
  import SetupWallet from '../dropin/SetupWallet.svelte';
  import { sats } from '../dropin/api';
  import { drop, follow, wantHistory } from '../dropin/store.svelte';
  import Privacy from '../zs/Privacy.svelte';
  import Ring from '../zs/Ring.svelte';
  import { readShielded, shielded } from '../zs/store.svelte';
  import '../zs/zs.css';

  $effect(() => follow());
  $effect(() => wantHistory(20));
  $effect(() => {
    void drop.version;
    if (drop.seed?.hasSeed) void readShielded();
  });
  const w = $derived(drop.overview?.wallet);
  const z = $derived(shielded.data?.balance);
  const transparent = $derived(sats(w?.available));
  const shieldedAll = $derived(sats(z?.available));
  const share = $derived(shieldedAll + transparent > 0n ? Number(shieldedAll) / Number(shieldedAll + transparent) : 0);
  const settling = $derived(z && z.available > z.spendable ? sats(z.available - z.spendable) : 0n);
</script>

<div class="page zs drop-overview">
  <header class="page-head"><h1>{t('Overview')}</h1></header>
  {#if drop.seed && !drop.seed.hasSeed}
    <SetupWallet />
  {:else}
    <div class="zs-split">
      <section class="zs-vault public" aria-label={t('Transparent balance')}>
        <div class="head"><span class="label">{t('Transparent balance')}</span><Privacy kind="public" /></div>
        <span class="big"><Amount sats={transparent} /></span>
        <span class="sub">{t('Deposits from eCash arrive here; withdrawals to eCash leave from here.')}</span>
        <div class="row acts">
          <button type="button" class="btn small" onclick={() => go('send')}><Icon name="send" size={15} /> {t('Send')}</button>
          <button type="button" class="btn small" onclick={() => go('receive', 'transparent')}><Icon name="receive" size={15} /> {t('Receive')}</button>
        </div>
      </section>
      <div class="zs-moves">
        <button type="button" class="btn" onclick={() => go('private' as never, 'move')}><Icon name="shieldin" size={16} /> {t('Shield')}</button>
        <button type="button" class="btn ghost" onclick={() => go('private' as never, 'move')}><Icon name="shieldout" size={16} /> {t('Unshield')}</button>
      </div>
      <section class="zs-vault private" aria-label={t('Shielded balance')}>
        <div class="head"><span class="label">{t('Shielded balance')}</span><Privacy kind="private" /></div>
        <span class="big"><Amount sats={shieldedAll} /></span>
        <span class="sub">{#if settling > 0n}<Amount sats={settling} /> {t('of it can be spent once its notes are 3 blocks deep.')}{:else}{t('Nobody but you sees what it holds or whom it pays.')}{/if}</span>
        <div class="row acts">
          <button type="button" class="btn primary small" onclick={() => go('send')}><Icon name="send" size={15} /> {t('Send privately')}</button>
          <button type="button" class="btn small" onclick={() => go('receive')}><Icon name="receive" size={15} /> {t('Receive privately')}</button>
        </div>
      </section>
    </div>
    <div class="zs-tiles">
      <div class="zs-tile"><span class="k">{t('Coming in')}</span><span class="v"><Amount sats={sats(w?.pendingIn) + sats(z?.pendingIn)} /></span><span class="n">{t('In payments waiting for the next block.')}</span></div>
      <div class="zs-tile"><span class="k">{t('Being withdrawn')}</span><span class="v"><Amount sats={sats(w?.withdrawing)} /></span><span class="n">{t('On its way to eCash, in a withdrawal bundle.')}</span></div>
      <div class="zs-tile share">
        <Ring {share} size={56} label={t('%1% of the wallet is shielded', Math.round(share * 100))} />
        <div><span class="k">{t('Shielded')}</span><span class="n">{t('Of what the wallet holds, how much is in the shielded balance.')}</span></div>
      </div>
    </div>
    <section class="panel">
      <div class="panel-head row">
        <h2 class="grow">{t('Latest activity')}</h2>
        <button type="button" class="btn ghost small" onclick={() => go('transactions')}>{t('All activity')}</button>
      </div>
      <ActivityList rows={drop.history.slice(0, 20)} empty={drop.historyLoaded ? t('Nothing yet') : t('Reading…')} />
    </section>
  {/if}
</div>

<style>
  .drop-overview {
    display: flex;
    flex-direction: column;
    gap: 1rem;
  }
  .acts {
    gap: 0.4rem;
    margin-top: 0.35rem;
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
</style>
