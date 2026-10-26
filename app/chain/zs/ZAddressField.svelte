<script lang="ts">
  // A zSide address typed or pasted: transparent (base58) or shielded (t-shld1…), checked by the node as it is typed
  // (dropin.checkAddress), never guessed here; its kind said, the wrong kind for the form said in words.
  import Icon from '../../components/Icon.svelte';
  import { t } from '../../lib/i18n.svelte';
  import { host } from '../../lib/rpc';
  import { request } from '../../lib/bridge';

  let {
    value = $bindable(''),
    valid = $bindable(false),
    kind = $bindable(''),
    id,
    label,
    accept = 'any',
    placeholder = '',
    disabled = false,
  }: {
    value?: string;
    valid?: boolean;
    kind?: '' | 'transparent' | 'shielded';
    id: string;
    label: string;
    accept?: 'any' | 'transparent' | 'shielded';
    placeholder?: string;
    disabled?: boolean;
  } = $props();

  let error = $state('');
  let mine = $state(false);
  let checking = $state(false);
  let seq = 0;

  $effect(() => {
    const text = value.trim();
    const mySeq = ++seq;
    valid = false;
    kind = '';
    mine = false;
    error = '';
    if (!text) return;
    checking = true;
    const timer = setTimeout(async () => {
      try {
        const params: Record<string, unknown> = { address: text };
        if (accept !== 'any') params.side = accept;
        const r = await request<{ valid: boolean; kind?: 'transparent' | 'shielded'; mine?: boolean; error?: string }>('host', 'dropin.checkAddress', params);
        if (mySeq !== seq) return;
        valid = r.valid;
        kind = r.valid ? (r.kind ?? '') : '';
        mine = !!r.mine;
        error = r.valid ? '' : (r.error ?? 'not an address');
      } catch (e) {
        if (mySeq === seq) error = e instanceof Error ? e.message : String(e);
      } finally {
        if (mySeq === seq) checking = false;
      }
    }, 180);
    return () => clearTimeout(timer);
  });

  async function paste() {
    try {
      const text = await host.paste();
      if (text) value = text.trim();
    } catch {
      // Not right after a gesture: the clipboard stays closed.
    }
  }
</script>

<div class="field addr">
  <label for={id}>{label}</label>
  <div class="row">
    <input {id} type="text" class="mono grow" spellcheck="false" autocomplete="off" {placeholder} {disabled} bind:value aria-invalid={!!error} aria-describedby="{id}-state" />
    <button type="button" class="btn ghost icon" title={t('Paste')} aria-label={t('Paste')} {disabled} onclick={paste}><Icon name="paste" size={16} /></button>
  </div>
  <span id="{id}-state" class="state" class:bad={!!error} class:good={valid}>
    {#if !value.trim()}&nbsp;
    {:else if checking}{t('Checking…')}
    {:else if error}<Icon name="alert" size={13} /> {t(error)}
    {:else if valid && kind === 'shielded'}<Icon name="shield" size={13} /> {mine ? t('A shielded address of this wallet') : t('A shielded address: a private payment')}
    {:else if valid}<Icon name="check" size={13} /> {mine ? t('A transparent address of this wallet') : t('A transparent address: a public payment')}
    {/if}
  </span>
</div>

<style>
  .addr .row {
    gap: 0.35rem;
  }
  .state {
    font-size: 0.82rem;
    color: var(--text-muted);
    min-height: 1.1rem;
    display: inline-flex;
    align-items: center;
    gap: 0.3rem;
  }
  .state.bad {
    color: var(--negative);
  }
  .state.good {
    color: var(--positive);
  }
</style>
