<script lang="ts">
  // The privacy of a balance, an address or a payment: Private (in the shielded pool: only the sender and the recipient
  // see the amount, the memo and who paid whom) or Public (transparent: on the chain for anyone to see), why in its tooltip.
  import Icon from '../../components/Icon.svelte';
  import { t } from '../../lib/i18n.svelte';

  let { kind, why = '' }: { kind: 'private' | 'public'; why?: string } = $props();

  const word = $derived(kind === 'private' ? t('Private') : t('Public'));
  const tip = $derived(
    why ||
      (kind === 'private'
        ? t('In the shielded pool: only the sender and the recipient see the amount, the memo and who paid whom.')
        : t('Transparent: the amount and the address are on the chain for anyone to see.')),
  );
</script>

<span class="zs-tag {kind}" title={tip} aria-label={`${word}: ${tip}`}><Icon name={kind === 'private' ? 'shield' : 'eye'} size={13} />{word}</span>
