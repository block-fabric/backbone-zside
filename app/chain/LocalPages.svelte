<script lang="ts">
  // The pages zSide draws: the drop-in pages in the kit's places (chain/overrides.ts), its own overview, Send and Receive
  // (two balances), and its own pages (chain/local.ts).
  import Explorer from './dropin/Explorer.svelte';
  import History from './dropin/History.svelte';
  import Home from './dropin/Home.svelte';
  import NodePage from './dropin/NodePage.svelte';
  import Peg from './dropin/Peg.svelte';
  import Memos from './pages/Memos.svelte';
  import Pool from './pages/Pool.svelte';
  import Private from './pages/Private.svelte';
  import ZOverview from './pages/ZOverview.svelte';
  import ZReceive from './pages/ZReceive.svelte';
  import ZSend from './pages/ZSend.svelte';
  let { page }: { page: string } = $props();
</script>

{#if page === 'home'}<Home />
{:else if page === 'overview'}<ZOverview />
{:else if page === 'send'}<ZSend />
{:else if page === 'receive'}<ZReceive />
{:else if page === 'transactions'}<History />
{:else if page === 'peg'}<Peg />
{:else if page === 'explorer'}<Explorer />
{:else if page === 'node'}<NodePage />
{:else if page === 'private'}<Private />
{:else if page === 'memos'}<Memos />
{:else if page === 'pool'}<Pool />
{/if}
