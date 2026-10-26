// zSide's own pages beside the drop-in pages (chain/overrides.ts puts those in the kit's places): the shielded balance
// (shield and unshield, its notes), the memos the shielded account got and sent, and the shielded pool of the chain.
import type { IconName } from '../components/Icon.svelte';

export interface LocalPage {
  id: string;
  title: string;
  icon: IconName;
  summary: string;
  section: 'wallet' | 'chain' | 'tools';
  wallet?: boolean;
  shortcut?: string;
  keywords?: string;
  quick?: { label: string; icon?: IconName; tab?: string; simpleLabel?: string };
  simpleTitle?: string;
  advanced?: boolean;
  simple?: boolean;
  simpleSummary?: string;
  tabOf?: { page: string; tab: string };
}

export const LOCAL_PAGES = [
  { id: 'private', title: 'Private', simpleTitle: 'Private balance', simple: true, simpleSummary: 'Hold and pay without being seen', icon: 'private', section: 'wallet', summary: 'The shielded balance: shield and unshield, its notes and addresses', wallet: true, shortcut: 'Alt+6', keywords: 'shielded zside orchard private shield unshield notes', quick: { label: 'Shield', icon: 'shieldin', tab: 'move', simpleLabel: 'Make private' } },
  { id: 'memos', title: 'Memos', icon: 'memo', section: 'wallet', summary: 'The memos of shielded payments, received and sent', wallet: true, keywords: 'inbox messages memo received sent' },
  { id: 'pool', title: 'Shielded pool', icon: 'pool', section: 'chain', summary: 'What the chain’s shielded pool holds, its notes and its latest shielded transactions', keywords: 'orchard pool notes nullifiers tree root anonymity set', advanced: true },
] as const satisfies readonly LocalPage[];

export type LocalPageId = (typeof LOCAL_PAGES)[number]['id'];

export interface LocalCommand {
  id: string;
  label: string;
  page: LocalPageId;
  tab?: string;
  tip?: string;
  keywords?: string;
}

export const LOCAL_COMMANDS = [
  { id: 'zs.shield', label: 'Shield coins…', page: 'private', tab: 'move', tip: 'Move transparent coins into the shielded balance', keywords: 'shield private' },
  { id: 'zs.unshield', label: 'Unshield coins…', page: 'private', tab: 'move', tip: 'Move coins out of the shielded balance', keywords: 'unshield public' },
  { id: 'zs.notes', label: 'Shielded notes', page: 'private', tab: 'notes', tip: 'The notes the shielded balance is made of', keywords: 'notes coins orchard' },
] as const satisfies readonly LocalCommand[];
