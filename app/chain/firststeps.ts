// The three first steps of zSide, on Home in Simple mode until dismissed.
import type { FirstStep } from '../lib/firststeps';

export const FIRST_STEPS: readonly FirstStep[] = [
  { title: 'Bring ECX here', text: 'Coins come from eCash. Drivechains gives an address to deposit to from an eCash wallet (the Backbone app: Sidechains → zSide). They arrive, public, with the next block of zSide.', icon: 'down', action: { label: 'Get a deposit address', page: 'peg', tab: 'deposit' } },
  { title: 'Make them private', text: 'Shield coins into your private balance: after that, nobody can see how much you hold or whom you pay.', icon: 'shield', action: { label: 'Shield', page: 'private', tab: 'move' } },
  { title: 'Send privately', text: 'Pay a shielded address (t-shld1…) from the Send page: only the recipient sees the amount and your memo.', icon: 'send', action: { label: 'Send', page: 'send' } },
];
