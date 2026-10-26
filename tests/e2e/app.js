// The end-to-end run of zside-app on a local eCash regtest (run_app.py): the app starts and runs its node
// (thunder-orchard); the wallet's backup phrase is made (its words only in the trusted dialog); ECX is deposited from
// eCash through the mainchain interface's wallet; a transparent payment is sent to another zSide node and one received
// from it; a withdrawal to eCash is asked; then the shielded round trip: coins shielded, a private payment with a memo to
// node B's shielded address, node B's private payment back with a memo of its own (shown in Memos), coins unshielded;
// the withdrawal paid; every page pictured, in the dark and the light theme.
// window.__E2E: { peerAddress, peerShielded, memoBack, mainAddress, saveFile } from the runner.
(async () => {
  const { host, sleep, log, T, waitFor, check, snapshot, click, type, go, theme, finish, ready } = E2E;
  const overview = () => host('dropin.overview');
  const history = () => host('dropin.history', { limit: 100 });
  const shielded = () => host('zside.shielded');
  const ecx = 100_000_000;
  const MEMO = 'e2e: lunch money';
  try {
    await ready();
    await check('the app runs its node (phase ready, a tip)', T().app.phase === 'ready');
    await check('app.info is the node’s and the app’s', T().app.info.name === 'zSide' && T().app.info.hostApi === 1 && T().app.info.embedded === false);
    await go('home');
    await waitFor('the setup card', () => document.querySelector('.setup'));
    await snapshot('zside-01-first-start');

    // ---- the backup phrase: made by the node, shown in the trusted dialog (answered yes by the test), the wallet set
    await host('test.confirmAnswer', { yes: true });
    await click('Make a new backup phrase');
    await waitFor('the wallet set up', async () => (await host('dropin.seed.status')).hasSeed);
    const asked = await host('test.confirmed');
    const phraseQ = asked.find((q) => q.kind === 'node:phrase.create');
    await check('the phrase was asked in the trusted dialog, its words never recorded', !!phraseQ && phraseQ.details === '(the words, not recorded)');
    await check('the page got no words', !JSON.stringify(T().app).match(/\b(abandon|zoo)\b/));
    await go('home');
    await waitFor('the home with a wallet', () => !document.querySelector('.setup'));
    await snapshot('zside-02-wallet-ready');

    // ---- a deposit from eCash, paid by Backbone's wallet (-grpcwallet), to a bare transparent address
    await go('peg', 'deposit');
    await waitFor('the deposit form', () => document.querySelector('#dep-amount'));
    await snapshot('zside-03-deposit');
    type('#dep-amount', '10');
    await host('test.confirmAnswer', { yes: true });
    await click('Review and deposit');
    await log('SIGNAL deposit-sent');
    await waitFor('the deposit credited', async () => (await overview()).wallet.available >= 10 * ecx, 300000);
    const deposited = (await history()).find((r) => r.kind === 'deposit');
    await check('the deposit is in the activity', !!deposited && deposited.amount === 10 * ecx, JSON.stringify(deposited));
    const q1 = (await host('test.confirmed')).find((q) => q.kind === 'node:deposit');
    await check('the deposit was asked with its amount and a bare address', !!q1 && q1.rows.some((r) => r.label === 'Amount' && r.value === '10.00000000 ECX') && !q1.rows.some((r) => /^s98_/.test(r.value)));

    // ---- send to the other zSide node, in public (its transparent address)
    await go('send');
    type('#send-to', window.__E2E.peerAddress);
    await waitFor('the address checked', () => document.querySelector('.state.good'));
    type('#send-amount', '1.5');
    await snapshot('zside-04-send');
    await host('test.confirmAnswer', { yes: true });
    await click('Review and send');
    await waitFor('the payment sent', async () => (await history()).some((r) => r.kind === 'send'), 60000);
    const q2 = (await host('test.confirmed')).find((q) => q.kind === 'node:send');
    await check('the payment was asked with the recipient first', !!q2 && q2.rows[0].label === 'To' && q2.rows[0].value === window.__E2E.peerAddress);
    await waitFor('the payment in a block', async () => (await history()).some((r) => r.kind === 'send' && !r.pending), 300000);
    await log('SIGNAL sent');

    // ---- receive from it, at a transparent address
    await go('receive', 'transparent');
    const shown = await waitFor('an address shown', () => {
      const el = document.querySelector('#taddr-text');
      return el ? el.textContent.trim() : null;
    });
    await snapshot('zside-05-receive-transparent');
    await log(`SIGNAL receive-address ${shown}`);
    await waitFor('the payment received', async () => (await history()).some((r) => r.kind === 'receive' && !r.pending && r.amount === 0.25 * ecx), 300000);
    await check('a payment received at the address shown', true);

    // ---- withdraw to eCash: asked now, paid at the end (a bundle, voted)
    await go('peg', 'withdraw');
    type('#w-to', window.__E2E.mainAddress);
    await waitFor('the eCash address checked', () => document.querySelector('.state.good'));
    type('#w-amount', '2');
    await snapshot('zside-06-withdraw');
    await host('test.confirmAnswer', { yes: true });
    await click('Review and withdraw');
    await waitFor('the withdrawal asked', async () => (await host('dropin.peg')).withdrawals.length > 0, 60000);
    await log('SIGNAL withdrawal-asked');

    // ---- shield: transparent coins into the shielded balance
    await go('private', 'move');
    await waitFor('the shield form', () => document.querySelector('#shield-amount'));
    type('#shield-amount', '3');
    await snapshot('zside-07-shield');
    await host('test.confirmAnswer', { yes: true });
    await click('Review and shield');
    await waitFor('the shield sent', async () => (await history()).some((r) => r.kind === 'shield'), 120000);
    const qs = (await host('test.confirmed')).find((q) => q.kind === 'node:shield');
    await check('shielding was asked with its amount', !!qs && qs.rows.some((r) => r.value === '3.00000000 ECX'));
    await waitFor('the shield in a block', async () => (await history()).some((r) => r.kind === 'shield' && !r.pending), 300000);
    await waitFor('the shielded coins spendable (3 blocks deep)', async () => (await shielded()).balance.spendable >= 3 * ecx, 300000);
    const sh = (await history()).find((r) => r.kind === 'shield');
    await check('the shield row says what moved', sh && sh.moved === 3 * ecx, JSON.stringify(sh));

    // ---- a private payment with a memo to node B's shielded address
    await go('send');
    type('#send-to', window.__E2E.peerShielded);
    await waitFor('the shielded address checked', () => document.querySelector('.state.good') && document.querySelector('#send-memo'));
    type('#send-amount', '1');
    type('#send-memo', MEMO);
    await sleep(400);
    await snapshot('zside-08-send-privately');
    await host('test.confirmAnswer', { yes: true });
    await click('Review and send privately');
    await waitFor('the private payment sent', async () => (await history()).some((r) => r.kind === 'zsend'), 180000);
    const qz = (await host('test.confirmed')).find((q) => q.kind === 'node:send-shielded');
    await check('the private payment was asked with its memo', !!qz && qz.rows.some((r) => r.label === 'Memo' && r.value === MEMO) && qz.rows[0].value === window.__E2E.peerShielded);
    await waitFor('the private payment in a block', async () => (await history()).some((r) => r.kind === 'zsend' && !r.pending), 300000);
    const zs1 = (await history()).find((r) => r.kind === 'zsend');
    await check('the private payment’s row: the recipient, the memo sent', zs1.to[0].address === window.__E2E.peerShielded && zs1.to[0].amount === ecx && zs1.memo === MEMO && zs1.memoSent === true, JSON.stringify(zs1));

    // ---- node B pays back to a shielded address of this wallet, with its memo
    await go('receive');
    const zaddr = await waitFor('a shielded address shown', () => {
      const el = document.querySelector('#zaddr-text');
      return el ? el.textContent.trim() : null;
    });
    await check('the shielded address is one', zaddr.startsWith('t-shld1'));
    await snapshot('zside-09-receive-privately');
    await log(`SIGNAL zsent ${zaddr}`);
    const back = await waitFor('the private payment back, in a block', async () => (await history()).find((r) => r.kind === 'zreceive' && !r.pending), 600000);
    await check('received privately with node B’s memo', back.amount === 0.4 * ecx && back.memo === window.__E2E.memoBack && back.ownAddress === zaddr, JSON.stringify(back));
    const memos = await host('zside.memos');
    await check('Memos: the one received and the one sent', memos.some((m) => m.direction === 'in' && m.text === window.__E2E.memoBack) && memos.some((m) => m.direction === 'out' && m.text === MEMO), JSON.stringify(memos));
    await go('memos');
    await sleep(1200);
    await snapshot('zside-10-memos');

    // ---- unshield
    await waitFor('the change spendable again', async () => (await shielded()).balance.spendable >= 1.5 * ecx, 300000);
    await go('private', 'move');
    await waitFor('the unshield form', () => document.querySelector('#unshield-amount'));
    type('#unshield-amount', '1.5');
    await host('test.confirmAnswer', { yes: true });
    await click('Review and unshield');
    await waitFor('the unshield in a block', async () => (await history()).some((r) => r.kind === 'unshield' && !r.pending), 300000);
    const un = (await history()).find((r) => r.kind === 'unshield');
    await check('the unshield row says what moved', un.moved === 1.5 * ecx, JSON.stringify(un));
    await go('private', 'overview');
    await sleep(1200);
    await snapshot('zside-11-private');
    await go('transactions');
    await sleep(1500);
    await snapshot('zside-12-activity');

    // ---- the withdrawal paid
    await go('peg', 'bundles');
    await sleep(1500);
    await snapshot('zside-13-bundle');
    const paid = await waitFor('the withdrawal paid on eCash', async () => (await host('dropin.peg')).withdrawals.find((w) => w.state === 'paid'), 900000);
    await check('the withdrawal is paid on eCash', !!paid, JSON.stringify(paid));
    await log(`SIGNAL withdrawal-paid ${paid.m6id}`);
    await go('peg', 'bundles');
    await sleep(1500);
    await snapshot('zside-14-paid');

    // ---- the other pages, both themes
    for (const [mode, id] of [['dark', 'midnight'], ['light', 'light']]) {
      await theme(id);
      for (const [page, tab, name] of [['home', '', 'home'], ['overview', '', 'overview'], ['private', 'overview', 'private'], ['private', 'move', 'shield'], ['private', 'notes', 'notes'], ['send', '', 'send'], ['receive', '', 'receive'], ['receive', 'transparent', 'receive-transparent'], ['receive', 'addresses', 'addresses'], ['memos', '', 'memos'], ['pool', '', 'pool'], ['transactions', '', 'activity'], ['peg', 'deposit', 'drivechains'], ['explorer', '', 'explorer'], ['node', 'info', 'node'], ['node', 'peers', 'peers'], ['settings', 'dropnode', 'settings-node'], ['settings', 'dropwallet', 'settings-wallet']]) {
        await go(page, tab);
        await sleep(1200);
        await snapshot(`zside-${mode}-${name}`);
      }
    }
    await theme('midnight');

    // ---- a row of the activity: its dialog (the memo, the recipient)
    await go('transactions');
    await waitFor('rows listed', () => document.querySelectorAll('[role="row"]').length > 2, 30000);
    const rowEl = [...document.querySelectorAll('[role="row"]')].find((r) => r.textContent.includes('Received privately'));
    if (rowEl) rowEl.dispatchEvent(new MouseEvent('dblclick', { bubbles: true }));
    await sleep(1500);
    await snapshot('zside-15-private-receipt');
    document.dispatchEvent(new KeyboardEvent('keydown', { key: 'Escape', bubbles: true }));
    await sleep(500);

    // ---- the explorer: a block's details
    await go('explorer');
    await waitFor('blocks listed', () => document.querySelectorAll('[role="row"]').length > 2, 30000);
    const first = document.querySelector('[role="row"]:nth-child(2)') || document.querySelectorAll('[role="row"]')[1];
    if (first) first.dispatchEvent(new MouseEvent('dblclick', { bubbles: true }));
    await sleep(1500);
    await snapshot('zside-16-block');

    // ---- the backup phrase shown again: a question of the trusted dialog, never words in the page
    await go('settings', 'dropwallet');
    await host('test.confirmAnswer', { yes: true });
    await click('Show the phrase');
    await sleep(1000);
    const shownQ = (await host('test.confirmed')).filter((q) => q.kind === 'node:phrase.show');
    await check('showing the phrase is a question of the trusted dialog', shownQ.length === 1);

    // ---- saved to a file the user chose: asked, then written (the runner checks the file: owner-only, the words)
    await host('test.fileAnswer', { path: window.__E2E.saveFile });
    await host('test.confirmAnswer', { yes: true });
    await click('Save it to a file');
    await waitFor('the phrase saved', async () => (await host('test.confirmed')).some((q) => q.kind === 'node:phrase.save'), 30000);
    await sleep(1500);
    await log(`SIGNAL phrase-saved ${window.__E2E.saveFile}`);
  } catch (e) {
    await check('the run', false, e && e.stack ? e.stack : String(e));
  }
  await finish();
})();
