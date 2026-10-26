# zside-app: our app on the zSide drop-in

`zside-app` is zSide with our sidechain app: the sidechain template's window, trusted dialog and interface kit, with
pages for zSide's own data model (a transparent balance of UTXOs, a shielded balance of Orchard notes, the memos of
shielded payments, the shielded pool, withdrawal bundles, eCash as the mainchain). The node is LayerTwo's
`thunder-orchard` (this repository's drop-in), next to the app, unchanged: the app starts it as its child and talks to
its app RPC. Consensus, P2P and the LayerTwo JSON-RPC (thunder-orchard b225827, 44 methods) are the drop-in's own and
stay byte for byte what they are; the app layer is off unless the node is started with `--bt-app-rpc-port`.

The design shared by every drop-in app (why a thin client, the app RPC, the privileges, one backup phrase by BIP-85,
the pack, security, tests) is [core/doc/app.md](../core/doc/app.md). This page is zSide's part.

## Build and run

```
cmake -S . -B build-app -DBT_BUILD_APP=ON -DBT_KIT_DIR=<sidechain-template repo>   # GTK 3 + WebKitGTK 4.1, npm
cmake --build build-app -j4
build-app/chains/zside/zside-app                  # betanet, the enforcer at http://localhost:50051
build-app/chains/zside/zside-app --network regtest --mainchain-grpc-url http://127.0.0.1:50051
cmake --build build-app --target zside-app-pack   # build-app/pack/zside: the pack for the unified wallet
```

The app is `zside-app` (the stem `zside`, the unified wallet's catalog id); the node it runs is `thunder-orchard`,
next to it (`app/manifest.json`: `"program": "thunder-orchard"`), with LayerTwo's data folder by default
(`<data_dir>/thunder-orchard`: `"datadirName"`), so an existing thunder-orchard wallet is the app's. `app/kit.commit`
pins the sidechain template (branch `dropin-kit`). The app's options are Thunder's (`--network`, `--datadir`,
`--mainchain-grpc-url`, `--rpc-port`, `--p2p-port`, `--app-rpc-port`, `--node-arg=<arg>`), also in Settings → Node.

## One backup phrase

The wallet is BIP-39 (tiny-bip39, no passphrase), and everything in it comes from that seed: the transparent keys
(m/43'/1899'/0'/98'/0'/i, BLAKE3 "bip32ish") and the Orchard spending key (the m/43'/1899'/0'/98'/2'/0' scalar as the
ZIP-32 seed, coin 0, account 0), so its shielded addresses and notes too. The unified wallet's BIP-85 phrase (core/doc/app.md
§3, stem `zside`) therefore covers the whole wallet, shielded coins included: `getwalletphraseinfo`/`setwalletphrase`
and `dropin.seed.*` work as for Thunder, and no part needs a backup of its own. Vectors (master "abandon ×11 about"),
checked against an independent implementation:

| stem, network | index | phrase | fingerprint |
|---|---|---|---|
| zside, betanet | 859980934 | debate wedding craft path drip afraid special renew text wrong flag praise | 879486a2c5decd21 |
| zside, regtest | 2109803093 | civil fox reject monitor clock vacant captain allow hood buffalo maze social | c6669596e00dd339 |

A wallet made with `--bt-wallet-derivation v0.18.0` (thunder-orchard 0.18.0's HMAC keys) says so in
`getwalletphraseinfo`'s `derivation`; the phrase is the same, the keys LayerTwo's of that version.

## The pages

The drop-in pages (`core/app/ui`) in the kit's places: Home (the transparent balance, the network and the eCash
link, Drivechains, zSide's shielded-balance card, the latest activity), Activity, Drivechains, the block explorer, the
node, Settings → Node and → Wallet. zSide's own (`app/chain`):

- **Overview**: the two balances side by side, transparent (public) and shielded (private), the moves between them,
  what comes in and what is being withdrawn, how much of the wallet is shielded, the latest activity.
- **Send**: the kind of the address decides. To a shielded address (`t-shld1…`): out of the shielded balance,
  privately, with an optional memo (`create_shielded_transfer`); to a transparent one: out of the transparent balance,
  in public (`create_transparent_transfer`). The amount offered is what can be spent now: their wallet spends a note
  only under the anchor 3 blocks below the tip, so a note newer than that is shown as settling.
- **Receive**: a shielded address of the wallet with its QR code (a new one on demand: every one pays the same
  account and none can be linked to another), a transparent one, and every address of the wallet of both kinds.
- **Private**: the shielded balance, **Shield** (`create_shield`: transparent coins to a new shielded address of the
  wallet) and **Unshield** (`create_unshield`: to a new transparent address of the wallet), its notes (which can be
  spent now, their memos).
- **Memos**: what shielded payments said, received (the wallet's incoming viewing key) and sent (its outgoing viewing
  key: the wallet's bundles are built with it), as data (SafeText; a memo that is not text in hex); CSV export.
- **Shielded pool** (Advanced): what the pool holds, its notes and nullifiers, the root of its note commitment tree,
  actions per block, the latest shielded transactions (the chain's: no wallet data).

The activity has zSide's kinds: shielded, unshielded (each with what moved), sent privately (the recipient's shielded
address and the memo sent), received privately (the shielded address it came to and its memo), within the shielded
balance. Memos and every other text from the chain are data: SafeText, never translated; the CSV exports go through the
kit's `toCsv` (no cell is a formula in a spreadsheet).

### Memos: beyond LayerTwo's RPC

thunder-orchard's `create_shielded_transfer [dest, value_sats, fee_sats]` has no memo: their wallet writes an empty
one (512 zero bytes). Our app's `rpc.confirmed` of the same method takes a 4th parameter, the memo text (at most 512 bytes
and, as it is shown in the trusted dialog, what core's `bt::appui::display_text_problem` takes: valid UTF-8 without any
control, format, separator, private-use, unassigned or default-ignorable code point; the page checks the same with its
twin, `app/ui/text.ts`); without it, the LayerTwo handler runs exactly as LayerTwo's RPC; with it, the app layer builds the same
transaction with the same wallet function and the memo in the recipient's note (ZIP 302 text). The memo lives inside
the recipient's encrypted note: consensus and their nodes are not concerned by it (any 512 bytes are valid), and the
LayerTwo RPC is unchanged. Memos received are read in ZIP 302's way (text; "no memo"; anything else in hex).

### Deposits name the bare address

zSide credits a deposit only to a bare base58 transparent address: the `s98_<address>_<check>` text of
`format_deposit_address` is not one, and a deposit naming it is credited to nobody (thunder-orchard's rule, doc/zside.md
§"Consensus quirks" 7; Backbone's `createsidechaindeposit` writes the text it is given as the deposit's destination). So
the app gives the address itself wherever a deposit is concerned (Drivechains → Deposit, Receive → Transparent, the
explorer: `depositAddress` is the address), says why, and its deposit through the mainchain interface's wallet names
the bare address (`create_deposit`, as LayerTwo's). The address check refuses an `s98_…` text as a zSide address.

## What the pages use of the node (app/manifest.json)

- **Reads**: the LayerTwo reads by name (the same handlers and JSON): `balance`, `format_deposit_address`,
  `get_best_mainchain_block_hash`, `get_best_sidechain_block_hash`, `get_block`, `get_block_hash`, `get_bmm_inclusions`,
  `get_shielded_wallet_addresses`, `get_stxos`, `get_transaction`, `get_transparent_wallet_addresses`, `get_utxos`,
  `get_wallet_stxos`, `get_wallet_utxos`, `get_withdrawal_bundle`, `getblockcount`, `latest_failed_withdrawal_bundle_height`,
  `list_peers`, `list_utxos`, `openapi_schema`, `pending_withdrawal_bundle`, `sidechain_wealth`; and `getmainchaininfo`,
  `getbalances`, `getblockchaininfo`, `getnetworkinfo`, `uptime`.
- **Confirmed** (only through `rpc.confirmed`, asked in the trusted dialog): `create_transparent_transfer [dest,
  value_sats, fee_sats]`, `create_shielded_transfer [dest, value_sats, fee_sats, memo?]`, `create_shield [value_sats,
  fee_sats]`, `create_unshield [value_sats, fee_sats]`, `create_withdrawal [ecash_address, amount_sats, fee_sats,
  mainchain_fee_sats]`, `create_deposit [address, value_sats, fee_sats]`, `mine [fee_sats?]`. Every describer sums the
  parts with `spend_total` (each addition checked, at most 21,000,000 ECX) and refuses before asking what the balance
  it spends from cannot pay (transparent, or the shielded notes spendable now; a deposit is paid on eCash by the
  mainchain interface's wallet).
- **Host**: the shared `dropin.*` (core/doc/app.md §2, with zSide's reads: `dropin.addresses` and `dropin.seed.status`
  exercise `get_transparent_wallet_addresses`, `dropin.newAddress` `get_new_transparent_address`, `dropin.history`
  `get_wallet_utxos` and `get_shielded_wallet_addresses`) and `zside.shielded` (`balance`, `get_shielded_wallet_addresses`),
  `zside.newShieldedAddress` (`get_new_shielded_address`), `zside.memos` (`get_shielded_wallet_addresses`), `zside.pool`
  (`get_block`).

Ownership: whether a transparent address or output is the wallet's is said only to a caller of
`get_transparent_wallet_addresses` (the host's `owner_read`); the shielded account (notes, memos, shielded addresses,
whether a shielded address is the wallet's) only to a caller of `get_shielded_wallet_addresses`. Events: the chain's
to a reader of the chain, the balances to a reader of `getbalances` (both balances), the wallet's transactions (shielded
ones too) to a reader of both accounts. The tests check this file equals what the node serves (`AppLayer::manifest`).

## Tests

- `tests/test_zside_appui.cpp`: every LayerTwo method's reply byte-identical with and without the app layer (44
  methods, six kinds of bad parameters each, the reads with good ones, with and without a wallet, and after the layer
  stopped), the app RPC's reads equal to the LayerTwo results (an error of LayerTwo's an error of the app RPC), the
  phrase made only in a question / restored / refused over another, the unified wallet's phrase (the BIP-85 vectors
  above; the wallet it sets has the same transparent and shielded addresses as one given the phrase by LayerTwo's
  `set_seed_from_mnemonic`), wallet ownership and the shielded account only for their readers, every describer's sum
  refused near UINT64_MAX and above 21,000,000 ECX, memos (ZIP 302 reading, what may be sent), the manifest.
- The interface (`build-app/zside-app-ui/src/webui/app`): `npx svelte-check --fail-on-warnings`, and `npx vitest run
  src/chain` (`app/chain/zside.test.ts`: the payments, shielding and unshielding through `rpc.confirmed` with LayerTwo's
  parameters, a memo only as the 4th, a memo that is not one line refused, no words of a phrase, nothing outside the
  manifest, the memos' CSV; with the shared `dropin.test.ts`). The assembled interface's `node_modules` is a link to
  the template's: vitest 5 then needs `server.fs.allow` to name it (a config merging `vite.config.ts` with
  `{ server: { fs: { allow: ['.', realpathSync('node_modules')] } } }`).
- `tests/e2e/run_app.py` (a build with `-DBT_APP_TEST_HOOKS=ON`; xvfb-run): a local eCash regtest (backboned
  `-regtest -ecashregtest=betanet -grpc`, slot 98 proposed and acked), zside-app runs node A, a zSide node B is the
  other side (its own app layer on, driven by the runner with its cookie as the unified wallet would): the app starts,
  the phrase is made in the trusted dialog, 10 ECX deposited (to a bare address), 1.5 ECX sent to B, 0.25 ECX received
  from B, 2 ECX withdrawn; 3 ECX shielded, 1 ECX paid privately to B's shielded address with a memo (asked with it),
  B pays 0.4 ECX back to A's shielded address with a memo of its own (A's activity and Memos show it), 1.5 ECX
  unshielded, the withdrawal paid on eCash; the phrase shown and saved (0600); then A's LayerTwo replies
  byte-identical without and with the app layer (57 reads, the last 12 blocks in both verbosities). Screenshots of every
  page, dark and light. Last run: 18 checks passed, 57/57 replies byte-identical.

```
python3 tests/e2e/run_app.py --bin build-app/chains/zside --backboned <backboned> --tmp <dir> --shots <dir> --base-port 49870
```

## Platforms

Linux (GTK 3, WebKitGTK 4.1): built, unit-tested and run end to end. Windows (mingw-w64, WebView2): the node
(`thunder-orchard.exe`, with the Orchard FFI built by cargo for `x86_64-pc-windows-gnu`: `rustup target add
x86_64-pc-windows-gnu --toolchain 1.96.0`) and `zside-app.exe` cross-compile (`-DCMAKE_TOOLCHAIN_FILE=core/cmake/mingw64.cmake
-DBT_BUILD_APP=ON -DWEBVIEW2_INCLUDE_DIR=<the WebView2 SDK headers>` and the mingw64 depends prefix); not yet run on
Windows. macOS: not built.
