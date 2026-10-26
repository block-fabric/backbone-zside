# zSide (eCash slot 98): drop-in client

`thunder-orchard` (this repository) replaces iwakura-rein/thunder-orchard's
`thunder_orchard_app` on eCash betanet. Consensus, P2P, mainchain link, CLI flags and JSON-RPC
follow **thunder-orchard master b225827** (= v0.18.1 consensus + anchor-from-JSON RPC + MIT
licence), the rules every betanet zSide block was made under (v0.18.0–0.18.1 share them; the
M1 hash_id_2 names v0.15.0, which has no betanet network and other hashes — informational
only).

**Cryptography is the reference crate.** Orchard point decoding, `Action::from_parts`,
`Bundle::try_from_parts(.., ProofSizeEnforcement::Strict)`, binding and spend-authorization
RedPallas signatures, the halo2 proof (`VerifyingKey::build()` = the fixed NU6.2 circuit), the
note commitment frontier (`incrementalmerkletree` 0.8.2), ZIP-32 keys, note encryption and
the bundle builder/prover are the `orchard` 0.14.0 / `halo2_proofs` 0.3.2 crates — the exact
versions in thunder-orchard's Cargo.lock — linked as a static library through a ~500-line C
ABI (`rust/zside_orchard_ffi`, header `chains/zside/include/zside/orchard_ffi.h`). A faithful
C++ port of halo2/Orchard is impractical and would be the riskiest part to get bit-exact. All
byte formats (bincode wire form, borsh hashing form, txid, merkle trees) and the whole state
machine, node, wallet and RPC are C++.

## Status

| Milestone | State | Evidence |
|---|---|---|
| Codecs / hashes | done | All 116 public betanet blocks (0..115, tip `902fa300…`, 2026-10-22), fetched over QUIC from `seed.beta.ecash.eu.com:4098` with `zside-fetch-blocks`: bincode decode → re-encode byte-exact, every block id = the seed index; the 8 txs the index serves as borsh hex round-trip; empty-body root `812c9708…bdbb`, genesis `f87359e6…` |
| Oracle (their types crate) | done | Their `thunder_orchard_types` (MIT) on the same blocks vs ours (`ZS_DUMP`): 124 lines — block hash, merkle root, every txid, borsh size, Orchard frontier root and nullifier count per block — **identical** |
| State machine | done | Full replay with every check (`test_zside_replay.cpp`): 116 BMM commitments in the child of `prev_main` (genesis BMM at mainchain 973,757), 7 Orchard bundles / 14 actions (5 shields, 2 shielded-only bundles): binding + spend-auth signatures and halo2 proofs verified, anchors in the historical roots, nullifiers, frontier `4b434496…a711` (6 historical roots, 14 nullifiers), 6 FROST signatures, 6 utreexo proofs, 3 deposits; sidechain wealth 1,023,345,000 sat; rollback to genesis and reconnect identical (frontier restored at every step) |
| Live betanet sync | done | From an empty datadir through `https://enforcer.beta.ecash.ninja` (973,920 header infos) and the public seed peer, twice: tip 115 `902fa300…` (first build), and with the side-tips port tip 116 `ea58bce9…`, each = the seed index at that time |
| Regtest pair (their node + ours) | done | `tests/regtest/zside_regtest.py full` — see below |
| Drop-in surface | done | binary `thunder-orchard` with their flags/defaults, `thunder-orchard-cli` with their 44 subcommands, the same 44 JSON-RPC methods, `openapi_schema` = theirs byte for byte |

### Regtest pair (local, their b225827 build next to ours, enforcer 17eb2ce)

`tests/regtest/zside_regtest.py full`: blocks mined alternately by each node (BMM via the
enforcer), the two nodes peered only with each other; after every block the raw JSON-RPC
replies of both are compared (reads, `get_block` both verbosities, UTXO sets, both wallets'
UTXOs/STXOs), the whole history again at the end. Final run (2026-10-22): **1,249 reply
comparisons, 1 difference** (below); 43 blocks.

* deposits, transparent transfers both ways;
* shields on both sides; **shielded transfers both ways** (their wallet's bundle received and
  spent again by ours, ours by theirs) — balances exact to the sat on both;
* unshields; withdrawals → bundle Submitted → **Confirmed** after 6 blocks (paid on the
  mainchain, CTIP 4.0 → 2.4998 ECX), status identical;
* our shielded tx relayed to their node and mined in **their** block; their unshield relayed
  to ours and mined in **our** block;
* a mainchain reorg removing the BMM blocks of the last two side blocks: both nodes keep
  them (side-tips rule), BMM on top of them fails on both, the next template of either goes
  on the last block whose `prev_main` survived, and both switch to it;
* fresh node of each implementation syncing only from the other: all 43 blocks identical;
* our node with their mnemonic derives their 14 transparent and 9 shielded addresses;
* `openapi_schema` identical; their CLI against our RPC: identical except `list-utxos` /
  `get-stxos` order (theirs comes from a HashMap: random; equal as sets); our CLI = theirs
  on every read subcommand checked.
* The one difference: `get_bmm_inclusions` of a block kept across the reorg lists two main
  blocks on theirs (the reorged-away one too) and one on ours: our node never received the
  BMM result of the stale main block (it fetches the active chain's ancestors only). RPC
  only; open item.

Their bugs seen on the way (not ours): their wallet intermittently cannot build a spend
(`Orchard ShardTree error: Tree does not contain a root at address ...`, their issue #29 /
PR #41; the harness retries after a block); `get_transaction` returns `null` for confirmed
txs outside the tip block. Other upstream issues seen during the regtest runs (their node,
the enforcer, electrs) are reported separately; details held for coordinated disclosure. The harness works around
them (it mines with ecashd and restarts services when needed).

## Drop-in surface

* **CLI** (app/cli.rs): `--add-peer`, `-d/--datadir` (default `<data_dir>/thunder-orchard`),
  `--headless` (accepted), `--log-dir` (`<datadir>/logs/v0.18.1`), `--log-level`,
  `--log-level-file`, `--mainchain-grpc-url` (`http://localhost:50051`; https accepted),
  `--mnemonic-seed-phrase-path`, `-n/--net-addr` (`0.0.0.0:4098`), `--network`
  (betanet|forknet|regtest|signet), `--network-magic`, `-p/--private-rpc-addr`,
  `-r/--rpc-addr` (both `127.0.0.1:6098`), `--server-name`, `--wallet-dir`. Ours start with
  `--bt-` (`--bt-no-seeds`, `--bt-no-p2p`, `--bt-rpc-allowed-origin/-host`,
  `--bt-rpc-allow-external`, `--bt-wallet-derivation v0.18.1|v0.18.0`).
* **P2P**: thunder-rust's QUIC/bincode protocol, magic `8d 19 28 04` ("ZSIDE"; regtest 00,
  signet 01, forknet 02), port 4098, seeds `seed.beta.ecash.drivecha.in` and
  `seed.beta.ecash.ninja` (their list) plus `seed.beta.ecash.eu.com` (ours: on 2026-10-22 the
  two in their list accepted QUIC connections but sent nothing — idle timeouts — while
  eu.com served every block; a stock thunder-orchard on betanet cannot sync without
  `--add-peer`).
* **JSON-RPC**: their 44 methods with serde shapes. Orchard bundles as their human-readable
  serde: `nullifier`/`rk`/`cmx`/`cv_net`/`anchor` as `0x`-hex (const_hex), `epk_bytes`,
  ciphertexts, proof and signatures as plain hex, `flags` a number, `balance` i64 sats; header
  `roots` as plain `NodeHash` serde (thunder-orchard dropped thunder's DisplayFromStr);
  `balance` = `{total_shielded_sats, total_transparent_sats, available_shielded_sats,
  available_transparent_sats}`; shielded addresses Bech32m `t-shld1…` (43 raw bytes).
* **Wallet**: BIP-39; BLAKE3 "bip32ish" (`zSide seed` derive-key master, keyed-BLAKE3
  children, 512-bit scalar reduction; v0.18.0 wallets: `--bt-wallet-derivation v0.18.0` = the
  HMAC-SHA512 scheme); transparent keys m/43'/1899'/0'/98'/0'/i from index 0; Orchard spending
  key = ZIP-32 from the m/43'/1899'/0'/98'/2'/0' scalar (coin 0, account 0), shielded addresses
  external indexes 0,1,2…; spends against the root 3 blocks under the tip. Import their wallet
  by mnemonic (verified: identical addresses).
* **Datadir**: `backbone-zside.sqlite`, `backbone-wallet.sqlite` (owner-only); we resync.

## Consensus quirks reproduced

1. Txid = BLAKE3(borsh(inputs) ‖ borsh(outputs) ‖ borsh(Option<bundle without auth>)); the
   bundle hash form is ZIP-244-like with the **memo taken from enc[32..544]** (bytes 32..52
   hashed twice). Tx merkle root = H(inputs root, H(bundle w/o auth), outputs root); plain
   CBMTs for outputs, transactions and the block (no fees in the merkle tree).
2. Orchard signatures sign the txid. Proofs and signatures are not committed by the header.
3. **EmptyAnchor**: the empty-tree root is always a historical root but is refused with spends
   enabled; roots are recorded per block only when new; no anchor window.
4. Nullifier double spends are refused **only at connect** (prevalidate passes).
5. Sigops count transparent authorizations only; the value
   balance enters the fee (> 0 value in, ≤ 0 value out); a shielded-only tx's fee is its
   value balance.
6. orchard 0.14 decoding: identity `rk`, invalid or identity `epk`, non-canonical points,
   unknown flag bits and non-canonical proof sizes make the tx undecodable.
7. Shared with thunder-rust: no intra-block spends, utreexo roots in the header and proofs in
   inputs, bundle builder `break`, a pending bundle never expires, an unknown bundle
   confirmed at height > 0 halts, `deposit_blocks` little-endian keys, fork choice
   `better_tip`, first genesis sticks; deposits credit only a bare base58 address (`s98_…`
   burns to `ALL_ZEROS`).

## Kept (consensus-neutral) and deviations

* Mempool/template policy: a tx re-spending a nullifier already in the chain is refused and
  never put in a template; peers' txs get their utreexo proof regenerated before the mempool;
  templates drop stale proofs.
* Mempool: a tx spending one outpoint twice or carrying one nullifier twice is refused (as
  their insert does); blocks refuse both too (sorted input scan; connect_orchard
  check-then-put) — test `orchard_duplicate_nullifier_in_one_tx` (a real bundle spending one
  note twice verifies and passes prevalidate, connect refuses it).
* P2P hardening, with core's shared helpers (`bt/sidechain/node.h`, as backbone-thunder and
  backbone-bitnames): bans hold for inbound connections (closed at connect) and on every
  request, keyed by address (IPv4-mapped IPv6 as its IPv4, native IPv6 by /64); requests on
  a connection not known as connected are refused (fail closed); GetHeaders answers complete,
  bounded by the end block's height + 1, at most 30 a minute per remote address, kept across
  reconnects (tests `zside_node_*`, over QUIC on loopback); one body-fetching chain per peer,
  a round that delivers no body ends it; SIGPIPE ignored (a stopped enforcer killed the
  node); core gRPC sends with MSG_NOSIGNAL.
* `get_transaction` finds confirmed transactions; **theirs returns `null` for any tx not in
  the tip block** (`node/mod.rs:579-588` calls `is_descendant(tip, block)` with the arguments
  swapped; thunder-rust 0.18.2 has the fix). Ours answers as 0.18.2 does.
* Wallet: shields never consolidate an existing note (theirs sometimes does, against a deep
  anchor); notes are found by rescanning the active chain (simple, reorg-safe; O(chain)).
* RPC hardening as backbone-thunder (Host/Origin checks, loopback only by default).

## Mainchain reorgs: their side-tips rule (reproduced)

thunder-orchard b225827 is a thunder-rust **0.18.1** backport: it lacks 4df63d3, and its
side-tips index (`lib/archive/side_tips/mod.rs`, identical to thunder-rust's and
plain-bitnames') keeps sidechain blocks whose BMM block was reorged away. A first version of
ours used backbone-thunder's "disconnect a tip no longer BMM-verified" rule and **split from
their node** on the regtest reorg; ours now runs the side-tips port from backbone-bitnames
(53c70e7, 232ba0e: `side_tips.{h,cpp}`, `Node::sync_to_mainchain_tip` /
`handle_mainchain_block_event`, NewTipReady and peer-tip gates), with the same
`REPRODUCE_SIDE_TIPS_HALT = false` switch (pending the user's decision, as BitNames). Ours
also looks at every peer's last tip again after each mainchain event (a tip seen before our
side tips reached its main block was otherwise ignored until the peer's tip changed).
`--bt-rebuild-side-tips` rebuilds the index. The halt switch stays off (user decision,
2026-10-22, as BitNames and BitAssets).

thunder-rust 0.18.2 (244e20f, what betanet Thunder runs) has the same side-tips module
(byte-identical `side_tips/mod.rs`) and the same `handle_mainchain_block_event` loop: 4df63d3
only makes the disconnect in that loop also revert the 2WPD and refill the mempool; it does
not change which blocks are disconnected. A sidechain block whose BMM block is reorged away
stays in `sidechain_tips`, so 0.18.2 keeps it too (as here). backbone-thunder has the same
side-tips port since 0538ae9 (checked against their 0.18.2 binary through a regtest reorg).

## Consensus-changing proposals (not coded)

Known upstream consensus behaviour is reproduced as is; proposals are details held for coordinated disclosure.
A consensus-neutral item for their node: check chain nullifiers in the template and mempool,
as ours does.

## Remaining

Windows build of the Rust FFI (mingw target wired in CMake, not built); equal-height side
forks; `invalidate_block` interplay with their node; a weeks-long betanet shadow.
