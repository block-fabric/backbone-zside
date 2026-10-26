# backbone-zside

Drop-in replacement client for **zSide (eCash slot 98)**: consensus-, P2P-, mainchain- and
RPC-compatible with iwakura-rein/thunder-orchard b225827 (v0.18.1 consensus, MIT), the node
eCash betanet runs. C++20 on the shared engine `core/` (= `../backbone-core`); the Orchard
cryptography (halo2 proofs, RedPallas signatures, the note commitment tree, keys and note
encryption) is the **reference `orchard` 0.14.0 / `halo2_proofs` 0.3.2 crates** — the exact
versions thunder-orchard links — behind a small C ABI (`rust/zside_orchard_ffi`). See
`doc/zside.md` (status, evidence, drop-in surface, reproduced quirks, deviations) and
`doc/differential-tests.md`.

Inspired by zSide / thunder-orchard by LayerTwo Labs and iwakura-rein.

## Build (Linux)

```
git submodule update --init
core/depends/fetch.sh && cmake -S core/depends -B core/depends/work/linux   # OpenSSL 3.5.9 + ngtcp2 (or reuse a built prefix)
rust/fetch-vendor.sh          # the pinned crates into rust/vendor, checked against Cargo.lock and VENDOR.sha256
cmake -S . -B build -DCMAKE_BUILD_TYPE=RelWithDebInfo [-DBT_DEPENDS_PREFIX=<prefix>]
cmake --build build -j4       # cargo build --release --locked --offline runs as part of it
build/tests/bt_tests
```

Rust: rustup with toolchain 1.96.0 (`rust/rust-toolchain.toml`). Binaries:
`build/chains/zside/thunder-orchard`, `thunder-orchard-cli`, `zside-fetch-blocks`.

## The app (zside-app)

Our sidechain app on this node: the sidechain template's window, trusted dialog and interface kit, with pages for
zSide's two balances (transparent and shielded: shield, unshield, private payments with a memo, shielded addresses,
the memos, the shielded pool); the node (`thunder-orchard`) runs as the app's child, unchanged (consensus and the
LayerTwo RPC byte for byte), the app talking to its separate, authenticated app RPC. The same pages are a pack for the
unified wallet. See `doc/app.md` and `core/doc/app.md`.

```
cmake -S . -B build-app -DBT_BUILD_APP=ON -DBT_KIT_DIR=<sidechain-template repo>   # GTK 3, WebKitGTK 4.1, npm
~/skydoge/tools/build.sh ~/skydoge/backbone-zside build-app
build-app/chains/zside/zside-app
```

## Reproducible Rust inputs

`rust/zside_orchard_ffi/Cargo.lock` pins every crate to the version in thunder-orchard's own
Cargo.lock (orchard 0.14.0, halo2_proofs 0.3.2, halo2_gadgets 0.5.0, incrementalmerkletree
0.8.2, reddsa 0.5.1, pasta_curves 0.5.1, zcash_note_encryption 0.4.1, zip32 0.2.0, ...), with
crates.io sha256 checksums. `rust/fetch-vendor.sh` vendors them (`cargo vendor --locked`) and
checks the whole tree against `rust/VENDOR.sha256`; the build is `--locked --offline` from
that tree. The vendored sources (58 MB) are not committed.
