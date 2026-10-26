#!/bin/sh
# Fill rust/vendor with the exact crates of zside_orchard_ffi/Cargo.lock and check them.
#  * `cargo vendor --locked` downloads each crate from crates.io and verifies it against the
#    sha256 recorded in Cargo.lock (orchard 0.14.0, halo2_proofs 0.3.2, ... = thunder-orchard
#    b225827's versions);
#  * the whole tree is then hashed (sorted list of per-file sha256) and compared with
#    VENDOR.sha256, so the build input is pinned bit for bit.
# The build itself is `cargo build --release --locked --offline` (CMake does it).
set -e
cd "$(dirname "$0")"
CARGO=${CARGO:-$(command -v cargo || echo "$HOME/.cargo/bin/cargo")}
if [ ! -d vendor ] || [ "$1" = "--refresh" ]; then
  rm -rf vendor
  (cd zside_orchard_ffi && "$CARGO" vendor --locked --versioned-dirs -q ../vendor >/dev/null)
fi
got=$(cd vendor && find . -type f | LC_ALL=C sort | xargs sha256sum | sha256sum | cut -d' ' -f1)
want=$(cut -d' ' -f1 VENDOR.sha256)
if [ "$got" != "$want" ]; then
  echo "vendor tree hash $got != VENDOR.sha256 $want" >&2
  exit 1
fi
echo "vendor OK ($got)"
