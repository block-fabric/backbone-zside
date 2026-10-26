#!/usr/bin/env python3
# Copyright (c) 2026 The Backbone developers
# Distributed under the MIT software license.
"""End-to-end run of zside-app on a local eCash regtest (doc/app.md "Tests"): slot 98, app.js in its page; the runner
is core/tests/e2e/dropin_app.py. The node is thunder-orchard (LayerTwo's name). Besides deposit, payments both ways,
receipt and a withdrawal paid on eCash: a shielded round trip. The app shields coins, pays node B's shielded address
privately with a memo; node B (its own app layer on, driven here with its cookie as the unified wallet would) pays
A's shielded address back with a memo of its own, which the app shows; the app unshields.

    run_app.py --bin build-app/chains/zside --backboned <backboned> --tmp <dir> --shots <dir> [--base-port 49400]
"""

import sys
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent.parent / "core" / "tests" / "e2e"))
from dropin_app import Chain, main  # noqa: E402
from dropin_regtest import JsonRpc, wait_for  # noqa: E402

READS = [("getblockcount", []), ("get_best_sidechain_block_hash", []), ("get_best_mainchain_block_hash", []), ("list_utxos", []),
         ("pending_withdrawal_bundle", []), ("latest_failed_withdrawal_bundle_height", []), ("sidechain_wealth", []), ("balance", []),
         ("get_transparent_wallet_addresses", []), ("get_shielded_wallet_addresses", []), ("get_wallet_utxos", []), ("get_wallet_stxos", []),
         ("openapi_schema", []), ("list_peers", []), ("get_block_hash", [0]),
         ("get_transaction", ["00" * 32]), ("get_withdrawal_bundle", ["00" * 32])]

MEMO_BACK = "e2e: thanks for lunch"


def b_confirmed(run, method, params):
    """A spend of node B through its app RPC, as the unified wallet makes one: rpc.confirmed, the question, the token."""
    user, secret = (run.base / "B" / "backbone-app.cookie").read_text().strip().split(":", 1)
    app = JsonRpc(run.port + 27, user, secret)
    request = {"kind": "host", "method": "rpc.confirmed", "params": {"method": method, "params": params}}
    first = app.webuihost(request, "", "", [])
    question = first["confirm"]
    rows = {r["label"]: r["value"] for r in question.get("rows", [])}
    done = app.webuihost(request, question["token"], "", [])
    return done["result"], rows


def on_signal(msg, run):
    """SIGNAL zsent <A's shielded address>: B got the private payment; it pays A's shielded address back, with a memo."""
    words = msg.split()
    if words[0] != "zsent":
        return []
    to = words[1]
    failures = []
    wait_for(lambda: run.b.balance()["available_shielded_sats"] >= 100_000_000, "B's shielded coins", 300, 1)
    print(f"  node B: shielded balance {run.b.balance()}", flush=True)

    def pay_back():
        # Spendable once its note is 3 blocks deep: refused before that (the describer says so).
        try:
            return b_confirmed(run, "create_shielded_transfer", [to, 40_000_000, 1000, MEMO_BACK])
        except RuntimeError as e:
            if "Not enough" in str(e):
                return None
            raise

    txid, rows = wait_for(pay_back, "B's shielded payment back", 400, 2)
    print(f"  node B pays 0.4 ECX back to A's shielded address with a memo: {txid}", flush=True)
    if rows.get("Memo") != MEMO_BACK:
        failures.append(f"node B's question did not show the memo: {rows}")
    return failures


def more_reads(a, addrs):
    count = a.getblockcount()
    reads = []
    for h in range(max(0, count - 12), count):
        block = a.get_block_hash(h)
        reads += [("get_block", [block]), ("get_block", [block, True]), ("get_bmm_inclusions", [block])]
    return reads


if __name__ == "__main__":
    sys.exit(main(Chain(stem="zside", title="zSide", slot=98, program="thunder-orchard", script=HERE / "app.js", reads=READS,
                        peer_setup=lambda b: (b.set_seed_from_mnemonic(b.generate_mnemonic()), b.get_new_transparent_address())[1],
                        peer_available=lambda b: b.balance()["available_transparent_sats"],
                        peer_pay=lambda b, to, sats: b.create_transparent_transfer(to, sats, 1000),
                        wallet_addresses=lambda a: a.get_transparent_wallet_addresses(),
                        peer_args=lambda run: ["--bt-app-rpc-port", str(run.port + 27)],
                        e2e_extra=lambda b: {"peerShielded": b.get_new_shielded_address(), "memoBack": MEMO_BACK},
                        on_signal=on_signal, more_reads=more_reads)))
