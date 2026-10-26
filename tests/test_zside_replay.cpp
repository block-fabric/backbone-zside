// End-to-end known answers against public eCash betanet zSide data (slot 98): every block
// fetched over P2P from the public seed, replayed with every check (halo2 proofs included).
#include "test.h"

#include <zside/betanet_fixture.h>
#include <zside/orchard_ffi.h>

#include <cstdlib>

#include <cstdio>

using namespace zside;

static const fixture::Data& data()
{
    static std::optional<fixture::Data> d;
    if (!d) {
        std::string err;
        d = fixture::load(bttest::data_dir() + "/betanet", err);
        if (!d) std::fprintf(stderr, "fixture load: %s\n", err.c_str());
    }
    return *d;
}

TEST(betanet_tx_borsh_roundtrip)
{
    // every public tx: borsh decode -> re-encode identical -> blake3 == txid
    size_t n = 0;
    for (auto& [txid, hex] : data().txhex) {
        auto raw = bt::hex_decode(hex);
        REQUIRE(raw.has_value());
        bt::Reader r(*raw);
        Transaction t = borsh_de_transaction(r);
        CHECK(r.empty());
        CHECK(t.canonical_bytes() == *raw);
        CHECK_EQ(bt::hex_encode(t.txid()), txid);
        // bincode round trip of the same transaction
        bt::Writer w;
        bincode(w, t);
        bt::Reader br(w.buf);
        Transaction back = de_transaction(br);
        CHECK(br.empty());
        CHECK(back.canonical_bytes() == t.canonical_bytes());
        if (t.orchard_bundle) CHECK(orchard_bundle_decodes(*t.orchard_bundle));
        n++;
    }
    CHECK_EQ(n, size_t(8));
}

TEST(betanet_replay_full_blocks)
{
    auto blocks = fixture::load_blocks_bin(bttest::data_dir() + "/betanet/blocks.bin");
    const uint32_t N = 116; // heights 0..115 (tip on 2026-10-22)
    REQUIRE(blocks.size() == N);
    bt::kv::MemStore store;
    State st;
    auto r = fixture::replay_full(data(), blocks, st, store);
    std::fprintf(stderr, "  %u blocks connected (all checks), %u byte-exact re-encodings, %u hashes = index, %u FROST sigs, %u utreexo proofs, %u BMM, %u deposits, %u orchard bundles (%u actions; %u shield, %u transfer, %u unshield); %s\n",
                 r.blocks, r.reencoded_exact, r.hashes_match_index, r.signatures, r.proofs, r.bmm_verified, r.deposits, r.orchard_bundles,
                 r.orchard_actions, r.shields, r.shielded_transfers, r.unshields, r.error.c_str());
    CHECK(r.error.empty());
    CHECK_EQ(r.blocks, N);
    CHECK_EQ(r.reencoded_exact, N);
    CHECK_EQ(r.bmm_verified, N);
    CHECK_EQ(r.orchard_bundles, 7u);
    bt::kv::Txn t(store);
    CHECK_EQ(*st.height(t), N - 1);
    CHECK_EQ(bt::hex_encode(*st.tip(t)), bt::hex_encode(data().blocks[N - 1].id));
    std::fprintf(stderr, "  orchard: frontier root %s, %zu historical roots, %zu nullifiers\n", bt::hex_encode(st.orchard_frontier_root(t)).c_str(),
                 st.orchard_historical_roots(t).size(), st.orchard_nullifiers(t).size());
    uint64_t wealth = st.sidechain_wealth(t);
    std::fprintf(stderr, "  sidechain_wealth %llu sats, utxos %zu, stxos %zu\n", (unsigned long long)wealth, st.utxos(t).size(), st.stxos(t).size());
    for (auto& [m6id, info] : st.bundles(t))
        std::fprintf(stderr, "  bundle %s %s: %s @%u\n", bt::hex_encode(m6id).c_str(), info.first.kind == WithdrawalBundleInfo::Known ? "known" : "unknown",
                     to_string(info.second.latest().value), info.second.latest().height);
    if (auto p = st.pending_bundle_m6id(t)) std::fprintf(stderr, "  pending m6id %s\n", bt::hex_encode(*p).c_str());
}

TEST(betanet_full_rollback_to_genesis)
{
    // Disconnect the whole betanet history (block + its 2WPD window, newest first, as
    // net_task.rs disconnect_tip_ does) and check that every table returns to empty;
    // then reconnect and check the tip and state again.
    auto blocks = fixture::load_blocks_bin(bttest::data_dir() + "/betanet/blocks.bin");
    bt::kv::MemStore store;
    State st;
    std::vector<fixture::ReplayStep> steps;
    auto r = fixture::replay_full(data(), blocks, st, store, &steps);
    REQUIRE(r.error.empty());
    uint64_t wealth;
    size_t nutxo;
    {
        bt::kv::Txn t(store);
        wealth = st.sidechain_wealth(t);
        nutxo = st.utxos(t).size();
    }
    for (size_t i = steps.size(); i-- > 0;) {
        bt::kv::Txn t(store);
        st.disconnect_2wpd(t, steps[i].window);
        st.disconnect_tip(t, steps[i].block.header, steps[i].block.body);
        if (i > 0) st.put_accumulator(t, *bt::utreexo::MemForest::deserialize(steps[i - 1].accumulator));
        else t.del(State::T_ACCUMULATOR, bt::Bytes{});
        if (i > 0) CHECK(st.orchard_frontier(t) == steps[i - 1].frontier);
        t.commit();
    }
    bt::kv::Txn t(store);
    CHECK(!st.tip(t).has_value());
    CHECK(st.utxos(t).empty());
    CHECK(st.stxos(t).empty());
    CHECK(st.bundles(t).empty());
    CHECK(!st.pending_bundle_m6id(t).has_value());
    CHECK(st.deposit_blocks(t).empty());
    CHECK(st.bundle_event_blocks(t).empty());
    CHECK(st.orchard_nullifiers(t).empty());
    CHECK_EQ(st.orchard_historical_roots(t).size(), size_t(1)); // the empty root only
    CHECK(st.orchard_frontier(t) == bt::Bytes{0});
    // reconnect everything
    State st2;
    auto r2 = fixture::replay_full(data(), blocks, st2, store);
    CHECK(r2.error.empty());
    bt::kv::Txn t2(store);
    CHECK_EQ(st2.sidechain_wealth(t2), wealth);
    CHECK_EQ(st2.utxos(t2).size(), nutxo);
}

TEST(betanet_dump_for_oracle)
{
    // ZS_DUMP=<file>: the lines the Rust oracle (their thunder_orchard_types) prints, for a diff.
    const char* out = std::getenv("ZS_DUMP");
    if (!out) return;
    auto blocks = fixture::load_blocks_bin(bttest::data_dir() + "/betanet/blocks.bin");
    bt::kv::MemStore store;
    State st;
    std::vector<fixture::ReplayStep> steps;
    auto r = fixture::replay_full(data(), blocks, st, store, &steps);
    REQUIRE(r.error.empty());
    FILE* f = std::fopen(out, "w");
    size_t nfs = 0;
    for (size_t h = 0; h < steps.size(); h++) {
        auto& b = steps[h].block;
        for (auto& tx : b.body.transactions) {
            std::fprintf(f, "tx %zu %s %zu\n", h, bt::hex_encode(tx.txid()).c_str(), tx.canonical_bytes().size());
            if (tx.orchard_bundle) nfs += tx.orchard_bundle->actions.size();
        }
        Hash32 root;
        zs_frontier_root(steps[h].frontier.data(), steps[h].frontier.size(), root.data());
        std::fprintf(f, "block %zu %s %s frontier %s nullifiers %zu\n", h, bt::hex_encode(b.header.hash()).c_str(),
                     bt::hex_encode(compute_merkle_root(b.body.coinbase, b.body.transactions)).c_str(), bt::hex_encode(root).c_str(), nfs);
    }
    std::fclose(f);
}
