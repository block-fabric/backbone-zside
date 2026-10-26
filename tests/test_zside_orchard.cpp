// zSide Orchard consensus quirks (study Part II zSide §5), on real betanet bundles.
#include "test.h"

#include <zside/betanet_fixture.h>
#include <zside/orchard_ffi.h>

#include <cstring>

using namespace zside;

namespace {
struct Replayed {
    bt::kv::MemStore store;
    State st;
    std::vector<fixture::ReplayStep> steps;
    Replayed()
    {
        std::string err;
        auto d = fixture::load(bttest::data_dir() + "/betanet", err);
        auto blocks = fixture::load_blocks_bin(bttest::data_dir() + "/betanet/blocks.bin");
        auto r = fixture::replay_full(*d, blocks, st, store, &steps);
        if (!r.error.empty()) throw std::runtime_error(r.error);
    }
    const Transaction* find_tx(bool shielded_only)
    {
        for (auto& s : steps)
            for (auto& t : s.block.body.transactions)
                if (t.orchard_bundle && (!shielded_only || (t.inputs.empty() && t.outputs.empty()))) return &t;
        return nullptr;
    }
};
Replayed& R()
{
    static Replayed r;
    return r;
}
} // namespace

TEST(orchard_empty_anchor_rule)
{
    // lib/state/mod.rs:432-454: the empty-tree root is always a historical root, but with spends
    // enabled it is refused (EmptyAnchor); with spends disabled it is accepted.
    auto& r = R();
    bt::kv::Txn t(r.store);
    OrchardBundle b = *r.find_tx(false)->orchard_bundle;
    b.anchor = orchard_empty_root();
    b.flags = 0x02; // outputs only
    r.st.validate_orchard_anchor(t, b);
    b.flags = 0x03;
    bool threw = false;
    try {
        r.st.validate_orchard_anchor(t, b);
    } catch (const StateError& e) {
        threw = std::string(e.what()).find("EmptyAnchor") != std::string::npos;
    }
    CHECK(threw);
    b.anchor[0] ^= 1; // any root never reached: InvalidAnchor, whatever the flags
    threw = false;
    try {
        r.st.validate_orchard_anchor(t, b);
    } catch (const StateError& e) {
        threw = std::string(e.what()).find("InvalidAnchor") != std::string::npos;
    }
    CHECK(threw);
    // every anchor betanet used is a historical root of our replayed state (no window)
    for (auto& s : r.steps)
        for (auto& tx : s.block.body.transactions)
            if (tx.orchard_bundle) r.st.validate_orchard_anchor(t, *tx.orchard_bundle);
}

TEST(orchard_nullifier_double_spend_only_at_connect)
{
    // block.rs: prevalidate (anchor, proofs, signatures, fees) accepts a block that re-spends a
    // confirmed nullifier; only connect_orchard refuses it (NullifierDoubleSpent).
    auto& r = R();
    const Transaction* tx = r.find_tx(true); // a shielded-only betanet tx (no transparent inputs)
    REQUIRE(tx != nullptr);
    bt::kv::Txn t(r.store);
    Body b;
    b.transactions.push_back(*tx);
    Header h;
    h.prev_side_hash = r.st.tip(t);
    h.prev_main_hash = r.steps.back().block.header.prev_main_hash;
    h.merkle_root = compute_merkle_root(b.coinbase, b.transactions);
    auto pre = r.st.prevalidate(t, h, b, State::CheckOpts{true, false});
    h.roots = pre.roots_after;
    pre = r.st.prevalidate(t, h, b); // every check passes
    CHECK(pre.total_fees == uint64_t(tx->orchard_bundle->value_balance));
    bool threw = false;
    try {
        r.st.connect_prevalidated(t, h, b, pre);
    } catch (const StateError& e) {
        threw = std::string(e.what()).find("NullifierDoubleSpent") != std::string::npos;
    }
    CHECK(threw);
}

TEST(orchard_txid_ignores_auth_and_signs_bare_txid)
{
    // The txid (= the Orchard sighash, as theirs) commits to the bundle without its
    // proof and signatures: changing a spend-auth signature keeps the txid and the merkle root
    // but fails verification (authorizations are not committed by the header).
    auto& r = R();
    Transaction tx = *r.find_tx(false);
    Hash32 id = tx.txid(), mr = tx.merkle_root();
    CHECK_EQ(orchard_verify(*tx.orchard_bundle, id), 0);
    tx.orchard_bundle->actions[0].spend_auth_sig[5] ^= 1;
    CHECK(tx.txid() == id);
    CHECK(tx.merkle_root() == mr);
    CHECK(orchard_verify(*tx.orchard_bundle, id) != 0);
    // the memo quirk: bytes 32..52 of enc are hashed twice (compact enc[..52] and memo enc[32..])
    Transaction t2 = *r.find_tx(false);
    t2.orchard_bundle->actions[0].enc[40] ^= 1;
    Writer w;
    borsh_without_auth(w, *t2.orchard_bundle);
    size_t n = t2.orchard_bundle->actions.size();
    CHECK_EQ(w.buf.size(), n * (148 + 532 + 160) + 1 + 8 + 32);
    CHECK(t2.txid() != id);
}

TEST(orchard_decode_rejects_bad_parts)
{
    auto& r = R();
    OrchardBundle b = *r.find_tx(false)->orchard_bundle;
    CHECK(orchard_bundle_decodes(b));
    OrchardBundle x = b;
    x.proof.push_back(0); // ProofSizeEnforcement::Strict
    CHECK(!orchard_bundle_decodes(x));
    x = b;
    x.flags = 0x04; // unknown flag bit
    CHECK(!orchard_bundle_decodes(x));
    x = b;
    std::memset(x.actions[0].rk.data(), 0, 32); // identity rk
    CHECK(!orchard_bundle_decodes(x));
    x = b;
    std::memset(x.actions[0].epk.data(), 0, 32); // identity epk (orchard 0.14 from_parts)
    CHECK(!orchard_bundle_decodes(x));
    x = b;
    std::memset(x.actions[0].nf.data(), 0xff, 32); // non-canonical field element
    CHECK(!orchard_bundle_decodes(x));
}

namespace {
// Build, prove and sign a bundle as our wallet does (sighash = the txid).
void finish(Transaction& tx, ZsBuilder* b, const bt::ByteArray<32>& sk)
{
    zs_init_prover();
    int32_t err = 0;
    ZsUnsigned* u = zs_builder_build(b, &err);
    if (!u) throw std::runtime_error("build " + std::to_string(err));
    auto read = [](Reader& r, OrchardBundle& o) {
        o.actions.resize(r.u32());
        for (auto& a : o.actions) {
            a.nf = r.array<32>();
            a.rk = r.array<32>();
            a.cmx = r.array<32>();
            a.epk = r.array<32>();
            a.enc = r.array<580>();
            a.out = r.array<80>();
            a.cv = r.array<32>();
            a.spend_auth_sig = r.array<64>();
        }
        o.flags = r.u8();
        o.value_balance = int64_t(r.u64());
        o.anchor = r.array<32>();
    };
    uint8_t* buf = nullptr;
    size_t len = 0;
    zs_unsigned_effects(u, &buf, &len);
    OrchardBundle eff;
    {
        Reader r(bt::ByteSpan(buf, len));
        read(r, eff);
    }
    zs_buffer_free(buf, len);
    tx.orchard_bundle = eff;
    Hash32 sighash = tx.txid();
    if (zs_unsigned_finish(u, sighash.data(), sk.data(), 1, &buf, &len) != 0) throw std::runtime_error("sign");
    OrchardBundle full;
    {
        Reader r(bt::ByteSpan(buf, len));
        read(r, full);
        full.proof = r.raw(r.u32());
        full.binding_sig = r.array<64>();
    }
    zs_buffer_free(buf, len);
    tx.orchard_bundle = full;
}

Header connect_block(State& st, bt::kv::Store& store, const Transaction& tx, uint8_t main_byte, bool expect_ok)
{
    bt::kv::Txn t(store);
    Body b;
    b.transactions.push_back(tx);
    Header h;
    h.prev_side_hash = st.tip(t);
    h.prev_main_hash[0] = main_byte;
    h.merkle_root = compute_merkle_root(b.coinbase, b.transactions);
    auto pre = st.prevalidate(t, h, b, State::CheckOpts{true, false});
    h.roots = pre.roots_after;
    pre = st.prevalidate(t, h, b); // every check (anchor, proof, signatures) passes
    if (!expect_ok) {
        st.connect_prevalidated(t, h, b, pre); // throws
        return h;
    }
    st.connect_prevalidated(t, h, b, pre);
    st.connect_2wpd(t, {});
    t.commit();
    return h;
}
} // namespace

TEST(orchard_duplicate_nullifier_in_one_tx)
{
    // A bundle spending the same note twice carries one nullifier twice. Their node: the tx
    // decodes and verifies (two valid spends of one note), prevalidate accepts the block, and
    // connect_orchard's check-then-put refuses the second nullifier (NullifierDoubleSpent):
    // no shielded double spend. Their mempool refuses it the same way (insert puts each
    // nullifier as it checks it); ours: tx_self_conflict.
    bt::ByteArray<32> seed{};
    seed[0] = 7;
    bt::ByteArray<32> sk;
    REQUIRE(zs_sk_from_zip32_seed(seed.data(), 32, 0, 0, sk.data()) == 0);
    bt::ByteArray<96> fvk;
    REQUIRE(zs_fvk(sk.data(), fvk.data()) == 0);
    ShieldedAddress addr;
    REQUIRE(zs_address(fvk.data(), 0, 0, addr.b.data()) == 0);
    bt::kv::MemStore store;
    State st;
    // block 0: an outputs-only bundle creating a 0-value note to addr (value balance 0, fee 0)
    Transaction t0;
    {
        ZsBuilder* b = zs_builder_new(0x02, true, orchard_empty_root().data(), nullptr, 0);
        REQUIRE(zs_builder_add_output(b, addr.b.data(), 0, nullptr) == 0);
        finish(t0, b, sk);
        zs_builder_free(b);
    }
    connect_block(st, store, t0, 1, true);
    // find our note and its position
    Bytes acts = orchard_ffi_actions(*t0.orchard_bundle);
    auto& ob = *t0.orchard_bundle;
    ZsBundle* zb = zs_bundle_parse(acts.data(), ob.actions.size(), ob.flags, ob.value_balance, ob.anchor.data(), ob.proof.data(), ob.proof.size(), ob.binding_sig.data());
    REQUIRE(zb != nullptr);
    bt::ByteArray<115> note;
    uint8_t memo[512];
    uint32_t pos = UINT32_MAX;
    for (size_t i = 0; i < ob.actions.size(); i++)
        if (zs_bundle_decrypt(zb, i, fvk.data(), note.data(), memo) >= 0) pos = uint32_t(i);
    zs_bundle_free(zb);
    REQUIRE(pos != UINT32_MAX);
    Bytes leaves;
    for (auto& a : ob.actions) append(leaves, a.cmx.span());
    uint8_t path[1024];
    Hash32 anchor;
    REQUIRE(zs_merkle_path(leaves.data(), ob.actions.size(), pos, path, anchor.data()) == 0);
    {
        bt::kv::Txn t(store);
        CHECK(anchor == st.orchard_frontier_root(t));
    }
    // block 1: spend the note twice
    Transaction t1;
    {
        ZsBuilder* b = zs_builder_new(0x03, false, anchor.data(), nullptr, 0);
        REQUIRE(zs_builder_add_spend(b, fvk.data(), note.data(), pos, path) == 0);
        REQUIRE(zs_builder_add_spend(b, fvk.data(), note.data(), pos, path) == 0);
        REQUIRE(zs_builder_add_output(b, addr.b.data(), 0, nullptr) == 0);
        finish(t1, b, sk);
        zs_builder_free(b);
    }
    size_t same = 0;
    for (auto& a : t1.orchard_bundle->actions)
        for (auto& c : t1.orchard_bundle->actions)
            if (&a != &c && a.nf == c.nf) same++;
    CHECK(same >= 2);
    CHECK_EQ(orchard_verify(*t1.orchard_bundle, t1.txid()), 0);
    CHECK(tx_self_conflict(t1) == std::optional<std::string>("NullifierDoubleSpent"));
    bool threw = false;
    try {
        connect_block(st, store, t1, 2, false);
    } catch (const StateError& e) {
        threw = std::string(e.what()).find("NullifierDoubleSpent") != std::string::npos;
    }
    CHECK(threw);
    // the same outpoint twice in one tx: refused by the mempool and by block prevalidation
    Transaction t2;
    OutPoint op{OutPoint::Deposit, Hash32{}, 0};
    t2.inputs = {{op, Hash32{}}, {op, Hash32{}}};
    CHECK(tx_self_conflict(t2) == std::optional<std::string>("UtxoDoubleSpent"));
}
