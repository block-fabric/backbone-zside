// Reproduction tests for the consensus quirks zSide (thunder-orchard b225827) shares with
// thunder-rust (study §5, Part II Thunder §5 and zSide §5); the Orchard quirks are in
// test_zside_orchard.cpp. Each test pins behaviour a compatible node must share with theirs.
#include "test.h"

#include <zside/archive.h>
#include <zside/state.h>

#include <bt/crypto.h>

using namespace zside;
using bt::kv::MemStore;
using bt::kv::Txn;
using bt::utreexo::NodeHash;

namespace {

bt::frost::SigningKey key(const std::string& label)
{
    auto h = bt::sha512(bt::ByteSpan((const uint8_t*)label.data(), label.size()));
    return bt::frost::SigningKey{bt::frost::reduce_wide(h)};
}
Address addr(const bt::frost::SigningKey& k) { return address_from_vk(k.verifying_key()); }

struct Chain {
    MemStore store;
    State st;
    uint32_t main_counter = 1;

    Hash32 next_main()
    {
        Hash32 h;
        h[0] = uint8_t(main_counter);
        h[1] = uint8_t(main_counter >> 8);
        h[31] = 0xaa;
        main_counter++;
        return h;
    }

    // Build, root and connect a block; throws StateError if invalid.
    Header connect(const std::vector<AuthorizedTransaction>& txs, Coinbase cb = {}, bool check_auth = true)
    {
        Txn t(store);
        Body b = Body::from_authorized(txs, cb);
        Header h;
        h.prev_side_hash = st.tip(t);
        h.prev_main_hash = next_main();
        h.merkle_root = compute_merkle_root(b.coinbase, b.transactions);
        auto pre = st.prevalidate(t, h, b, State::CheckOpts{check_auth, false});
        h.roots = pre.roots_after;
        pre = st.prevalidate(t, h, b); // every check
        st.connect_prevalidated(t, h, b, pre);
        st.connect_2wpd(t, {});
        t.commit();
        return h;
    }

    void deposit(const Address& a, uint64_t value, uint8_t txid_byte, uint32_t vout = 0)
    {
        bt::mainchain::Deposit d;
        d.txid[0] = txid_byte;
        d.vout = vout;
        std::string s = a.to_base58();
        d.address.assign(s.begin(), s.end());
        d.value_sats = value;
        bt::mainchain::TwoWayPegData w;
        bt::mainchain::BlockInfo bi;
        bi.events.emplace_back(d);
        w.block_info.emplace_back(next_main(), bi);
        Txn t(store);
        st.connect_2wpd(t, w);
        t.commit();
    }

    std::pair<OutPoint, Output> find_utxo(const Address& a)
    {
        Txn t(store);
        for (auto& [op, o] : st.utxos(t))
            if (o.address == a) return {op, o};
        throw std::runtime_error("no utxo");
    }
};

AuthorizedTransaction spend(const std::vector<std::pair<OutPoint, Output>>& ins, const std::vector<Output>& outs, const std::vector<bt::frost::SigningKey>& keys)
{
    AuthorizedTransaction at;
    for (auto& [op, o] : ins) at.transaction.inputs.emplace_back(op, pointed_output_hash(op, o));
    at.transaction.outputs = outs;
    auto msg = at.transaction.canonical_bytes();
    for (auto& k : keys) at.authorizations.push_back(Authorization{k.verifying_key(), k.sign(msg)});
    return at;
}

Output value_out(const Address& a, uint64_t v) { return Output{a, Content{Content::Value, v, 0, {}}}; }

Output withdrawal_out(const Address& a, uint64_t v, uint64_t fee, const std::string& main)
{
    Content c;
    c.kind = Content::Withdrawal;
    c.value = v;
    c.main_fee = fee;
    c.main_address = *bt::btc::Address::parse(main);
    return Output{a, c};
}

} // namespace

TEST(quirk_intra_block_spend_rejected)
{
    // lib/state/block.rs:68-73: inputs come from the parent's UTXO set only (PR #154 pending)
    Chain c;
    auto k = key("alice");
    c.connect({});
    c.deposit(addr(k), 1000, 1);
    auto dep = c.find_utxo(addr(k));
    auto tx1 = spend({dep}, {value_out(addr(k), 900)}, {k});
    OutPoint op1{OutPoint::Regular, tx1.transaction.txid(), 0};
    auto tx2 = spend({{op1, value_out(addr(k), 900)}}, {value_out(addr(k), 800)}, {k});
    bool rejected = false;
    try {
        c.connect({tx1, tx2});
    } catch (const StateError& e) {
        rejected = std::string(e.what()).find("NoUtxo") != std::string::npos;
    }
    CHECK(rejected);
    c.connect({tx1}); // alone it is fine
}

TEST(quirk_zero_input_tx)
{
    // known upstream consensus behaviour for zero-input transactions, reproduced
    // (details held for coordinated disclosure)
    Chain c;
    auto k = key("bob");
    c.connect({});
    AuthorizedTransaction z;
    z.transaction.outputs.push_back(value_out(addr(k), 0));
    c.connect({z});
    c.connect({z});
    Txn t(c.store);
    size_t n = 0;
    for (auto& [op, o] : c.st.utxos(t))
        if (o.address == addr(k)) n++;
    CHECK_EQ(n, size_t(1)); // same outpoint, overwritten
    CHECK_EQ(c.st.accumulator(t).leaves, uint64_t(2)); // but two accumulator leaves
}

TEST(quirk_authorizations_not_committed)
{
    // types/block/body.rs:154-224: signatures are outside the merkle root and the block hash
    Chain c;
    auto k = key("carol");
    c.connect({});
    c.deposit(addr(k), 5000, 2);
    auto dep = c.find_utxo(addr(k));
    auto a = spend({dep}, {value_out(addr(k), 4000)}, {k});
    auto b = a;
    b.authorizations[0].signature = k.sign(b.transaction.canonical_bytes()); // fresh nonce
    CHECK(!(a.authorizations[0].signature.R == b.authorizations[0].signature.R));
    Body ba = Body::from_authorized({a}, {}), bb = Body::from_authorized({b}, {});
    CHECK(borsh_bytes(ba) != borsh_bytes(bb));
    Txn t(c.store);
    CHECK(compute_merkle_root(ba.coinbase, ba.transactions) == compute_merkle_root(bb.coinbase, bb.transactions));
    CHECK(verify_authorizations(ba) && verify_authorizations(bb));
}

TEST(quirk_deposit_address_parsing)
{
    // proto.rs:446-506: the OP_RETURN bytes must be UTF-8 base58 of exactly 20 bytes,
    // otherwise the deposit is credited to Address::ALL_ZEROS (a burn that stays a UTXO)
    auto k = key("dave");
    Address a = addr(k);
    bt::mainchain::Deposit d;
    d.value_sats = 1;
    std::string plain = a.to_base58();
    d.address.assign(plain.begin(), plain.end());
    CHECK(State::deposit_output(d).address == a);
    std::string s9 = a.format_for_deposit(); // the s98_..._xxxxxx display form burns
    d.address.assign(s9.begin(), s9.end());
    CHECK(State::deposit_output(d).address == Address::ALL_ZEROS);
    d.address = {0xff, 0xfe};
    CHECK(State::deposit_output(d).address == Address::ALL_ZEROS);
    d.address.assign(plain.begin(), plain.end());
    d.address.push_back(' ');
    CHECK(State::deposit_output(d).address == Address::ALL_ZEROS);
}

TEST(quirk_coinbase_may_create_withdrawals)
{
    // block.rs:146-148: coinbase content is not checked; a coinbase Withdrawal output
    // enters the next bundle (value + main_fee must be covered by fees)
    Chain c;
    auto k = key("erin");
    c.connect({});
    c.deposit(addr(k), 100000, 3);
    auto dep = c.find_utxo(addr(k));
    auto tx = spend({dep}, {value_out(addr(k), 50000)}, {k});
    Coinbase cb;
    cb.outputs.push_back(withdrawal_out(addr(k), 40000, 10000, "bc1qaw84063ptkynlelkj4l6jff2erhnru93kcdg96"));
    c.connect({tx}, cb);
    for (int i = 0; i < 4; i++) c.connect({});
    Txn t(c.store);
    auto p = c.st.pending_bundle(t);
    REQUIRE(p.has_value());
    CHECK_EQ(p->first.spend_utxos.size(), size_t(1));
    CHECK_EQ(p->first.outputs[2].value, uint64_t(40000));
}

TEST(quirk_pending_bundle_never_expires)
{
    // two_way_peg_data.rs:623-660: `Dropped` is never set; an unproposed bundle blocks
    // every later withdrawal forever
    Chain c;
    auto k = key("frank");
    c.connect({});
    c.deposit(addr(k), 300000, 4);
    auto dep = c.find_utxo(addr(k));
    auto tx = spend({dep}, {withdrawal_out(addr(k), 100000, 1000, "1A7pUaYFaXHq1JTTJfLfgy2FwFcjNsVXMT"), value_out(addr(k), 198000)}, {k});
    c.connect({tx});
    for (int i = 0; i < 3; i++) c.connect({});
    Hash32 first;
    {
        Txn t(c.store);
        REQUIRE(c.st.pending_bundle_m6id(t).has_value());
        first = *c.st.pending_bundle_m6id(t);
    }
    // a second withdrawal later waits behind the first, however long
    auto rest = c.find_utxo(addr(k));
    {
        Txn t(c.store);
        for (auto& [op, o] : c.st.utxos(t))
            if (o.content.kind == Content::Value && o.address == addr(k)) rest = {op, o};
    }
    auto tx2 = spend({rest}, {withdrawal_out(addr(k), 50000, 1000, "1A7pUaYFaXHq1JTTJfLfgy2FwFcjNsVXMT"), value_out(addr(k), 147000)}, {k});
    c.connect({tx2});
    for (int i = 0; i < 200; i++) c.connect({});
    Txn t(c.store);
    CHECK(*c.st.pending_bundle_m6id(t) == first);
    auto b = c.st.bundle(t, first);
    CHECK(b->second.latest().value == BundleStatus::Pending);
    CHECK_EQ(b->first.bundle.spend_utxos.size(), size_t(1));
}

TEST(quirk_unknown_bundle_confirmed_halts)
{
    // two_way_peg_data.rs:311-354: an unknown bundle Succeeded at side height > 0 fails
    // every block (the chain halts); at height 0 it spends every UTXO
    auto event = [](const Hash32& m6id, bt::mainchain::BundleStatus s) {
        bt::mainchain::TwoWayPegData w;
        bt::mainchain::BlockInfo bi;
        bt::mainchain::WithdrawalBundleEvent e;
        e.m6id = m6id;
        e.status = s;
        bi.events.emplace_back(e);
        Hash32 mh;
        mh[0] = uint8_t(s) + 0x40;
        w.block_info.emplace_back(mh, bi);
        return w;
    };
    Hash32 m6;
    m6.v.fill(0x77);
    {
        Chain c;
        c.connect({});
        c.connect({});
        Txn t(c.store);
        c.st.connect_2wpd(t, event(m6, bt::mainchain::BundleStatus::Submitted)); // unknown, recorded
        bool halted = false;
        try {
            c.st.connect_2wpd(t, event(m6, bt::mainchain::BundleStatus::Confirmed));
        } catch (const StateError& e) {
            halted = std::string(e.what()) == "UnknownWithdrawalBundleConfirmed";
        }
        CHECK(halted);
    }
    {
        Chain c;
        c.connect({});
        c.deposit(addr(key("g")), 1000, 9);
        Txn t(c.store);
        c.st.connect_2wpd(t, event(m6, bt::mainchain::BundleStatus::Submitted));
        c.st.connect_2wpd(t, event(m6, bt::mainchain::BundleStatus::Confirmed));
        CHECK(c.st.utxos(t).empty()); // all UTXOs considered spent
        CHECK(c.st.bundle(t, m6)->first.kind == WithdrawalBundleInfo::UnknownConfirmed);
    }
}

TEST(quirk_bundle_builder_breaks_at_first_misfit)
{
    // two_way_peg_data.rs:91-102: aggregates sorted by (main_fee, value, address) desc;
    // the first one that does not fit ends the bundle, smaller later ones are not tried.
    MemStore store;
    State st;
    Txn t(store);
    auto put_withdrawal = [&](uint32_t i, uint64_t fee, const bt::btc::Address& a) {
        OutPoint op{OutPoint::Regular, Hash32{}, i};
        Output o;
        o.content.kind = Content::Withdrawal;
        o.content.value = 1000;
        o.content.main_fee = fee;
        o.content.main_address = a;
        auto k = op.key();
        Writer w;
        bincode(w, o);
        t.put(State::T_UTXOS, bt::ByteSpan(k.data(), k.size()), w.buf);
    };
    // 3221 P2WPKH aggregates (31-byte txouts) with high fees, then one P2TR (43 bytes)
    // that no longer fits, then one P2WPKH that would still fit.
    for (uint32_t i = 0; i < 3221; i++) {
        bt::btc::Address a;
        a.kind = bt::btc::Address::Kind::Segwit;
        a.program.assign(20, 0);
        a.program[0] = uint8_t(i);
        a.program[1] = uint8_t(i >> 8);
        put_withdrawal(i, 1000000, a);
    }
    bt::btc::Address tr;
    tr.kind = bt::btc::Address::Kind::Segwit;
    tr.witver = 1;
    tr.program.assign(32, 7);
    put_withdrawal(5000, 500000, tr);
    bt::btc::Address small;
    small.kind = bt::btc::Address::Kind::Segwit;
    small.program.assign(20, 0xee);
    put_withdrawal(6000, 1000, small);
    auto b = st.collect_withdrawal_bundle(t, 10);
    REQUIRE(b.has_value());
    CHECK_EQ(b->outputs.size(), size_t(2 + 3221));
    CHECK(bt::btc::inputless_tx_weight(b->outputs) <= 400000);
}

TEST(quirk_empty_root_vs_zero_root)
{
    // types/util.rs:420-447: the header hash treats an Empty root as 32 zero bytes, but
    // validity compares roots as enums, so [Empty] and [Some(0^32)] hash alike while only
    // one of them is valid
    Chain c;
    auto k = key("hank");
    c.connect({});
    c.deposit(addr(k), 700, 5);
    auto dep = c.find_utxo(addr(k));
    auto burn_all = spend({dep}, {}, {k}); // no outputs: whole value is fee, unclaimed
    Header h = c.connect({burn_all});
    REQUIRE(h.roots.size() == 1);
    CHECK(h.roots[0].is_empty());
    Header z = h;
    z.roots[0] = NodeHash::some(Hash32{});
    CHECK(z.hash() == h.hash());
    CHECK(!(z.roots == h.roots));
}

TEST(quirk_utreexo_verify_accepts_half_matched_roots)
{
    // rustreexo proof.rs:267-312: `remaining != matched && remaining != 0` -> false, so a
    // proof whose computed roots half match is accepted even for a non-member leaf
    std::vector<NodeHash> leaves;
    for (uint8_t i = 0; i < 3; i++) leaves.push_back(NodeHash::some(bt::sha256(bt::ByteSpan(&i, 1))));
    bt::utreexo::MemForest f;
    CHECK(!f.modify(leaves, {}).has_value());
    auto p = f.prove({leaves[0], leaves[2]});
    REQUIRE(p.has_value());
    auto ok = f.verify(*p, {leaves[0], leaves[2]});
    CHECK(ok && *ok);
    NodeHash fake = NodeHash::some(Hash32{});
    // computed roots come out as [leaf2, wrong]; leaf2 matches first, wrong does not
    auto quirk = f.verify(*p, {fake, leaves[2]});
    CHECK(quirk && *quirk); // accepted by rustreexo semantics
    auto none = f.verify(*p, {fake, fake});
    CHECK(none && !*none);
    // and a proof with no targets verifies for any claimed spend
    bt::utreexo::Proof empty;
    auto e = f.verify(empty, {fake});
    CHECK(e && *e);
}

TEST(quirk_fork_choice_lower_work_wins_and_first_genesis_sticks)
{
    // archive/mod.rs:1435-1650
    MemStore store;
    Archive ar;
    Txn t(store);
    auto main_block = [&](uint8_t id, const Hash32& prev, uint8_t work) {
        bt::mainchain::BlockHeaderInfo hi;
        hi.block_hash[0] = id;
        hi.block_hash[31] = 1;
        hi.prev_block_hash = prev;
        hi.work[0] = work;
        ar.put_main_header_info(t, hi);
        return hi.block_hash;
    };
    Hash32 m0 = main_block(1, Hash32{}, 1);
    Hash32 m1 = main_block(2, m0, 1);
    Hash32 m2 = main_block(3, m1, 1);
    Hash32 m3 = main_block(4, m2, 1);
    Hash32 m4 = main_block(5, m3, 1);
    auto side = [&](std::optional<Hash32> prev, const Hash32& prev_main, uint8_t salt) {
        Header h;
        h.merkle_root[0] = salt;
        h.prev_side_hash = prev;
        h.prev_main_hash = prev_main;
        ar.put_header(t, h);
        return h.hash();
    };
    Hash32 g0 = side(std::nullopt, m0, 1);
    Hash32 g1 = side(std::nullopt, m0, 2);
    CHECK(!ar.better_tip(t, TipRef{g0, m1}, TipRef{g1, m1}).has_value()); // two genesis: no reorg
    Hash32 a1 = side(g0, m1, 3); // height 1
    Hash32 b1 = side(g0, m3, 4); // height 1, BMM'd later on the same mainchain lineage
    TipRef ta{a1, m2}, tb{b1, m4};
    auto w = ar.better_tip(t, ta, tb);
    REQUIRE(w.has_value());
    CHECK(*w == ta); // equal height, same lineage: the LOWER work tip wins
    Hash32 a2 = side(a1, m2, 5);
    CHECK(*ar.better_tip(t, tb, TipRef{a2, m3}) == (TipRef{a2, m3})); // greater height wins
}

TEST(quirk_deposit_blocks_le_key_order)
{
    // lib/state/mod.rs:73-81: deposit_blocks is keyed by SerdeBincode<u32> (little-endian)
    // under LMDB's memcmp order, so after 256 entries `last()` is no longer the newest
    // and new entries keep overwriting key 256
    Chain c;
    auto k = key("ivy");
    c.connect({});
    for (int i = 0; i < 258; i++) {
        c.connect({});
        bt::mainchain::Deposit d;
        d.txid[0] = uint8_t(i);
        d.txid[1] = uint8_t(i >> 8);
        d.txid[2] = 0x55;
        std::string s = addr(k).to_base58();
        d.address.assign(s.begin(), s.end());
        d.value_sats = 10;
        bt::mainchain::TwoWayPegData w;
        bt::mainchain::BlockInfo bi;
        bi.events.emplace_back(d);
        Hash32 mh;
        mh[0] = uint8_t(i);
        mh[1] = uint8_t(i >> 8);
        mh[2] = 0x66;
        w.block_info.emplace_back(mh, bi);
        Txn t(c.store);
        c.st.connect_2wpd(t, w);
        t.commit();
    }
    Txn t(c.store);
    auto rows = c.st.deposit_blocks(t);
    CHECK_EQ(rows.size(), size_t(257)); // 258 deposit blocks, but seq 256 was overwritten
    // disconnecting the newest deposit block now fails an assertion (their node panics)
    bt::mainchain::TwoWayPegData w;
    bool panicked = false;
    try {
        // the newest window: the last deposit block as connect saw it
        bt::mainchain::Deposit d;
        d.txid[0] = uint8_t(257);
        d.txid[1] = uint8_t(257 >> 8);
        d.txid[2] = 0x55;
        std::string s = addr(k).to_base58();
        d.address.assign(s.begin(), s.end());
        d.value_sats = 10;
        bt::mainchain::BlockInfo bi;
        bi.events.emplace_back(d);
        Hash32 mh;
        mh[0] = uint8_t(257);
        mh[1] = uint8_t(257 >> 8);
        mh[2] = 0x66;
        w.block_info.emplace_back(mh, bi);
        c.st.disconnect_2wpd(t, w);
    } catch (const StateError& e) {
        panicked = e.panic;
    }
    CHECK(panicked);
}
