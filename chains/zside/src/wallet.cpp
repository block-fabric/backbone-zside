// Copyright (c) 2026 The Backbone developers
// Distributed under the MIT software license.
#include <zside/orchard_ffi.h>
#include <zside/wallet.h>

#include <bt/crypto.h>

#include <sodium.h>

#include <algorithm>

namespace zside {

using bt::kv::Txn;

enum : uint8_t { W_SEED = 1, W_INDEX_TO_ADDR = 2, W_ADDR_TO_INDEX = 3, W_ORCHARD_INDEX = 4 };

static constexpr uint32_t ANCHOR_CHECKPOINT_DEPTH = 3; // lib/wallet/mod.rs:156

// ------------------------------------------------------------------ bip32ish (lib/wallet/bip32.rs)
static bt::frost::Scalar scalar_from_uniform_be64(const uint8_t* be)
{
    bt::ByteArray<64> le;
    for (int i = 0; i < 64; i++) le[i] = be[63 - i]; // bytes.reverse(); from_bytes_mod_order_wide
    return bt::frost::reduce_wide(le);
}

static ZsXpriv finish_child(const ZsXpriv& parent, const bt::Blake3& h)
{
    uint8_t out[96];
    h.finalize_xof(out, 96);
    ZsXpriv c;
    bt::frost::Scalar tweak = scalar_from_uniform_be64(out);
    crypto_core_ristretto255_scalar_add(c.secret.data(), parent.secret.data(), tweak.data());
    std::memcpy(c.chaincode.data(), out + 64, 32);
    return c;
}

ZsXpriv ZsXpriv::master(const bt::ByteArray<64>& seed)
{
    bt::frost::init();
    auto h = bt::Blake3::derive_key("zSide seed");
    h.update(seed.span());
    uint8_t out[96];
    h.finalize_xof(out, 96);
    ZsXpriv x;
    x.secret = scalar_from_uniform_be64(out);
    std::memcpy(x.chaincode.data(), out + 64, 32);
    return x;
}

ZsXpriv ZsXpriv::derive_hardened(uint32_t index) const
{
    bt::Blake3 h(chaincode); // Hasher<true>: keyed, then 0x00
    uint8_t zero = 0;
    h.update(&zero, 1);
    h.update(secret.span()); // PrimeField repr: 32-byte little-endian
    uint32_t n = index | 0x80000000u;
    uint8_t be[4] = {uint8_t(n >> 24), uint8_t(n >> 16), uint8_t(n >> 8), uint8_t(n)};
    h.update(be, 4);
    return finish_child(*this, h);
}

ZsXpriv ZsXpriv::derive_non_hardened(uint32_t index) const
{
    bt::Blake3 h(chaincode); // Hasher<false>
    h.update(bt::frost::SigningKey{secret}.verifying_key().span());
    uint8_t be[4] = {uint8_t(index >> 24), uint8_t(index >> 16), uint8_t(index >> 8), uint8_t(index)};
    h.update(be, 4);
    return finish_child(*this, h);
}

// m/43'/1899'/0'/98'/<purpose>'
static bt::frost::Scalar node_secret(const bt::ByteArray<64>& seed, KeyDerivation d, uint32_t purpose, std::optional<uint32_t> last)
{
    if (d == KeyDerivation::Hmac) {
        auto v = bt::hd::Variant::V0_18_1;
        auto x = bt::hd::Xpriv::master(seed, v).derive_hardened(43, v).derive_hardened(1899, v).derive_hardened(0, v).derive_hardened(THIS_SIDECHAIN, v).derive_hardened(purpose, v);
        if (last) x = purpose == 2 ? x.derive_hardened(*last, v) : x.derive(*last, v);
        return x.secret;
    }
    auto x = ZsXpriv::master(seed).derive_hardened(43).derive_hardened(1899).derive_hardened(0).derive_hardened(THIS_SIDECHAIN).derive_hardened(purpose);
    if (last) {
        if (purpose == 2) x = x.derive_hardened(*last);
        else if (*last & 0x80000000u) x = x.derive_hardened(*last & 0x7fffffffu); // ChildIndex::from
        else x = x.derive_non_hardened(*last);
    }
    return x.secret;
}

bt::frost::SigningKey Wallet::transparent_key(const bt::ByteArray<64>& seed, uint32_t index, KeyDerivation d)
{
    auto s = node_secret(seed, d, 0, index);
    if (s.is_zero()) throw std::runtime_error("expected secret scalar to be non-zero");
    return bt::frost::SigningKey{s};
}

bt::ByteArray<32> Wallet::orchard_spending_key(const bt::ByteArray<64>& seed, KeyDerivation d)
{
    auto s = node_secret(seed, d, 2, 0u); // m/.../2'/0'
    bt::ByteArray<32> sk;
    if (zs_sk_from_zip32_seed(s.data(), 32, 0, 0, sk.data()) != 0) throw std::runtime_error("zip32 derivation failed");
    return sk;
}

bt::ByteArray<96> Wallet::full_viewing_key(const bt::ByteArray<32>& sk)
{
    bt::ByteArray<96> f;
    if (zs_fvk(sk.data(), f.data()) != 0) throw std::runtime_error("invalid spending key");
    return f;
}

ShieldedAddress Wallet::shielded_address(const bt::ByteArray<96>& fvk, uint32_t index)
{
    ShieldedAddress a;
    if (zs_address(fvk.data(), index, 0, a.b.data()) != 0) throw std::runtime_error("invalid fvk");
    return a;
}

// ------------------------------------------------------------------ seed
Wallet::Wallet(const std::string& path, Node& node, KeyDerivation d) : store_(bt::kv::open_sqlite(path)), node_(node), deriv_(d) {}

std::optional<bt::ByteArray<64>> Wallet::seed()
{
    Txn t(*store_);
    auto v = t.get(W_SEED, bt::Bytes{0});
    if (!v || v->size() != 64) return std::nullopt;
    return bt::ByteArray<64>::from_span(*v);
}

bt::ByteArray<64> Wallet::need_seed()
{
    auto s = seed();
    if (!s) throw std::runtime_error("no seed");
    return *s;
}

bool Wallet::has_seed()
{
    std::lock_guard<std::mutex> l(mu_);
    return seed().has_value();
}

void Wallet::set_seed(const bt::ByteArray<64>& s)
{
    std::lock_guard<std::mutex> l(mu_);
    auto cur = seed();
    if (cur) {
        if (*cur == s) return;
        throw std::runtime_error("seed already exists");
    }
    Txn t(*store_);
    t.put(W_SEED, bt::Bytes{0}, s.span());
    t.clear(W_INDEX_TO_ADDR);
    t.clear(W_ADDR_TO_INDEX);
    t.clear(W_ORCHARD_INDEX);
    t.commit();
}

std::optional<Hash32> Wallet::seed_digest(std::string_view label)
{
    std::lock_guard<std::mutex> l(mu_);
    auto s = seed();
    if (!s) return std::nullopt;
    const uint8_t zero = 0;
    Hash32 h = bt::sha256_parts({bt::ByteSpan(reinterpret_cast<const uint8_t*>(label.data()), label.size()), bt::ByteSpan(&zero, 1), s->span()});
    sodium_memzero(s->data(), s->size());
    return h;
}

void Wallet::set_seed_from_mnemonic(const std::string& mnemonic)
{
    auto p = bt::hd::parse_mnemonic(mnemonic);
    if (!p) throw std::runtime_error(bt::hd::mnemonic_error(mnemonic));
    set_seed(bt::hd::mnemonic_to_seed(*p));
}

bt::frost::SigningKey Wallet::key(uint32_t index) { return transparent_key(need_seed(), index, deriv_); }

static Bytes be32(uint32_t v)
{
    Writer w;
    w.u32be(v);
    return w.buf;
}
static uint32_t rd_be32(bt::ByteSpan b) { return uint32_t(b[0]) << 24 | uint32_t(b[1]) << 16 | uint32_t(b[2]) << 8 | b[3]; }

// ------------------------------------------------------------------ addresses
Address Wallet::get_new_transparent_address()
{
    std::lock_guard<std::mutex> l(mu_);
    Txn t(*store_);
    uint32_t index = 0; // lib/wallet/mod.rs:515-530: last + 1, else 0
    if (auto lv = t.last(W_INDEX_TO_ADDR)) index = rd_be32(lv->first) + 1;
    Address a = address_from_vk(key(index).verifying_key());
    t.put(W_INDEX_TO_ADDR, be32(index), a.b.span());
    t.put(W_ADDR_TO_INDEX, a.b.span(), be32(index));
    t.commit();
    return a;
}

Address Wallet::get_or_generate_last_transparent_address()
{
    {
        std::lock_guard<std::mutex> l(mu_);
        Txn t(*store_);
        if (auto lv = t.last(W_INDEX_TO_ADDR)) {
            Address a;
            std::memcpy(a.b.data(), lv->second.data(), 20);
            return a;
        }
    }
    return get_new_transparent_address();
}

std::vector<Address> Wallet::transparent_addresses()
{
    std::lock_guard<std::mutex> l(mu_);
    Txn t(*store_);
    std::vector<Address> r;
    t.scan(W_INDEX_TO_ADDR, [&](bt::ByteSpan, bt::ByteSpan v) {
        Address a;
        std::memcpy(a.b.data(), v.data(), 20);
        r.push_back(a);
        return true;
    });
    std::sort(r.begin(), r.end(), [](const Address& a, const Address& b) { return a.to_base58() < b.to_base58(); });
    return r;
}

ShieldedAddress Wallet::get_new_shielded_address()
{
    std::lock_guard<std::mutex> l(mu_);
    Txn t(*store_);
    uint32_t index = 0; // :465-483
    if (auto lv = t.last(W_ORCHARD_INDEX)) index = rd_be32(lv->first) + 1;
    auto a = shielded_address(full_viewing_key(orchard_spending_key(need_seed(), deriv_)), index);
    t.put(W_ORCHARD_INDEX, be32(index), a.b.span());
    t.commit();
    return a;
}

std::vector<ShieldedAddress> Wallet::shielded_addresses()
{
    std::lock_guard<std::mutex> l(mu_);
    Txn t(*store_);
    std::vector<ShieldedAddress> r;
    t.scan(W_ORCHARD_INDEX, [&](bt::ByteSpan, bt::ByteSpan v) {
        ShieldedAddress a;
        std::memcpy(a.b.data(), v.data(), 43);
        r.push_back(a);
        return true;
    });
    std::sort(r.begin(), r.end(), [](const ShieldedAddress& a, const ShieldedAddress& b) { return a.to_string() < b.to_string(); });
    return r;
}

bool Wallet::is_mine(const Address& a)
{
    std::lock_guard<std::mutex> l(mu_);
    Txn t(*store_);
    return t.get(W_ADDR_TO_INDEX, a.b.span()).has_value();
}

// ------------------------------------------------------------------ coins
std::vector<std::pair<OutPoint, Output>> Wallet::utxos()
{
    auto a = transparent_addresses();
    return node_.utxos_by_addresses(std::set<Address>(a.begin(), a.end()));
}

std::vector<std::pair<OutPoint, SpentOutput>> Wallet::stxos()
{
    auto a = transparent_addresses();
    return node_.stxos_by_addresses(std::set<Address>(a.begin(), a.end()));
}

std::vector<std::pair<OutPoint, Output>> Wallet::utxos_unconfirmed()
{
    std::vector<std::pair<OutPoint, Output>> r;
    for (auto& at : node_.mempool()) {
        Hash32 txid = at.transaction.txid();
        for (uint32_t v = 0; v < at.transaction.outputs.size(); v++)
            if (is_mine(at.transaction.outputs[v].address)) r.emplace_back(OutPoint{OutPoint::Regular, txid, v}, at.transaction.outputs[v]);
    }
    return r;
}

std::vector<std::pair<OutPoint, SpentOutput>> Wallet::stxos_unconfirmed()
{
    std::map<OutPoint, Output> mine;
    for (auto& [op, o] : utxos()) mine[op] = o;
    std::vector<std::pair<OutPoint, SpentOutput>> r;
    for (auto& at : node_.mempool()) {
        Hash32 txid = at.transaction.txid();
        for (uint32_t i = 0; i < at.transaction.inputs.size(); i++) {
            auto it = mine.find(at.transaction.inputs[i].first);
            if (it != mine.end()) r.emplace_back(it->first, SpentOutput{it->second, InPoint{InPoint::Regular, txid, i}});
        }
    }
    return r;
}

// ------------------------------------------------------------------ chain scan (notes, tree)
struct Wallet::Scan {
    std::vector<Hash32> leaves;            // every note commitment of the active chain, in order
    std::vector<uint64_t> leaves_at_end;   // leaves after block h (index = height)
    std::vector<WalletNote> notes;         // received, value > 0, not yet spent on chain
    std::set<Hash32> pending_nullifiers;   // spent by mempool txs
};

Wallet::Scan Wallet::scan()
{
    Scan s;
    auto sd = seed();
    if (!sd) return s;
    auto fvk = full_viewing_key(orchard_spending_key(*sd, deriv_));
    auto h = node_.height();
    std::vector<WalletNote> recv;
    if (h)
        for (uint32_t height = 0; height <= *h; height++) {
            auto bh = node_.block_hash_at(height);
            auto body = bh ? node_.body(*bh) : std::nullopt;
            if (!body) throw std::runtime_error("wallet scan: missing block " + std::to_string(height));
            for (auto& tx : body->transactions) {
                if (!tx.orchard_bundle) continue;
                auto& b = *tx.orchard_bundle;
                Bytes acts = orchard_ffi_actions(b);
                ZsBundle* zb = zs_bundle_parse(acts.data(), b.actions.size(), b.flags, b.value_balance, b.anchor.data(), b.proof.data(), b.proof.size(), b.binding_sig.data());
                if (!zb) throw std::runtime_error("wallet scan: bundle does not decode");
                Hash32 txid = tx.txid();
                for (size_t i = 0; i < b.actions.size(); i++) {
                    WalletNote n;
                    uint8_t memo[512];
                    if (zs_bundle_decrypt(zb, i, fvk.data(), n.note.data(), memo) >= 0) {
                        uint64_t v = 0;
                        for (int k = 7; k >= 0; k--) v = v << 8 | n.note[43 + k];
                        if (v != 0) { // wallet/mod.rs:1196: zero-value notes are not kept
                            n.value = v;
                            n.position = s.leaves.size() + i;
                            n.height = height;
                            n.txid = txid;
                            zs_note_nullifier(n.note.data(), fvk.data(), n.nullifier.data());
                            recv.push_back(n);
                        }
                    }
                }
                zs_bundle_free(zb);
                for (auto& a : b.actions) s.leaves.push_back(a.cmx);
            }
            s.leaves_at_end.push_back(s.leaves.size());
        }
    {
        std::lock_guard<std::recursive_mutex> l(node_.lock());
        Txn t(node_.store());
        for (auto& n : recv)
            if (!node_.state().orchard_nullifier(t, n.nullifier)) s.notes.push_back(n);
    }
    for (auto& at : node_.mempool())
        if (at.transaction.orchard_bundle)
            for (auto& a : at.transaction.orchard_bundle->actions) s.pending_nullifiers.insert(a.nf);
    return s;
}

std::vector<WalletNote> Wallet::notes() { return scan().notes; }

// The app layer's view of the shielded account: what scan() finds, plus the memos, the notes the wallet sent to others
// (recovered with its outgoing viewing key: the wallet's bundles are built with it), which transaction spent each note,
// and the mempool's. Read only.
ShieldedView Wallet::shielded_view()
{
    ShieldedView v;
    auto sd = seed();
    if (!sd) return v;
    const auto sk = orchard_spending_key(*sd, deriv_);
    sodium_memzero(sd->data(), sd->size());
    const auto fvk = full_viewing_key(sk);
    std::map<Hash32, size_t> by_nf;
    uint64_t leaves = 0;
    std::vector<uint64_t> leaves_at_end;
    auto look = [&](const Transaction& tx, std::optional<uint32_t> height) {
        if (!tx.orchard_bundle) return;
        const auto& b = *tx.orchard_bundle;
        const Hash32 txid = tx.txid();
        bool touches = false;
        for (const auto& a : b.actions) {
            auto it = by_nf.find(a.nf);
            if (it == by_nf.end()) continue;
            ShieldedNote& n = v.notes[it->second];
            if (n.spent_in) continue;
            n.spent_in = txid;
            n.spent_pending = !height;
            v.spent_by_tx[txid] += n.value;
            touches = true;
        }
        Bytes acts = orchard_ffi_actions(b);
        ZsBundle* zb = zs_bundle_parse(acts.data(), b.actions.size(), b.flags, b.value_balance, b.anchor.data(), b.proof.data(), b.proof.size(), b.binding_sig.data());
        if (zb) {
            for (size_t i = 0; i < b.actions.size(); i++) {
                bt::ByteArray<115> note;
                uint8_t memo[512];
                ShieldedNote n;
                int32_t scope = zs_bundle_decrypt(zb, i, fvk.data(), note.data(), memo);
                if (scope >= 0) {
                    n.incoming = true;
                    n.internal = scope == 1;
                } else if (zs_bundle_recover(zb, i, fvk.data(), note.data(), memo) >= 0) {
                    n.incoming = false;
                } else {
                    continue;
                }
                uint64_t value = 0;
                for (int k = 7; k >= 0; k--) value = value << 8 | note[43 + k];
                if (value == 0) continue; // the builder's dummy outputs; zero-value notes are not kept (wallet/mod.rs:1196)
                n.txid = txid;
                n.height = height;
                n.value = value;
                std::memcpy(n.address.b.data(), note.data(), 43);
                std::memcpy(n.memo.data(), memo, 512);
                n.position = leaves + i;
                if (n.incoming) {
                    Hash32 nf;
                    zs_note_nullifier(note.data(), fvk.data(), nf.data());
                    // A note of the mempool can be spent only once it is in a block: no nullifier to look for yet.
                    if (height) by_nf[nf] = v.notes.size();
                }
                v.notes.push_back(n);
                touches = true;
            }
            zs_bundle_free(zb);
        }
        if (touches) v.value_balance[txid] = b.value_balance;
        if (height) leaves += b.actions.size();
    };
    const auto tip = node_.height();
    if (tip)
        for (uint32_t height = 0; height <= *tip; height++) {
            auto bh = node_.block_hash_at(height);
            auto body = bh ? node_.body(*bh) : std::nullopt;
            if (!body) throw std::runtime_error("wallet scan: missing block " + std::to_string(height));
            for (const auto& tx : body->transactions) look(tx, height);
            leaves_at_end.push_back(leaves);
        }
    for (const auto& at : node_.mempool()) look(at.transaction, std::nullopt);
    // Spendable now: a note under the anchor ANCHOR_CHECKPOINT_DEPTH blocks below the tip (select_notes).
    uint64_t anchor_leaves = 0;
    if (!leaves_at_end.empty()) {
        const uint32_t t = uint32_t(leaves_at_end.size() - 1);
        anchor_leaves = leaves_at_end[t - std::min(ANCHOR_CHECKPOINT_DEPTH, t)];
    }
    for (const auto& n : v.notes) {
        if (!n.incoming) continue;
        if (!n.height) {
            v.pending_in += n.value;
            continue;
        }
        if (n.spent_in && !n.spent_pending) continue;
        v.total += n.value;
        if (n.spent_in) continue;
        v.available += n.value;
        if (n.position < anchor_leaves) v.spendable += n.value;
    }
    return v;
}

// get_balance (:1521-1581): transparent from UTXOs (withdrawals not available) plus outputs
// spent by unconfirmed txs; shielded from unspent notes plus notes spent by unconfirmed txs.
Balance Wallet::balance()
{
    Balance b;
    for (auto& [op, o] : utxos()) {
        b.total_transparent += o.get_value();
        if (o.content.kind != Content::Withdrawal) b.available_transparent += o.get_value();
    }
    auto s = scan();
    for (auto& n : s.notes) {
        b.total_shielded += n.value;
        if (!s.pending_nullifiers.count(n.nullifier)) b.available_shielded += n.value;
    }
    for (auto& [op, so] : stxos_unconfirmed()) {
        b.available_transparent -= std::min(b.available_transparent, so.output.get_value());
    }
    return b;
}

// select_transparent_coins (:654-685)
std::pair<uint64_t, std::vector<std::pair<OutPoint, Output>>> Wallet::select_transparent(uint64_t value)
{
    auto u = utxos();
    std::set<OutPoint> pending;
    for (auto& [op, _] : stxos_unconfirmed()) pending.insert(op);
    std::stable_sort(u.begin(), u.end(), [](auto& a, auto& b) { return a.second.get_value() < b.second.get_value(); });
    uint64_t total = 0;
    std::vector<std::pair<OutPoint, Output>> sel;
    for (auto& [op, o] : u) {
        if (o.content.kind == Content::Withdrawal || pending.count(op)) continue;
        if (total > value) break;
        total += o.get_value();
        sel.emplace_back(op, o);
    }
    if (total < value) throw std::runtime_error("not enough funds");
    return {total, sel};
}

static std::pair<std::vector<std::pair<OutPoint, Hash32>>, bt::utreexo::Proof> inputs_with_proof(Node& node, const std::vector<std::pair<OutPoint, Output>>& coins)
{
    std::vector<std::pair<OutPoint, Hash32>> ins;
    std::vector<bt::utreexo::NodeHash> targets;
    for (auto& [op, o] : coins) {
        Hash32 h = pointed_output_hash(op, o);
        ins.emplace_back(op, h);
        targets.push_back(bt::utreexo::NodeHash::some(h));
    }
    auto acc = node.tip_accumulator();
    auto p = acc.prove(targets);
    if (!p) throw std::runtime_error("utreexo: cannot prove inputs");
    return {ins, *p};
}

static uint64_t add(uint64_t a, uint64_t b)
{
    if (a + b < a) throw std::runtime_error("amount overflow");
    return a + b;
}

Transaction Wallet::create_transparent_transfer(const Address& dest, uint64_t value, uint64_t fee)
{
    auto [total, coins] = select_transparent(add(value, fee));
    auto [ins, proof] = inputs_with_proof(node_, coins);
    Transaction tx;
    tx.inputs = ins;
    tx.proof = proof;
    tx.outputs.push_back(Output{dest, Content{Content::Value, value, 0, {}}});
    tx.outputs.push_back(Output{get_new_transparent_address(), Content{Content::Value, total - value - fee, 0, {}}});
    return tx;
}

Transaction Wallet::create_withdrawal(const bt::btc::Address& main_address, uint64_t value, uint64_t main_fee, uint64_t fee)
{
    auto [total, coins] = select_transparent(add(add(value, fee), main_fee));
    auto [ins, proof] = inputs_with_proof(node_, coins);
    Transaction tx;
    tx.inputs = ins;
    tx.proof = proof;
    Content w;
    w.kind = Content::Withdrawal;
    w.value = value;
    w.main_fee = main_fee;
    w.main_address = main_address;
    tx.outputs.push_back(Output{get_new_transparent_address(), w});
    tx.outputs.push_back(Output{get_new_transparent_address(), Content{Content::Value, total - value - fee - main_fee, 0, {}}});
    return tx;
}

// ------------------------------------------------------------------ orchard builds
namespace {
struct BuilderGuard {
    ZsBuilder* b;
    ~BuilderGuard() { zs_builder_free(b); }
};

void read_actions(Reader& r, OrchardBundle& b)
{
    uint32_t n = r.u32();
    b.actions.resize(n);
    for (auto& a : b.actions) {
        a.nf = r.array<32>();
        a.rk = r.array<32>();
        a.cmx = r.array<32>();
        a.epk = r.array<32>();
        a.enc = r.array<580>();
        a.out = r.array<80>();
        a.cv = r.array<32>();
        a.spend_auth_sig = r.array<64>();
    }
    b.flags = r.u8();
    b.value_balance = int64_t(r.u64());
    b.anchor = r.array<32>();
}
} // namespace

void Wallet::finish_orchard(Transaction& tx, ::ZsBuilder* builder)
{
    zs_init_prover();
    int32_t err = 0;
    ZsUnsigned* u = zs_builder_build(builder, &err);
    if (!u) throw std::runtime_error("orchard bundle build failed (" + std::to_string(err) + ")");
    uint8_t* buf = nullptr;
    size_t len = 0;
    zs_unsigned_effects(u, &buf, &len);
    OrchardBundle eff;
    {
        Reader r(bt::ByteSpan(buf, len));
        read_actions(r, eff);
    }
    zs_buffer_free(buf, len);
    tx.orchard_bundle = eff;
    Hash32 sighash = tx.txid(); // authorization.rs:250-276: the txid (bundle without auth)
    auto sk = orchard_spending_key(need_seed(), deriv_);
    if (zs_unsigned_finish(u, sighash.data(), sk.data(), 1, &buf, &len) != 0) throw std::runtime_error("orchard signing failed");
    OrchardBundle full;
    {
        Reader r(bt::ByteSpan(buf, len));
        read_actions(r, full);
        full.proof = r.raw(r.u32());
        full.binding_sig = r.array<64>();
    }
    zs_buffer_free(buf, len);
    tx.orchard_bundle = full;
    if (tx.txid() != sighash) throw std::runtime_error("orchard signing changed the effects");
}

Transaction Wallet::create_shield(uint64_t value, uint64_t fee)
{
    auto [total, coins] = select_transparent(add(value, fee));
    auto [ins, proof] = inputs_with_proof(node_, coins);
    Transaction tx;
    tx.inputs = ins;
    tx.proof = proof;
    uint64_t change = total - value - fee;
    if (change) tx.outputs.push_back(Output{get_new_transparent_address(), Content{Content::Value, change, 0, {}}});
    auto dest = get_new_shielded_address();
    auto fvk = full_viewing_key(orchard_spending_key(need_seed(), deriv_));
    // SPENDS_DISABLED with the empty anchor (their path without a note to consolidate)
    BuilderGuard g{zs_builder_new(0x02, true, orchard_empty_root().data(), fvk.data(), 1)};
    if (!g.b || zs_builder_add_output(g.b, dest.b.data(), value, nullptr) != 0) throw std::runtime_error("orchard output");
    finish_orchard(tx, g.b);
    return tx;
}

namespace {
struct Spend {
    WalletNote n;
    std::array<uint8_t, 1024> path;
};
} // namespace

// select_shielded_coins (:584-652): anchor = root ANCHOR_CHECKPOINT_DEPTH blocks under the tip
// (the deepest available), notes newer than the anchor skipped.
static std::pair<Hash32, std::vector<Spend>> select_notes(const Wallet::Scan& s, uint64_t value, uint64_t& total)
{
    if (s.leaves_at_end.empty()) throw std::runtime_error("not enough funds");
    uint32_t tip = uint32_t(s.leaves_at_end.size() - 1);
    uint32_t depth = std::min(ANCHOR_CHECKPOINT_DEPTH, tip);
    uint32_t anchor_height = tip - depth;
    uint64_t n_leaves = s.leaves_at_end[anchor_height];
    Hash32 anchor = orchard_empty_root();
    Bytes leaves;
    for (uint64_t i = 0; i < n_leaves; i++) append(leaves, s.leaves[i].span());
    std::vector<Spend> sel;
    total = 0;
    for (auto& n : s.notes) {
        if (total >= value) break;
        if (n.position >= n_leaves || s.pending_nullifiers.count(n.nullifier)) continue;
        Spend sp{n, {}};
        if (zs_merkle_path(leaves.data(), n_leaves, uint32_t(n.position), sp.path.data(), anchor.data()) != 0) continue;
        total += n.value;
        sel.push_back(sp);
    }
    if (total < value) throw std::runtime_error("not enough funds");
    return {anchor, sel};
}

Transaction Wallet::create_shielded_transfer(const ShieldedAddress& dest, uint64_t value, uint64_t fee, const std::array<uint8_t, 512>* memo)
{
    auto s = scan();
    uint64_t total = 0;
    auto [anchor, spends] = select_notes(s, add(value, fee), total);
    auto change_addr = get_new_shielded_address();
    auto fvk = full_viewing_key(orchard_spending_key(need_seed(), deriv_));
    Transaction tx;
    tx.proof = node_.tip_accumulator().prove({}).value_or(bt::utreexo::Proof{});
    BuilderGuard g{zs_builder_new(0x03, false, anchor.data(), fvk.data(), 1)};
    if (!g.b || zs_builder_add_output(g.b, dest.b.data(), value, memo ? memo->data() : nullptr) != 0 ||
        zs_builder_add_output(g.b, change_addr.b.data(), total - value - fee, nullptr) != 0)
        throw std::runtime_error("orchard output");
    for (auto& sp : spends)
        if (zs_builder_add_spend(g.b, fvk.data(), sp.n.note.data(), uint32_t(sp.n.position), sp.path.data()) != 0) throw std::runtime_error("orchard spend");
    finish_orchard(tx, g.b);
    return tx;
}

Transaction Wallet::create_unshield(uint64_t value, uint64_t fee)
{
    auto s = scan();
    uint64_t total = 0;
    auto [anchor, spends] = select_notes(s, add(value, fee), total);
    Transaction tx;
    tx.proof = node_.tip_accumulator().prove({}).value_or(bt::utreexo::Proof{});
    tx.outputs.push_back(Output{get_new_transparent_address(), Content{Content::Value, value, 0, {}}});
    auto change_addr = get_new_shielded_address();
    auto fvk = full_viewing_key(orchard_spending_key(need_seed(), deriv_));
    BuilderGuard g{zs_builder_new(0x03, true, anchor.data(), fvk.data(), 1)};
    if (!g.b || zs_builder_add_output(g.b, change_addr.b.data(), total - value - fee, nullptr) != 0) throw std::runtime_error("orchard output");
    for (auto& sp : spends)
        if (zs_builder_add_spend(g.b, fvk.data(), sp.n.note.data(), uint32_t(sp.n.position), sp.path.data()) != 0) throw std::runtime_error("orchard spend");
    finish_orchard(tx, g.b);
    return tx;
}

AuthorizedTransaction Wallet::authorize(const Transaction& tx)
{
    AuthorizedTransaction at;
    at.transaction = tx;
    Bytes msg = tx.canonical_bytes();
    auto all = node_.utxos();
    for (auto& [op, _] : tx.inputs) {
        auto it = std::find_if(all.begin(), all.end(), [&](auto& p) { return p.first == op; });
        if (it == all.end()) throw std::runtime_error("no utxo " + op.to_string());
        uint32_t index;
        {
            std::lock_guard<std::mutex> l(mu_);
            Txn t(*store_);
            auto v = t.get(W_ADDR_TO_INDEX, it->second.address.b.span());
            if (!v) throw std::runtime_error("WrongKeyForAddress: no key for " + it->second.address.to_base58());
            index = rd_be32(*v);
        }
        auto sk = key(index);
        at.authorizations.push_back(Authorization{sk.verifying_key(), sk.sign(msg)});
    }
    return at;
}

} // namespace zside
