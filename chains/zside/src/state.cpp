// Copyright (c) 2026 The Backbone developers
// Distributed under the MIT software license.
//
// Literal port of thunder-orchard b225827 lib/state/{mod.rs, block.rs, orchard.rs,
// two_way_peg_data.rs} (= thunder-rust v0.18.1 + the Orchard pool; :NNN cite their lines).
// Function and branch order follow theirs so that every error/accept decision and every
// accumulator insertion order is identical. Comments `//:NNN` cite their line numbers.
#include <zside/orchard_ffi.h>
#include <zside/state.h>

#include <bt/crypto.h>

#include <algorithm>
#include <set>

namespace zside {

using bt::kv::Txn;
using bt::mainchain::BlockEvent;
using bt::mainchain::TwoWayPegData;
using bt::utreexo::NodeHash;

const char* to_string(BundleStatus s)
{
    switch (s) {
    case BundleStatus::Confirmed: return "Confirmed";
    case BundleStatus::Dropped: return "Dropped";
    case BundleStatus::Failed: return "Failed";
    case BundleStatus::Pending: return "Pending";
    case BundleStatus::Submitted: return "Submitted";
    case BundleStatus::SubmittedUnexpected: return "SubmittedUnexpected";
    }
    return "?";
}

static NodeHash nh(const Hash32& h) { return NodeHash::some(h); }

// ------------------------------------------------------------------ AccumulatorDiff
void AccumulatorDiff::insert(const NodeHash& h)
{
    auto it = idx.find(h);
    if (it != idx.end()) {
        if (!it->second->second) { // removal pending: cancel it
            order.erase(it->second);
            idx.erase(it);
        }
        return; // inserting twice -> one insertion
    }
    order.emplace_back(h, true);
    idx[h] = std::prev(order.end());
}

void AccumulatorDiff::remove(const NodeHash& h)
{
    auto it = idx.find(h);
    if (it != idx.end()) {
        if (it->second->second) { // insertion pending: cancel it
            order.erase(it->second);
            idx.erase(it);
        }
        return;
    }
    order.emplace_back(h, false);
    idx[h] = std::prev(order.end());
}

void AccumulatorDiff::split(std::vector<NodeHash>& ins, std::vector<NodeHash>& dels) const
{
    for (auto& [h, add] : order) (add ? ins : dels).push_back(h);
}

// ------------------------------------------------------------------ withdrawal bundle
static uint32_t varint_size(uint64_t n) { return uint32_t(bt::btc::compact_size_len(n)); }

static std::optional<uint32_t> txout_size(uint32_t spk_size)
{
    uint64_t s = 8ull + varint_size(spk_size) + spk_size;
    if (s > UINT32_MAX) return std::nullopt;
    return uint32_t(s);
}

bool predict_weight_ok(uint32_t n_outputs, uint32_t sum_txout_sizes)
{
    const uint64_t TXIN = 36 + 1 + 0 + 4; // treasury input, empty scriptSig
    uint64_t no = uint64_t(n_outputs) + 2;
    if (no > UINT32_MAX) return false;
    uint64_t sum = uint64_t(*txout_size(34)) + *txout_size(10) + sum_txout_sizes;
    if (sum > UINT32_MAX) return false;
    uint64_t base = 4 + (varint_size(1) + TXIN) + (varint_size(no) + sum) + 4;
    if (base > UINT32_MAX) return false;
    return base * 4 <= 400000; // MAX_STANDARD_WEIGHT
}

std::optional<WithdrawalBundle> make_withdrawal_bundle(uint32_t block_height, uint64_t fee, std::map<OutPoint, Output> spend_utxos,
                                                       std::vector<bt::btc::TxOut> payouts)
{
    // inputs commitment: hash(Vec<OutPoint> = sorted keys ++ [Regular{0^32, block_height}])  types/lib.rs:226-247
    Writer w;
    w.borsh_len(spend_utxos.size() + 1);
    for (auto& [op, _] : spend_utxos) borsh(w, op);
    OutPoint fake{OutPoint::Regular, Hash32{}, block_height};
    borsh(w, fake);
    Hash32 commitment = bt::blake3(w.buf);
    Writer fw;
    fw.u64be(fee);
    WithdrawalBundle b;
    b.spend_utxos = std::move(spend_utxos);
    b.outputs.push_back({0, bt::btc::op_return_push(fw.buf)});
    b.outputs.push_back({0, bt::btc::op_return_push(commitment.span())});
    for (auto& p : payouts) b.outputs.push_back(std::move(p));
    if (bt::btc::inputless_tx_weight(b.outputs) > 400000) return std::nullopt; // BundleTooHeavy
    return b;
}

// ------------------------------------------------------------------ encodings
static Bytes u32le(uint32_t v)
{
    Writer w;
    w.u32(v);
    return w.buf;
}
static const Bytes UNIT{};

static void enc_output(Writer& w, const Output& o) { bincode(w, o); }

static void enc_spent(Writer& w, const SpentOutput& s)
{
    bincode(w, s.output);
    w.u32(s.inpoint.kind);
    w.raw(s.inpoint.id);
    if (s.inpoint.kind == InPoint::Regular) w.u32(s.inpoint.vin);
}
static SpentOutput dec_spent(Reader& r)
{
    SpentOutput s;
    s.output = de_output(r);
    s.inpoint.kind = InPoint::Kind(r.u32());
    s.inpoint.id = r.array<32>();
    if (s.inpoint.kind == InPoint::Regular) s.inpoint.vin = r.u32();
    return s;
}

static void enc_utxo_map(Writer& w, const std::map<OutPoint, Output>& m)
{
    w.u64(m.size());
    for (auto& [op, o] : m) {
        bincode(w, op);
        bincode(w, o);
    }
}
static std::map<OutPoint, Output> dec_utxo_map(Reader& r)
{
    std::map<OutPoint, Output> m;
    uint64_t n = r.u64();
    for (uint64_t i = 0; i < n; i++) {
        OutPoint op = de_outpoint(r);
        m[op] = de_output(r);
    }
    return m;
}

void enc_bundle_info(Writer& w, const WithdrawalBundleInfo& i)
{
    w.u8(i.kind);
    if (i.kind == WithdrawalBundleInfo::Known) {
        enc_utxo_map(w, i.bundle.spend_utxos);
        w.u64(i.bundle.outputs.size());
        for (auto& o : i.bundle.outputs) {
            w.u64(o.value);
            w.bincode_bytes(o.script_pubkey);
        }
    } else if (i.kind == WithdrawalBundleInfo::UnknownConfirmed) {
        enc_utxo_map(w, i.spend_utxos);
    }
}
WithdrawalBundleInfo dec_bundle_info(Reader& r)
{
    WithdrawalBundleInfo i;
    i.kind = WithdrawalBundleInfo::Kind(r.u8());
    if (i.kind == WithdrawalBundleInfo::Known) {
        i.bundle.spend_utxos = dec_utxo_map(r);
        uint64_t n = r.u64();
        for (uint64_t k = 0; k < n; k++) {
            bt::btc::TxOut o;
            o.value = r.u64();
            o.script_pubkey = r.bincode_bytes();
            i.bundle.outputs.push_back(std::move(o));
        }
    } else if (i.kind == WithdrawalBundleInfo::UnknownConfirmed) {
        i.spend_utxos = dec_utxo_map(r);
    }
    return i;
}

template <class T, class F>
static void enc_rollback(Writer& w, const RollBack<T>& rb, F encv)
{
    w.u64(rb.v.size());
    for (auto& hs : rb.v) {
        encv(w, hs.value);
        w.u32(hs.height);
    }
}
template <class T, class F>
static RollBack<T> dec_rollback(Reader& r, F decv)
{
    RollBack<T> rb;
    uint64_t n = r.u64();
    for (uint64_t i = 0; i < n; i++) {
        T v = decv(r);
        uint32_t h = r.u32();
        rb.v.push_back({v, h});
    }
    if (rb.v.empty()) throw bt::DecodeError("empty RollBack");
    return rb;
}

static Bytes m6id_key(const Hash32& m)
{
    Writer w;
    w.bincode_bytes(m.span()); // SerdeBincode<M6id>: u64 length + 32 bytes
    return w.buf;
}

// ------------------------------------------------------------------ getters
std::optional<Hash32> State::tip(const Txn& t) const
{
    auto v = t.get(T_TIP, UNIT);
    if (!v) return std::nullopt;
    return Hash32::from_span(*v);
}

std::optional<uint32_t> State::height(const Txn& t) const
{
    auto v = t.get(T_HEIGHT, UNIT);
    if (!v) return std::nullopt;
    Reader r(*v);
    return r.u32();
}

std::optional<Output> State::utxo(const Txn& t, const OutPoint& op) const
{
    auto k = op.key();
    auto v = t.get(T_UTXOS, ByteSpan(k.data(), k.size()));
    if (!v) return std::nullopt;
    Reader r(*v);
    return de_output(r);
}

std::optional<SpentOutput> State::stxo(const Txn& t, const OutPoint& op) const
{
    auto k = op.key();
    auto v = t.get(T_STXOS, ByteSpan(k.data(), k.size()));
    if (!v) return std::nullopt;
    Reader r(*v);
    return dec_spent(r);
}

static OutPoint op_from_key(ByteSpan k)
{
    OutPoint o;
    o.kind = OutPoint::Kind(k[0]);
    std::memcpy(o.txid.data(), k.data() + 1, 32);
    o.vout = uint32_t(k[33]) | uint32_t(k[34]) << 8 | uint32_t(k[35]) << 16 | uint32_t(k[36]) << 24;
    return o;
}

std::vector<std::pair<OutPoint, Output>> State::utxos(const Txn& t) const
{
    std::vector<std::pair<OutPoint, Output>> r;
    t.scan(T_UTXOS, [&](ByteSpan k, ByteSpan v) {
        Reader rd(v);
        r.emplace_back(op_from_key(k), de_output(rd));
        return true;
    });
    return r;
}

std::vector<std::pair<OutPoint, SpentOutput>> State::stxos(const Txn& t) const
{
    std::vector<std::pair<OutPoint, SpentOutput>> r;
    t.scan(T_STXOS, [&](ByteSpan k, ByteSpan v) {
        Reader rd(v);
        r.emplace_back(op_from_key(k), dec_spent(rd));
        return true;
    });
    return r;
}

bt::utreexo::MemForest State::accumulator(const Txn& t) const
{
    auto v = t.get(T_ACCUMULATOR, UNIT);
    if (!v) return {};
    auto f = bt::utreexo::MemForest::deserialize(*v);
    if (!f) throw StateError("corrupt accumulator", true);
    return std::move(*f);
}

void State::put_accumulator(Txn& t, const bt::utreexo::MemForest& f) const { t.put(T_ACCUMULATOR, UNIT, f.serialize()); }

std::optional<std::string> tx_self_conflict(const Transaction& tx)
{
    std::set<std::array<uint8_t, 37>> ins;
    for (auto& [op, _] : tx.inputs)
        if (!ins.insert(op.key()).second) return std::string("UtxoDoubleSpent");
    if (tx.orchard_bundle) {
        std::set<Hash32> nfs;
        for (auto& a : tx.orchard_bundle->actions)
            if (!nfs.insert(a.nf).second) return std::string("NullifierDoubleSpent");
    }
    return std::nullopt;
}

// ------------------------------------------------------------------ orchard (orchard.rs)
static Bytes opt_hash(const std::optional<Hash32>& h)
{
    Writer w; // SerdeBincode<Option<BlockHash>>
    if (h) {
        w.u8(1);
        w.raw(*h);
    } else {
        w.u8(0);
    }
    return w.buf;
}

Bytes State::orchard_frontier(const Txn& t) const
{
    auto v = t.get(T_ORCHARD_FRONTIER, UNIT);
    if (!v) return Bytes{0}; // Frontier::empty() (orchard.rs:47-49)
    return *v;
}

Hash32 State::orchard_frontier_root(const Txn& t) const
{
    Bytes f = orchard_frontier(t);
    Hash32 r;
    if (zs_frontier_root(f.data(), f.size(), r.data()) != 0) throw StateError("corrupt orchard frontier", true);
    return r;
}

bool State::orchard_historical_root(const Txn& t, const Hash32& anchor) const
{
    if (anchor == orchard_empty_root()) return true; // seeded under None, never deleted (orchard.rs:50-55)
    return t.get(T_ORCHARD_HISTORICAL_ROOTS, anchor.span()).has_value();
}

std::vector<std::pair<Hash32, std::optional<Hash32>>> State::orchard_historical_roots(const Txn& t) const
{
    std::vector<std::pair<Hash32, std::optional<Hash32>>> r;
    r.emplace_back(orchard_empty_root(), std::nullopt);
    t.scan(T_ORCHARD_HISTORICAL_ROOTS, [&](ByteSpan k, ByteSpan v) {
        Reader rd(v);
        std::optional<Hash32> b;
        if (rd.u8() == 1) b = rd.array<32>();
        r.emplace_back(Hash32::from_span(k), b);
        return true;
    });
    std::sort(r.begin(), r.end(), [](auto& a, auto& b) { return a.first < b.first; });
    return r;
}

bool State::orchard_nullifier(const Txn& t, const Hash32& nf) const { return t.get(T_ORCHARD_NULLIFIERS, nf.span()).has_value(); }

std::vector<Hash32> State::orchard_nullifiers(const Txn& t) const
{
    std::vector<Hash32> r;
    t.scan(T_ORCHARD_NULLIFIERS, [&](ByteSpan k, ByteSpan) {
        r.push_back(Hash32::from_span(k));
        return true;
    });
    return r;
}

// lib/state/mod.rs:432-454
void State::validate_orchard_anchor(const Txn& t, const OrchardBundle& b) const
{
    if (b.anchor == orchard_empty_root() && b.spends_enabled()) throw StateError("ValidateOrchardAnchor: EmptyAnchor");
    if (!orchard_historical_root(t, b.anchor)) throw StateError("ValidateOrchardAnchor: InvalidAnchor " + bt::hex_encode(b.anchor));
}

std::optional<Hash32> State::pending_bundle_m6id(const Txn& t) const
{
    auto v = t.get(T_PENDING_BUNDLE, UNIT);
    if (!v) return std::nullopt;
    return Hash32::from_span(*v);
}

static BundleStatus dec_status(Reader& r) { return BundleStatus(r.u8()); }
static void enc_status(Writer& w, BundleStatus s) { w.u8(uint8_t(s)); }

std::optional<std::pair<WithdrawalBundleInfo, RollBack<BundleStatus>>> State::bundle(const Txn& t, const Hash32& m6id) const
{
    auto v = t.get(T_BUNDLES, m6id_key(m6id));
    if (!v) return std::nullopt;
    Reader r(*v);
    auto info = dec_bundle_info(r);
    auto st = dec_rollback<BundleStatus>(r, dec_status);
    return std::make_pair(std::move(info), std::move(st));
}

std::vector<std::pair<Hash32, std::pair<WithdrawalBundleInfo, RollBack<BundleStatus>>>> State::bundles(const Txn& t) const
{
    std::vector<std::pair<Hash32, std::pair<WithdrawalBundleInfo, RollBack<BundleStatus>>>> res;
    t.scan(T_BUNDLES, [&](ByteSpan k, ByteSpan v) {
        Reader r(v);
        auto info = dec_bundle_info(r);
        auto st = dec_rollback<BundleStatus>(r, dec_status);
        res.emplace_back(Hash32::from_span(k.subspan(8)), std::make_pair(std::move(info), std::move(st)));
        return true;
    });
    return res;
}

void State::put_bundle(Txn& t, const Hash32& m6id, const WithdrawalBundleInfo& info, const RollBack<BundleStatus>& st) const
{
    Writer w;
    enc_bundle_info(w, info);
    enc_rollback(w, st, enc_status);
    t.put(T_BUNDLES, m6id_key(m6id), w.buf);
}

std::optional<RollBack<Hash32>> State::latest_failed_rollback(const Txn& t) const
{
    auto v = t.get(T_LATEST_FAILED, UNIT);
    if (!v) return std::nullopt;
    Reader r(*v);
    return dec_rollback<Hash32>(r, [](Reader& rd) { return rd.array<32>(); });
}

static void put_latest_failed(Txn& t, const RollBack<Hash32>& rb)
{
    Writer w;
    enc_rollback(w, rb, [](Writer& ww, const Hash32& h) { ww.raw(h); });
    t.put(State::T_LATEST_FAILED, UNIT, w.buf);
}

// mod.rs:220-249
std::optional<std::pair<uint32_t, Hash32>> State::latest_failed_bundle(const Txn& t) const
{
    auto rb = latest_failed_rollback(t);
    if (!rb) return std::nullopt;
    Hash32 m6id = rb->latest().value;
    auto b = bundle(t, m6id);
    if (!b) throw StateError("Inconsistent DBs: latest failed m6id missing", true);
    for (auto it = b->second.v.rbegin(); it != b->second.v.rend(); ++it)
        if (it->value == BundleStatus::Failed) return std::make_pair(it->height, m6id);
    throw StateError("missing failure status", true);
}

std::optional<std::pair<WithdrawalBundle, uint32_t>> State::pending_bundle(const Txn& t) const
{
    auto m = pending_bundle_m6id(t);
    if (!m) return std::nullopt;
    auto b = bundle(t, *m);
    if (!b) throw StateError("pending bundle missing from withdrawal_bundles");
    if (b->first.kind != WithdrawalBundleInfo::Known) throw StateError("PendingWithdrawalBundleUnknown");
    return std::make_pair(b->first.bundle, b->second.latest().height);
}

static std::vector<std::pair<uint32_t, std::pair<Hash32, uint32_t>>> seq_table(const Txn& t, uint8_t table)
{
    std::vector<std::pair<uint32_t, std::pair<Hash32, uint32_t>>> r;
    t.scan(table, [&](ByteSpan k, ByteSpan v) {
        Reader kr(k), vr(v);
        uint32_t seq = kr.u32();
        Bytes hb = vr.bincode_bytes();
        uint32_t h = vr.u32();
        r.emplace_back(seq, std::make_pair(Hash32::from_span(hb), h));
        return true;
    });
    return r;
}
std::vector<std::pair<uint32_t, std::pair<Hash32, uint32_t>>> State::deposit_blocks(const Txn& t) const { return seq_table(t, T_DEPOSIT_BLOCKS); }
std::vector<std::pair<uint32_t, std::pair<Hash32, uint32_t>>> State::bundle_event_blocks(const Txn& t) const { return seq_table(t, T_BUNDLE_EVENT_BLOCKS); }

static Bytes enc_block_ref(const Hash32& h, uint32_t height)
{
    Writer w;
    w.bincode_bytes(h.span());
    w.u32(height);
    return w.buf;
}
static std::optional<std::pair<uint32_t, std::pair<Hash32, uint32_t>>> seq_last(const Txn& t, uint8_t table)
{
    auto l = t.last(table); // memcmp-largest key, exactly as LMDB's last()
    if (!l) return std::nullopt;
    Reader kr(l->first), vr(l->second);
    uint32_t seq = kr.u32();
    Bytes hb = vr.bincode_bytes();
    uint32_t h = vr.u32();
    return std::make_pair(seq, std::make_pair(Hash32::from_span(hb), h));
}

// mod.rs:503-547
uint64_t State::sidechain_wealth(const Txn& t) const
{
    uint64_t dep_utxo = 0, dep_stxo = 0, wd_stxo = 0;
    for (auto& [op, o] : utxos(t))
        if (op.kind == OutPoint::Deposit) {
            if (dep_utxo + o.get_value() < dep_utxo) throw StateError("AmountOverflow");
            dep_utxo += o.get_value();
        }
    for (auto& [op, s] : stxos(t)) {
        if (op.kind == OutPoint::Deposit) {
            if (dep_stxo + s.output.get_value() < dep_stxo) throw StateError("AmountOverflow");
            dep_stxo += s.output.get_value();
        }
        if (s.inpoint.kind == InPoint::Withdrawal) {
            if (wd_stxo + s.output.get_value() < wd_stxo) throw StateError("AmountOverflow");
            wd_stxo += s.output.get_value();
        }
    }
    uint64_t total = dep_utxo + dep_stxo;
    if (total < dep_utxo || total < wd_stxo) throw StateError("AmountOverflow");
    return total - wd_stxo;
}

// ------------------------------------------------------------------ transactions (mod.rs:365-443)
uint64_t State::validate_filled(const FilledTransaction& ft)
{
    // validate_utxo_hashes
    for (size_t i = 0; i < ft.tx->inputs.size(); i++) {
        auto& [op, h] = ft.tx->inputs[i];
        if (pointed_output_hash(op, ft.spent_utxos[i]) != h) throw StateError("UtxoHashMismatch");
    }
    uint64_t in = 0, out = 0;
    for (size_t i = 0; i < ft.tx->inputs.size(); i++) {
        auto& u = ft.spent_utxos[i];
        if (u.content.kind == Content::Withdrawal) throw StateError("SpendWithdrawalOutput");
        uint64_t v = u.get_value();
        if (in + v < in) throw StateError("AmountOverflow");
        in += v;
    }
    for (auto& o : ft.tx->outputs) {
        uint64_t v = o.get_value();
        if (out + v < out) throw StateError("AmountOverflow");
        out += v;
    }
    if (ft.tx->orchard_bundle) { // :410-423
        int64_t vb = ft.tx->orchard_bundle->value_balance;
        uint64_t mag = vb < 0 ? uint64_t(0) - uint64_t(vb) : uint64_t(vb);
        uint64_t& side = vb > 0 ? in : out; // is_positive() ? value_in : value_out
        if (side + mag < side) throw StateError("AmountOverflow");
        side += mag;
    }
    if (out > in) throw StateError("NotEnoughValueIn");
    return in - out;
}

uint64_t State::validate_transaction(const Txn& t, const AuthorizedTransaction& tx) const
{
    FilledTransaction ft{&tx.transaction, {}};
    for (auto& [op, _] : tx.transaction.inputs) {
        auto u = utxo(t, op);
        if (!u) throw StateError("NoUtxo " + op.to_string());
        ft.spent_utxos.push_back(*u);
    }
    for (size_t i = 0; i < tx.authorizations.size() && i < ft.spent_utxos.size(); i++)
        if (address_from_vk(tx.authorizations[i].verifying_key) != ft.spent_utxos[i].address) throw StateError("WrongVerifyingKeyForAddress");
    if (tx.transaction.orchard_bundle) validate_orchard_anchor(t, *tx.transaction.orchard_bundle); // :477-483
    if (!verify_authorized_transaction(tx)) throw StateError("Authorization");
    return validate_filled(ft);
}

// ------------------------------------------------------------------ blocks (block.rs:17-196)
PrevalidatedBlock State::prevalidate(const Txn& t, const Header& h, const Body& body, CheckOpts opts) const
{
    auto tip_hash = tip(t);
    if (h.prev_side_hash != tip_hash) throw StateError("InvalidHeader: PrevSideHash");
    auto ht = height(t);
    uint32_t next_height = ht ? *ht + 1 : 0;
    if (body.authorizations.size() > body_sigops_limit(next_height)) throw StateError("TooManySigops");
    if (borsh_bytes(body).size() > body_size_limit(next_height)) throw StateError("BodyTooLarge");

    auto acc = accumulator(t);
    auto roots_before = acc.get_roots();

    std::vector<std::array<uint8_t, 37>> all_input_keys;
    std::vector<std::pair<bool, NodeHash>> diff_txs;
    PrevalidatedBlock pre;
    pre.next_height = next_height;
    uint64_t total_fees = 0;
    Hash32 mr = compute_merkle_root(body.coinbase, body.transactions); // block.rs:192-199 (infallible)
    if (mr != h.merkle_root) throw StateError("InvalidBody: merkle root");
    for (auto& tx : body.transactions) {
        Hash32 txid = tx.txid();
        if (tx.orchard_bundle) validate_orchard_anchor(t, *tx.orchard_bundle); // block.rs:244-255
        FilledTransaction ft{&tx, {}};
        std::vector<NodeHash> spent_hashes;
        for (auto& [op, uh] : tx.inputs) {
            auto u = utxo(t, op);
            if (!u) throw StateError("NoUtxo " + op.to_string());
            all_input_keys.push_back(op.key());
            ft.spent_utxos.push_back(*u);
            spent_hashes.push_back(nh(uh));
            diff_txs.emplace_back(false, nh(uh));
        }
        for (uint32_t vout = 0; vout < tx.outputs.size(); vout++) {
            OutPoint op{OutPoint::Regular, txid, vout};
            diff_txs.emplace_back(true, nh(pointed_output_hash(op, tx.outputs[vout])));
        }
        auto ok = acc.verify(tx.proof, spent_hashes);
        if (!ok) throw StateError("Utreexo error");
        if (!*ok) throw StateError("UtreexoProofFailed");
        uint64_t fee = validate_filled(ft);
        if (total_fees + fee < total_fees) throw StateError("AmountOverflow");
        total_fees += fee;
        pre.filled.push_back(std::move(ft));
    }
    std::sort(all_input_keys.begin(), all_input_keys.end());
    for (size_t i = 1; i < all_input_keys.size(); i++)
        if (all_input_keys[i] == all_input_keys[i - 1]) throw StateError("UtxoDoubleSpent");
    Hash32 cb_txid = h.coinbase_txid();
    uint64_t cb_value = 0;
    for (uint32_t vout = 0; vout < body.coinbase.outputs.size(); vout++) {
        auto& o = body.coinbase.outputs[vout];
        if (cb_value + o.get_value() < cb_value) throw StateError("AmountOverflow");
        cb_value += o.get_value();
        pre.diff.insert(nh(pointed_output_hash(OutPoint{OutPoint::Coinbase, cb_txid, vout}, o)));
    }
    for (auto& [ins, x] : diff_txs) {
        if (ins) pre.diff.insert(x);
        else pre.diff.remove(x);
    }
    if (cb_value > total_fees) throw StateError("NotEnoughFees");
    size_t k = 0;
    if (opts.authorizations)
    for (auto& ft : pre.filled)
        for (auto& u : ft.spent_utxos) {
            if (k >= body.authorizations.size()) break; // zip stops at the shorter
            if (address_from_vk(body.authorizations[k].verifying_key) != u.address) throw StateError("WrongPubKeyForAddress");
            k++;
        }
    if (opts.authorizations && !verify_authorizations(body)) throw StateError("Authorization");
    std::vector<NodeHash> ins, dels;
    pre.diff.split(ins, dels);
    if (auto e = acc.modify(ins, dels)) throw StateError("Utreexo: " + *e);
    pre.roots_after = acc.get_roots();
    if (opts.roots && pre.roots_after != h.roots) throw StateError("UtreexoRootsMismatch");
    pre.merkle_root = mr;
    pre.total_fees = total_fees;
    pre.coinbase_value = cb_value;
    return pre;
}

void State::apply_diff(Txn& t, const AccumulatorDiff& d) const
{
    auto acc = accumulator(t);
    std::vector<NodeHash> ins, dels;
    d.split(ins, dels);
    if (auto e = acc.modify(ins, dels)) throw StateError("Utreexo: " + *e);
    put_accumulator(t, acc);
}

void State::connect_prevalidated(Txn& t, const Header& h, const Body& body, const PrevalidatedBlock& pre) const
{
    if (tip(t) != h.prev_side_hash) throw StateError("InvalidHeader: PrevSideHash");
    if (pre.merkle_root != h.merkle_root) throw StateError("InvalidBody");
    const Bytes frontier_before = orchard_frontier(t);
    Bytes frontier = frontier_before;
    Hash32 cb_txid = h.coinbase_txid();
    for (uint32_t vout = 0; vout < body.coinbase.outputs.size(); vout++) {
        auto k = OutPoint{OutPoint::Coinbase, cb_txid, vout}.key();
        Writer w;
        enc_output(w, body.coinbase.outputs[vout]);
        t.put(T_UTXOS, ByteSpan(k.data(), k.size()), w.buf);
    }
    for (auto& ft : pre.filled) {
        Hash32 txid = ft.tx->txid();
        for (uint32_t vin = 0; vin < ft.tx->inputs.size(); vin++) {
            auto& op = ft.tx->inputs[vin].first;
            auto u = utxo(t, op);
            if (!u) throw StateError("NoUtxo " + op.to_string());
            auto k = op.key();
            t.del(T_UTXOS, ByteSpan(k.data(), k.size()));
            Writer w;
            enc_spent(w, SpentOutput{*u, InPoint{InPoint::Regular, txid, vin}});
            t.put(T_STXOS, ByteSpan(k.data(), k.size()), w.buf);
        }
        for (uint32_t vout = 0; vout < ft.tx->outputs.size(); vout++) {
            auto k = OutPoint{OutPoint::Regular, txid, vout}.key();
            Writer w;
            enc_output(w, ft.tx->outputs[vout]);
            t.put(T_UTXOS, ByteSpan(k.data(), k.size()), w.buf);
        }
        // connect_orchard (block.rs:447-475): append every cmx, then each nullifier must be new
        if (ft.tx->orchard_bundle) {
            auto& b = *ft.tx->orchard_bundle;
            Bytes cmxs;
            for (auto& a : b.actions) append(cmxs, a.cmx.span());
            uint8_t* out = nullptr;
            size_t out_len = 0;
            Hash32 root;
            int rc = zs_frontier_append(frontier.data(), frontier.size(), cmxs.data(), b.actions.size(), &out, &out_len, root.data());
            if (rc == 1) throw StateError("ConnectTransaction: Orchard: AppendCommitment");
            if (rc != 0) throw StateError("orchard frontier", true);
            frontier.assign(out, out + out_len);
            zs_buffer_free(out, out_len);
            for (auto& a : b.actions) {
                if (orchard_nullifier(t, a.nf)) throw StateError("ConnectTransaction: Orchard: NullifierDoubleSpent " + bt::hex_encode(a.nf));
                t.put(T_ORCHARD_NULLIFIERS, a.nf.span(), UNIT);
            }
        }
    }
    Hash32 bh = h.hash();
    t.put(T_TIP, UNIT, bh.span());
    t.put(T_HEIGHT, UNIT, u32le(pre.next_height));
    apply_diff(t, pre.diff);
    // block.rs:405-416: put the frontier; store its root as a historical root if it is new
    t.put(T_ORCHARD_FRONTIER, UNIT, frontier);
    Hash32 root;
    if (zs_frontier_root(frontier.data(), frontier.size(), root.data()) != 0) throw StateError("orchard frontier", true);
    if (!orchard_historical_root(t, root)) {
        t.put(T_ORCHARD_BLOCK_ROOT, opt_hash(bh), root.span());
        t.put(T_ORCHARD_HISTORICAL_ROOTS, root.span(), opt_hash(bh));
        t.put(T_ORCHARD_FRONTIER_UNDO, bh.span(), frontier_before);
    }
}

// block.rs:516-640
void State::disconnect_tip(Txn& t, const Header& h, const Body& body) const
{
    auto tip_hash = tip(t);
    if (!tip_hash) throw StateError("NoTip");
    if (*tip_hash != h.hash()) throw StateError("InvalidHeader: BlockHash");
    AccumulatorDiff diff;
    for (auto txit = body.transactions.rbegin(); txit != body.transactions.rend(); ++txit) {
        auto& tx = *txit;
        if (tx.orchard_bundle) // disconnect_orchard (block.rs:597-610)
            for (auto& a : tx.orchard_bundle->actions) t.del(T_ORCHARD_NULLIFIERS, a.nf.span());
        Hash32 txid = tx.txid();
        for (int64_t vout = int64_t(tx.outputs.size()) - 1; vout >= 0; vout--) {
            OutPoint op{OutPoint::Regular, txid, uint32_t(vout)};
            diff.remove(nh(pointed_output_hash(op, tx.outputs[size_t(vout)])));
            auto k = op.key();
            if (!t.del(T_UTXOS, ByteSpan(k.data(), k.size()))) throw StateError("NoUtxo " + op.to_string());
        }
        for (auto in = tx.inputs.rbegin(); in != tx.inputs.rend(); ++in) {
            auto k = in->first.key();
            auto s = stxo(t, in->first);
            if (!s) throw StateError("NoStxo " + in->first.to_string());
            diff.insert(nh(in->second));
            t.del(T_STXOS, ByteSpan(k.data(), k.size()));
            Writer w;
            enc_output(w, s->output);
            t.put(T_UTXOS, ByteSpan(k.data(), k.size()), w.buf);
        }
    }
    Hash32 cb_txid = h.coinbase_txid();
    for (int64_t vout = int64_t(body.coinbase.outputs.size()) - 1; vout >= 0; vout--) {
        OutPoint op{OutPoint::Coinbase, cb_txid, uint32_t(vout)};
        diff.remove(nh(pointed_output_hash(op, body.coinbase.outputs[size_t(vout)])));
        auto k = op.key();
        if (!t.del(T_UTXOS, ByteSpan(k.data(), k.size()))) throw StateError("NoUtxo " + op.to_string());
    }
    // tip/height revert (block.rs:611-630)
    auto ht = height(t);
    if (!ht) throw StateError("Height should not be None", true);
    if (!h.prev_side_hash && *ht == 0) {
        t.del(T_TIP, UNIT);
        t.del(T_HEIGHT, UNIT);
    } else if (!h.prev_side_hash || *ht == 0) {
        throw StateError("NoTip");
    } else {
        t.put(T_TIP, UNIT, h.prev_side_hash->span());
        t.put(T_HEIGHT, UNIT, u32le(*ht - 1));
    }
    // Their accumulator update here is overwritten by the archived snapshot of the new tip
    // (net_task.rs:194-213); the caller restores it, we still apply it for parity.
    apply_diff(t, diff);
    // block.rs:739-746: the frontier from before this block when it changed it, then the
    // block's historical root (if it added one).
    Hash32 bh = *tip_hash;
    if (auto undo = t.get(T_ORCHARD_FRONTIER_UNDO, bh.span())) {
        t.put(T_ORCHARD_FRONTIER, UNIT, *undo);
        t.del(T_ORCHARD_FRONTIER_UNDO, bh.span());
    }
    if (auto root = t.get(T_ORCHARD_BLOCK_ROOT, opt_hash(bh))) {
        t.del(T_ORCHARD_BLOCK_ROOT, opt_hash(bh));
        t.del(T_ORCHARD_HISTORICAL_ROOTS, *root);
    }
}

// ------------------------------------------------------------------ two-way peg
// proto.rs:446-506
Output State::deposit_output(const bt::mainchain::Deposit& d)
{
    Output o;
    o.content.kind = Content::Value;
    o.content.value = d.value_sats;
    std::string s(d.address.begin(), d.address.end());
    o.address = Address::ALL_ZEROS;
    if (Reader::utf8_valid(s))
        if (auto a = Address::from_base58(s)) o.address = *a;
    return o;
}

// two_way_peg_data.rs:23-114
std::optional<WithdrawalBundle> State::collect_withdrawal_bundle(const Txn& t, uint32_t block_height) const
{
    struct Agg {
        bt::btc::Address addr;
        uint64_t value = 0, main_fee = 0;
        std::map<OutPoint, Output> utxos;
    };
    std::vector<Agg> aggs; // HashMap keyed by Address (Eq includes network/hrp)
    for (auto& [op, o] : utxos(t)) {
        if (o.content.kind != Content::Withdrawal) continue;
        auto it = std::find_if(aggs.begin(), aggs.end(), [&](const Agg& a) { return a.addr == o.content.main_address; });
        if (it == aggs.end()) {
            aggs.push_back(Agg{o.content.main_address, 0, 0, {}});
            it = std::prev(aggs.end());
        }
        if (it->value + o.content.value < it->value) throw StateError("AmountOverflow");
        it->value += o.content.value;
        if (it->main_fee + o.content.main_fee < it->main_fee) throw StateError("AmountOverflow");
        it->main_fee += o.content.main_fee;
        it->utxos[op] = o;
    }
    if (aggs.empty()) return std::nullopt;
    // sort by Reverse((main_fee, value, main_address))
    std::sort(aggs.begin(), aggs.end(), [](const Agg& a, const Agg& b) {
        if (a.main_fee != b.main_fee) return a.main_fee > b.main_fee;
        if (a.value != b.value) return a.value > b.value;
        return b.addr < a.addr;
    });
    uint64_t fee = 0;
    std::map<OutPoint, Output> spend;
    std::vector<bt::btc::TxOut> outs;
    uint32_t txouts_size = 0;
    for (auto& a : aggs) {
        Bytes spk = a.addr.script_pubkey();
        uint64_t n_outputs = outs.size() + 1;
        if (n_outputs > UINT32_MAX) break;
        if (spk.size() > UINT32_MAX) continue;
        auto ts = txout_size(uint32_t(spk.size()));
        if (!ts) continue;
        uint64_t sum = uint64_t(txouts_size) + *ts;
        if (sum > UINT32_MAX) break;
        txouts_size = uint32_t(sum);
        if (!predict_weight_ok(uint32_t(n_outputs), txouts_size)) break; // `break`, not skip (bug §5)
        for (auto& [op, o] : a.utxos) spend[op] = o;
        outs.push_back({a.value, spk});
        if (fee + a.main_fee < fee) throw StateError("Amount addition overflow", true); // `+=` panics
        fee += a.main_fee;
    }
    auto b = make_withdrawal_bundle(block_height, fee, std::move(spend), std::move(outs));
    if (!b) throw StateError("BundleTooHeavy");
    return b;
}

// two_way_peg_data.rs:116-280
void State::connect_bundle_submitted(Txn& t, uint32_t block_height, AccumulatorDiff& diff, const Hash32& event_block, const Hash32& m6id) const
{
    auto pending = pending_bundle_m6id(t);
    if (pending && *pending == m6id) {
        auto b = bundle(t, m6id);
        if (!b) throw StateError("PendingWithdrawalBundleUnknown");
        if (b->first.kind != WithdrawalBundleInfo::Known) throw StateError("PendingWithdrawalBundleUnknown");
        for (auto& [op, o] : b->first.bundle.spend_utxos) {
            diff.remove(nh(pointed_output_hash(op, o)));
            auto k = op.key();
            if (!t.del(T_UTXOS, ByteSpan(k.data(), k.size()))) throw StateError("NoUtxo " + op.to_string());
            Writer w;
            enc_spent(w, SpentOutput{o, InPoint{InPoint::Withdrawal, m6id, 0}});
            t.put(T_STXOS, ByteSpan(k.data(), k.size()), w.buf);
        }
        if (b->second.latest().value != BundleStatus::Pending) throw StateError("assert Pending", true);
        if (!b->second.push(BundleStatus::Submitted, block_height)) throw StateError("push submitted", true);
        put_bundle(t, m6id, b->first, b->second);
        t.del(T_PENDING_BUNDLE, UNIT);
        return;
    }
    if (auto b = bundle(t, m6id)) {
        auto st = b->second.latest().value;
        auto kind = b->first.kind;
        if (st == BundleStatus::Confirmed) throw StateError("ConfirmedResubmitted");
        if (st == BundleStatus::Submitted || st == BundleStatus::SubmittedUnexpected) throw StateError("Resubmitted");
        if (st == BundleStatus::Dropped) {
            if (kind != WithdrawalBundleInfo::Known) throw StateError("UnknownDropped");
            // warn: dropped bundle submitted
        } else if (st == BundleStatus::Pending) {
            if (kind == WithdrawalBundleInfo::Known) throw StateError("DroppedPending");
            throw StateError("UnknownPending");
        } else if (st == BundleStatus::Failed) {
            if (kind == WithdrawalBundleInfo::UnknownConfirmed) throw StateError("UnknownConfirmedFailed");
            // warn: failed bundle resubmitted
        }
        if (!b->second.push(BundleStatus::SubmittedUnexpected, block_height)) throw StateError("push submitted unexpected", true);
        put_bundle(t, m6id, b->first, b->second);
        return;
    }
    // Unknown withdrawal bundle submitted
    WithdrawalBundleInfo info;
    info.kind = WithdrawalBundleInfo::Unknown;
    put_bundle(t, m6id, info, RollBack<BundleStatus>::make(BundleStatus::Submitted, block_height));
}

// two_way_peg_data.rs:282-402
void State::connect_bundle_confirmed(Txn& t, uint32_t block_height, AccumulatorDiff& diff, const Hash32& event_block, const Hash32& m6id) const
{
    auto b = bundle(t, m6id);
    if (!b) throw StateError("UnknownWithdrawalBundle");
    auto& [info, st] = *b;
    if (st.latest().value == BundleStatus::Confirmed) return; // already applied
    if (st.latest().value != BundleStatus::Submitted && st.latest().value != BundleStatus::SubmittedUnexpected)
        throw StateError("assert Submitted", true);
    if (info.kind == WithdrawalBundleInfo::UnknownConfirmed) throw StateError("UnknownWithdrawalBundleReconfirmed");
    if (info.kind == WithdrawalBundleInfo::Unknown) {
        if (block_height != 0) throw StateError("UnknownWithdrawalBundleConfirmed"); // halts the chain (bug §5.11)
        std::map<OutPoint, Output> all;
        for (auto& [op, o] : utxos(t)) all[op] = o;
        for (auto& [op, o] : all) {
            auto k = op.key();
            Writer w;
            enc_spent(w, SpentOutput{o, InPoint{InPoint::Withdrawal, m6id, 0}});
            t.put(T_STXOS, ByteSpan(k.data(), k.size()), w.buf);
            diff.remove(nh(pointed_output_hash(op, o)));
        }
        t.clear(T_UTXOS);
        info.kind = WithdrawalBundleInfo::UnknownConfirmed;
        info.spend_utxos = std::move(all);
    } else if (info.kind == WithdrawalBundleInfo::Known) {
        if (st.latest().value == BundleStatus::SubmittedUnexpected) {
            for (auto& [op, o] : info.bundle.spend_utxos) {
                auto k = op.key();
                if (!t.del(T_UTXOS, ByteSpan(k.data(), k.size()))) throw StateError("UnexpectedWithdrawalBundleInsolvency");
                Writer w;
                enc_spent(w, SpentOutput{o, InPoint{InPoint::Withdrawal, m6id, 0}});
                t.put(T_STXOS, ByteSpan(k.data(), k.size()), w.buf);
                diff.remove(nh(pointed_output_hash(op, o)));
            }
        }
    }
    if (!st.push(BundleStatus::Confirmed, block_height)) throw StateError("push confirmed", true);
    put_bundle(t, m6id, info, st);
}

// two_way_peg_data.rs:404-478
void State::connect_bundle_failed(Txn& t, uint32_t block_height, AccumulatorDiff& diff, const Hash32& m6id) const
{
    auto b = bundle(t, m6id);
    if (!b) throw StateError("UnknownWithdrawalBundle");
    auto& [info, st] = *b;
    if (st.latest().value == BundleStatus::Failed) return; // already applied
    if (st.latest().value != BundleStatus::Submitted && st.latest().value != BundleStatus::SubmittedUnexpected)
        throw StateError("assert Submitted", true);
    if (info.kind == WithdrawalBundleInfo::Known && st.latest().value != BundleStatus::SubmittedUnexpected) {
        for (auto& [op, o] : info.bundle.spend_utxos) {
            auto k = op.key();
            t.del(T_STXOS, ByteSpan(k.data(), k.size()));
            Writer w;
            enc_output(w, o);
            t.put(T_UTXOS, ByteSpan(k.data(), k.size()), w.buf);
            diff.insert(nh(pointed_output_hash(op, o)));
        }
        auto lf = latest_failed_rollback(t);
        RollBack<Hash32> nl;
        if (lf) {
            nl = *lf;
            if (!nl.push(m6id, block_height)) throw StateError("push latest failed", true);
        } else {
            nl = RollBack<Hash32>::make(m6id, block_height);
        }
        put_latest_failed(t, nl);
    }
    if (!st.push(BundleStatus::Failed, block_height)) throw StateError("push failed", true);
    put_bundle(t, m6id, info, st);
}

// two_way_peg_data.rs:560-667
void State::connect_2wpd(Txn& t, const TwoWayPegData& d) const
{
    auto ht = height(t);
    if (!ht) throw StateError("NoTip");
    uint32_t block_height = *ht;
    AccumulatorDiff diff;
    std::optional<Hash32> latest_deposit_block, latest_bundle_event_block;
    for (auto& [event_block, bi] : d.block_info) {
        for (auto& ev : bi.events) {
            if (auto dep = std::get_if<bt::mainchain::Deposit>(&ev)) {
                OutPoint op{OutPoint::Deposit, dep->txid, dep->vout};
                Output o = deposit_output(*dep);
                auto k = op.key();
                Writer w;
                enc_output(w, o);
                t.put(T_UTXOS, ByteSpan(k.data(), k.size()), w.buf);
                diff.insert(nh(pointed_output_hash(op, o)));
                latest_deposit_block = event_block;
            } else {
                auto& we = std::get<bt::mainchain::WithdrawalBundleEvent>(ev);
                switch (we.status) {
                case bt::mainchain::BundleStatus::Submitted: connect_bundle_submitted(t, block_height, diff, event_block, we.m6id); break;
                case bt::mainchain::BundleStatus::Confirmed: connect_bundle_confirmed(t, block_height, diff, event_block, we.m6id); break;
                case bt::mainchain::BundleStatus::Failed: connect_bundle_failed(t, block_height, diff, we.m6id); break;
                }
                latest_bundle_event_block = event_block;
            }
        }
    }
    if (latest_deposit_block) {
        auto l = seq_last(t, T_DEPOSIT_BLOCKS);
        uint32_t seq = l ? l->first + 1 : 0;
        t.put(T_DEPOSIT_BLOCKS, u32le(seq), enc_block_ref(*latest_deposit_block, block_height));
    }
    if (latest_bundle_event_block) {
        auto l = seq_last(t, T_BUNDLE_EVENT_BLOCKS);
        uint32_t seq = l ? l->first + 1 : 0;
        t.put(T_BUNDLE_EVENT_BLOCKS, u32le(seq), enc_block_ref(*latest_bundle_event_block, block_height));
    }
    auto lf = latest_failed_bundle(t);
    uint32_t last_failure_height = lf ? lf->first : 0;
    if (uint32_t(block_height - last_failure_height) >= WITHDRAWAL_BUNDLE_FAILURE_GAP && !pending_bundle_m6id(t)) {
        if (auto bundle_ = collect_withdrawal_bundle(t, block_height)) {
            Hash32 m6id = bundle_->m6id();
            t.put(T_PENDING_BUNDLE, UNIT, m6id.span());
            RollBack<BundleStatus> st;
            if (auto existing = bundle(t, m6id)) {
                st = existing->second;
                if (!st.push(BundleStatus::Pending, block_height)) throw StateError("push pending", true);
            } else {
                st = RollBack<BundleStatus>::make(BundleStatus::Pending, block_height);
            }
            WithdrawalBundleInfo info;
            info.kind = WithdrawalBundleInfo::Known;
            info.bundle = std::move(*bundle_);
            put_bundle(t, m6id, info, st);
        }
    }
    apply_diff(t, diff);
}

// two_way_peg_data.rs:669-737
void State::disconnect_bundle_submitted(Txn& t, uint32_t block_height, AccumulatorDiff& diff, const Hash32& m6id) const
{
    auto b = bundle(t, m6id);
    if (!b) {
        auto p = pending_bundle_m6id(t);
        if (p && *p == m6id) return; // already applied
        throw StateError("UnknownWithdrawalBundle");
    }
    auto [rest, latest] = b->second.pop();
    if (latest.value != BundleStatus::Submitted && latest.value != BundleStatus::SubmittedUnexpected) throw StateError("assert", true);
    if (latest.height != block_height) throw StateError("assert height", true);
    if (b->first.kind == WithdrawalBundleInfo::Known) {
        if (rest && rest->latest().value == BundleStatus::Pending) {
            auto& su = b->first.bundle.spend_utxos;
            for (auto it = su.rbegin(); it != su.rend(); ++it) {
                auto k = it->first.key();
                if (!t.del(T_STXOS, ByteSpan(k.data(), k.size()))) throw StateError("NoStxo");
                Writer w;
                enc_output(w, it->second);
                t.put(T_UTXOS, ByteSpan(k.data(), k.size()), w.buf);
                diff.insert(nh(pointed_output_hash(it->first, it->second)));
            }
            t.put(T_PENDING_BUNDLE, UNIT, m6id.span());
        }
    }
    if (rest) put_bundle(t, m6id, b->first, *rest);
    else t.del(T_BUNDLES, m6id_key(m6id));
}

// two_way_peg_data.rs:739-822
void State::disconnect_bundle_confirmed(Txn& t, uint32_t block_height, AccumulatorDiff& diff, const Hash32& m6id) const
{
    auto b = bundle(t, m6id);
    if (!b) throw StateError("UnknownWithdrawalBundle");
    auto info = b->first;
    auto [prev, latest] = b->second.pop();
    if (latest.value == BundleStatus::Submitted || latest.value == BundleStatus::SubmittedUnexpected) return; // already applied
    if (latest.value != BundleStatus::Confirmed) throw StateError("assert Confirmed", true);
    if (latest.height != block_height) throw StateError("assert height", true);
    if (!prev) throw StateError("Pop confirmed bundle status should be valid", true);
    auto pst = prev->latest().value;
    if (pst != BundleStatus::Submitted && pst != BundleStatus::SubmittedUnexpected) throw StateError("assert", true);
    if (info.kind == WithdrawalBundleInfo::Known) {
        if (pst == BundleStatus::SubmittedUnexpected) {
            for (auto& [op, o] : info.bundle.spend_utxos) {
                auto k = op.key();
                Writer w;
                enc_output(w, o);
                t.put(T_UTXOS, ByteSpan(k.data(), k.size()), w.buf);
                if (!t.del(T_STXOS, ByteSpan(k.data(), k.size()))) throw StateError("NoStxo");
                diff.insert(nh(pointed_output_hash(op, o)));
            }
        }
    } else if (info.kind == WithdrawalBundleInfo::UnknownConfirmed) {
        for (auto& [op, o] : info.spend_utxos) {
            auto k = op.key();
            Writer w;
            enc_output(w, o);
            t.put(T_UTXOS, ByteSpan(k.data(), k.size()), w.buf);
            if (!t.del(T_STXOS, ByteSpan(k.data(), k.size()))) throw StateError("NoStxo");
            diff.insert(nh(pointed_output_hash(op, o)));
        }
        info.kind = WithdrawalBundleInfo::Unknown;
        info.spend_utxos.clear();
    }
    put_bundle(t, m6id, info, *prev);
}

// two_way_peg_data.rs:824-910
void State::disconnect_bundle_failed(Txn& t, uint32_t block_height, AccumulatorDiff& diff, const Hash32& m6id) const
{
    auto b = bundle(t, m6id);
    if (!b) throw StateError("UnknownWithdrawalBundle");
    auto [prev, latest] = b->second.pop();
    if (latest.value == BundleStatus::Submitted) return; // already applied
    if (latest.value != BundleStatus::Failed) throw StateError("assert Failed", true);
    if (latest.height != block_height) throw StateError("assert height", true);
    if (!prev) throw StateError("Pop failed bundle status should be valid", true);
    auto pst = prev->latest().value;
    if (pst != BundleStatus::Submitted && pst != BundleStatus::SubmittedUnexpected) throw StateError("assert", true);
    if (b->first.kind == WithdrawalBundleInfo::Known && pst != BundleStatus::SubmittedUnexpected) {
        auto& su = b->first.bundle.spend_utxos;
        for (auto it = su.rbegin(); it != su.rend(); ++it) {
            auto k = it->first.key();
            Writer w;
            enc_spent(w, SpentOutput{it->second, InPoint{InPoint::Withdrawal, m6id, 0}});
            t.put(T_STXOS, ByteSpan(k.data(), k.size()), w.buf);
            if (!t.del(T_UTXOS, ByteSpan(k.data(), k.size()))) throw StateError("NoUtxo");
            diff.remove(nh(pointed_output_hash(it->first, it->second)));
        }
        auto lf = latest_failed_rollback(t);
        if (!lf) throw StateError("latest failed withdrawal bundle should exist", true);
        auto [prest, platest] = lf->pop();
        if (platest.value != m6id || platest.height != block_height) throw StateError("assert latest failed", true);
        if (prest) put_latest_failed(t, *prest);
        else t.del(T_LATEST_FAILED, UNIT);
    }
    put_bundle(t, m6id, b->first, *prev);
}

// two_way_peg_data.rs:1010-1117
void State::disconnect_2wpd(Txn& t, const TwoWayPegData& d) const
{
    auto ht = height(t);
    if (!ht) throw StateError("Height should not be None", true);
    uint32_t block_height = *ht;
    AccumulatorDiff diff;
    std::optional<Hash32> latest_deposit_block, latest_bundle_event_block;
    for (auto bit = d.block_info.rbegin(); bit != d.block_info.rend(); ++bit) {
        auto& [event_block, bi] = *bit;
        for (auto eit = bi.events.rbegin(); eit != bi.events.rend(); ++eit) {
            if (auto dep = std::get_if<bt::mainchain::Deposit>(&*eit)) {
                OutPoint op{OutPoint::Deposit, dep->txid, dep->vout};
                Output o = deposit_output(*dep);
                auto k = op.key();
                if (!t.del(T_UTXOS, ByteSpan(k.data(), k.size()))) throw StateError("NoUtxo " + op.to_string());
                diff.remove(nh(pointed_output_hash(op, o)));
                if (!latest_deposit_block) latest_deposit_block = event_block;
            } else {
                auto& we = std::get<bt::mainchain::WithdrawalBundleEvent>(*eit);
                switch (we.status) {
                case bt::mainchain::BundleStatus::Submitted: disconnect_bundle_submitted(t, block_height, diff, we.m6id); break;
                case bt::mainchain::BundleStatus::Confirmed: disconnect_bundle_confirmed(t, block_height, diff, we.m6id); break;
                case bt::mainchain::BundleStatus::Failed: disconnect_bundle_failed(t, block_height, diff, we.m6id); break;
                }
                if (!latest_bundle_event_block) latest_bundle_event_block = event_block;
            }
        }
    }
    if (latest_bundle_event_block) {
        auto l = seq_last(t, T_BUNDLE_EVENT_BLOCKS);
        if (!l) throw StateError("NoWithdrawalBundleEventBlock");
        if (l->second.first != *latest_bundle_event_block || l->second.second != block_height) throw StateError("assert bundle event block", true);
        if (!t.del(T_BUNDLE_EVENT_BLOCKS, u32le(l->first))) throw StateError("NoWithdrawalBundleEventBlock");
    }
    auto lf = latest_failed_bundle(t);
    uint32_t last_failure_height = lf ? lf->first : 0;
    if (uint32_t(block_height - last_failure_height) >= WITHDRAWAL_BUNDLE_FAILURE_GAP) {
        if (auto p = pending_bundle_m6id(t)) {
            auto b = bundle(t, *p);
            if (!b) throw StateError("PendingWithdrawalBundleUnknown");
            if (b->second.latest().height == block_height) {
                t.del(T_PENDING_BUNDLE, UNIT);
                auto [rest, _] = b->second.pop();
                if (rest) put_bundle(t, *p, b->first, *rest);
                else t.del(T_BUNDLES, m6id_key(*p));
            }
        }
    }
    if (latest_deposit_block) {
        auto l = seq_last(t, T_DEPOSIT_BLOCKS);
        if (!l) throw StateError("NoDepositBlock");
        if (l->second.first != *latest_deposit_block || l->second.second != block_height) throw StateError("assert deposit block", true);
        if (!t.del(T_DEPOSIT_BLOCKS, u32le(l->first))) throw StateError("NoDepositBlock");
    }
    apply_diff(t, diff);
}

} // namespace zside
