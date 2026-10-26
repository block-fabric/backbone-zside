// Copyright (c) 2026 The Backbone developers
// Distributed under the MIT software license.
#include <zside/types.h>

#include <zside/orchard_ffi.h>

#include <bt/bech32.h>
#include <bt/crypto.h>

#include <cmath>
#include <deque>

namespace zside {

using bt::DecodeError;
using bt::utreexo::NodeHash;

const Address Address::ALL_ZEROS{};

std::string Address::to_base58() const { return bt::base58_encode(b.span()); }

std::optional<Address> Address::from_base58(std::string_view s)
{
    auto d = bt::base58_decode(s);
    if (!d || d->size() != 20) return std::nullopt;
    Address a;
    std::memcpy(a.b.data(), d->data(), 20);
    return a;
}

std::string Address::format_for_deposit() const
{
    std::string prefix = "s" + std::to_string(THIS_SIDECHAIN) + "_" + to_base58() + "_";
    auto d = bt::sha256(ByteSpan((const uint8_t*)prefix.data(), prefix.size()));
    return prefix + bt::hex_encode(ByteSpan(d.data(), 3));
}

std::string ShieldedAddress::to_string() const { return *bt::bech32::encode("t-shld", b.span(), bt::bech32::Variant::Bech32m); }

// address.rs:140-160 bech32m_decode: hrp "t-shld", 43 bytes, valid Orchard address, canonical.
std::optional<ShieldedAddress> ShieldedAddress::parse(std::string_view s)
{
    auto d = bt::bech32::decode_bech32m_canonical(s, "t-shld");
    if (!d || d->size() != 43) return std::nullopt;
    ShieldedAddress a;
    std::memcpy(a.b.data(), d->data(), 43);
    if (!zs_address_valid(a.b.data())) return std::nullopt;
    return a;
}

Address address_from_vk(const bt::frost::Point& vk)
{
    bt::Blake3 h;
    h.update(vk.span());
    Address a;
    h.finalize_xof(a.b.data(), 20);
    return a;
}

uint64_t Content::get_value() const
{
    if (kind == Value) return value;
    uint64_t s = value + main_fee;
    return s < value ? UINT64_MAX : s;
}

std::array<uint8_t, 37> OutPoint::key() const
{
    std::array<uint8_t, 37> k{};
    k[0] = kind;
    std::memcpy(k.data() + 1, txid.data(), 32);
    for (int i = 0; i < 4; i++) k[33 + i] = uint8_t(vout >> (8 * i));
    return k;
}

std::string OutPoint::to_string() const
{
    switch (kind) {
    case Regular: return "regular " + bt::hex_encode(txid) + " " + std::to_string(vout);
    case Coinbase: return "coinbase " + bt::hex_encode(txid) + " " + std::to_string(vout);
    case Deposit: return "deposit " + bt::hex_encode_rev(txid.span()) + " " + std::to_string(vout);
    }
    return {};
}

// ---------------------------------------------------------------- borsh
void borsh(Writer& w, const Address& a) { w.raw(a.b); }

void borsh(Writer& w, const Content& c)
{
    w.u8(c.kind);
    w.u64(c.value);
    if (c.kind == Content::Withdrawal) {
        w.u64(c.main_fee);
        w.borsh_bytes(c.main_address.script_pubkey()); // util.rs: bitcoin_address -> spk bytes
    }
}

void borsh(Writer& w, const Output& o)
{
    borsh(w, o.address);
    borsh(w, o.content);
}

void borsh(Writer& w, const OutPoint& o)
{
    w.u8(o.kind);
    w.raw(o.txid);
    w.u32(o.vout);
}

// types/orchard/mod.rs:1533-1585
void borsh_without_auth(Writer& w, const OrchardBundle& b)
{
    for (auto& a : b.actions) { // compact actions (CompactActionRepr :617-623)
        w.raw(a.nf);
        w.raw(a.cmx);
        w.raw(a.epk);
        w.raw(ByteSpan(a.enc.data(), 52));
    }
    for (auto& a : b.actions) { // memo items: enc[32..=543] and enc[544..=563] (:451-458)
        w.raw(ByteSpan(a.enc.data() + 32, 512));
        w.raw(ByteSpan(a.enc.data() + 544, 20));
    }
    for (auto& a : b.actions) { // non-compact items
        w.raw(a.cv);
        w.raw(a.rk);
        w.raw(ByteSpan(a.enc.data() + 564, 16));
        w.raw(a.out);
    }
    w.u8(b.flags);
    w.u64(uint64_t(b.value_balance));
    w.raw(b.anchor);
}

// mod.rs:1589-1609: without auth, then the proof (borsh [u8]: u32 length), every spend-auth
// signature, the binding signature.
void borsh(Writer& w, const OrchardBundle& b)
{
    borsh_without_auth(w, b);
    w.borsh_bytes(b.proof);
    for (auto& a : b.actions) w.raw(a.spend_auth_sig);
    w.raw(b.binding_sig);
}

static void borsh_inputs(Writer& w, const Transaction& t)
{
    w.borsh_len(t.inputs.size());
    for (auto& [op, h] : t.inputs) {
        borsh(w, op);
        w.raw(h);
    }
}

static void borsh_outputs(Writer& w, const Transaction& t)
{
    w.borsh_len(t.outputs.size());
    for (auto& o : t.outputs) borsh(w, o);
}

static void borsh_bundle_without_auth_opt(Writer& w, const Transaction& t)
{
    if (t.orchard_bundle) {
        w.u8(1);
        borsh_without_auth(w, *t.orchard_bundle);
    } else {
        w.u8(0);
    }
}

// transaction/mod.rs:62-90 derive(BorshSerialize): inputs, (proof skipped), orchard_bundle, outputs.
void borsh(Writer& w, const Transaction& t)
{
    borsh_inputs(w, t);
    if (t.orchard_bundle) {
        w.u8(1);
        borsh(w, *t.orchard_bundle);
    } else {
        w.u8(0);
    }
    borsh_outputs(w, t);
}

void borsh(Writer& w, const Authorization& a)
{
    w.raw(a.verifying_key);
    w.raw(a.signature.R);
    w.raw(a.signature.z);
}

void borsh(Writer& w, const Coinbase& c)
{
    w.borsh_bytes(c.memo);
    w.borsh_len(c.outputs.size());
    for (auto& o : c.outputs) borsh(w, o);
}

void borsh(Writer& w, const Body& b)
{
    borsh(w, b.coinbase);
    w.borsh_len(b.transactions.size());
    for (auto& t : b.transactions) borsh(w, t);
    w.borsh_len(b.authorizations.size());
    for (auto& a : b.authorizations) borsh(w, a);
}

void borsh(Writer& w, const Header& h)
{
    w.raw(h.merkle_root);
    if (h.prev_side_hash) {
        w.u8(1);
        w.raw(*h.prev_side_hash);
    } else {
        w.u8(0);
    }
    w.raw(h.prev_main_hash);
    w.borsh_len(h.roots.size());
    for (auto& r : h.roots) w.raw(r.bytes()); // Deref: Empty/Placeholder -> zeros
}

// transaction/mod.rs:129-160
Hash32 Transaction::txid() const
{
    Writer w;
    borsh_inputs(w, *this);
    borsh_outputs(w, *this);
    borsh_bundle_without_auth_opt(w, *this);
    return bt::blake3(w.buf);
}

// transaction/mod.rs:100-127: blake3(borsh{inputs_root, blake3(borsh(Option<bundle w/o auth>)), outputs_root})
Hash32 Transaction::merkle_root() const
{
    Writer b;
    borsh_bundle_without_auth_opt(b, *this);
    Writer w;
    w.raw(inputs_merkle_root(inputs));
    w.raw(bt::blake3(b.buf));
    w.raw(outputs_merkle_root(outputs));
    return bt::blake3(w.buf);
}
Bytes Transaction::canonical_bytes() const { return borsh_bytes(*this); }

Hash32 Header::hash() const { return zside::hash(*this); }
Hash32 Header::coinbase_txid() const { return compute_coinbase_txid(merkle_root, prev_main_hash, prev_side_hash); }

Hash32 compute_coinbase_txid(const Hash32& merkle_root, const Hash32& prev_main_hash, const std::optional<Hash32>& prev_side)
{
    Writer w;
    w.raw(merkle_root);
    w.raw(prev_main_hash);
    if (prev_side) {
        w.u8(1);
        w.raw(*prev_side);
    } else {
        w.u8(0);
    }
    return bt::blake3(w.buf);
}

Hash32 pointed_output_hash(const OutPoint& op, const Output& out)
{
    Writer w;
    borsh(w, op);
    borsh(w, out);
    return bt::blake3(w.buf);
}

size_t Body::inputs_len() const
{
    size_t n = 0;
    for (auto& t : transactions) n += t.inputs.size();
    return n;
}

std::vector<AuthorizedTransaction> Body::authorized_transactions() const
{
    std::vector<AuthorizedTransaction> r;
    size_t k = 0;
    for (auto& t : transactions) {
        AuthorizedTransaction at;
        at.transaction = t;
        for (size_t i = 0; i < t.inputs.size() && k < authorizations.size(); i++) at.authorizations.push_back(authorizations[k++]);
        r.push_back(std::move(at));
    }
    return r;
}

Body Body::from_authorized(std::vector<AuthorizedTransaction> txs, Coinbase cb)
{
    Body b;
    b.coinbase = std::move(cb);
    for (auto& t : txs) {
        for (auto& a : t.authorizations) b.authorizations.push_back(a);
        b.transactions.push_back(std::move(t.transaction));
    }
    return b;
}

std::optional<uint64_t> FilledTransaction::fee() const
{
    uint64_t in = 0, out = 0;
    for (auto& o : spent_utxos) {
        uint64_t v = o.get_value();
        if (in + v < in) return std::nullopt;
        in += v;
    }
    for (auto& o : tx->outputs) {
        uint64_t v = o.get_value();
        if (out + v < out) return std::nullopt;
        out += v;
    }
    if (tx->orchard_bundle) { // lib/state/mod.rs:410-423
        int64_t vb = tx->orchard_bundle->value_balance;
        uint64_t mag = vb < 0 ? uint64_t(0) - uint64_t(vb) : uint64_t(vb); // unsigned_abs
        uint64_t& side = vb > 0 ? in : out;
        if (side + mag < side) return std::nullopt;
        side += mag;
    }
    if (in < out) return std::nullopt; // NotEnoughValueIn
    return in - out;
}

// ---------------------------------------------------------------- bincode
void bincode(Writer& w, const Address& a) { w.raw(a.b); }

void bincode(Writer& w, const Content& c)
{
    w.u32(c.kind); // DefaultRepr enum
    w.u64(c.value);
    if (c.kind == Content::Withdrawal) {
        w.u64(c.main_fee);
        w.bincode_str(c.main_address.to_string()); // Address serde = collect_str(Display)
    }
}

void bincode(Writer& w, const Output& o)
{
    bincode(w, o.address);
    bincode(w, o.content);
}

void bincode(Writer& w, const OutPoint& o)
{
    w.u32(o.kind);
    if (o.kind == OutPoint::Deposit) {
        w.bincode_bytes(o.txid.span()); // bitcoin::Txid serde = serialize_bytes
        w.u32(o.vout);
    } else {
        w.raw(o.txid); // [u8; 32] as a tuple
        w.u32(o.vout);
    }
}

void bincode(Writer& w, const NodeHash& h)
{
    w.u32(h.tag);
    if (h.tag == NodeHash::Some) w.raw(h.h);
}

void bincode(Writer& w, const bt::utreexo::Proof& p)
{
    w.bincode_len(p.targets.size());
    for (auto t : p.targets) w.u64(t);
    w.bincode_len(p.hashes.size());
    for (auto& h : p.hashes) bincode(w, h);
}

// BundleRepr serde (mod.rs:1498-1525, ActionRepr :780-811): [u8; N] via serde_with Bytes
// (u64 length prefix) for epk/enc/out/signatures, plain [u8; 32] tuples for nf/rk/cmx/cv/anchor,
// NonEmpty as a sequence, flags u8, value balance i64, proof Vec<u8> as bytes.
void bincode(Writer& w, const OrchardBundle& b)
{
    w.bincode_len(b.actions.size());
    for (auto& a : b.actions) {
        w.raw(a.nf);
        w.raw(a.rk);
        w.raw(a.cmx);
        w.bincode_bytes(a.epk.span());
        w.bincode_bytes(a.enc.span());
        w.bincode_bytes(a.out.span());
        w.raw(a.cv);
        w.bincode_bytes(a.spend_auth_sig.span());
    }
    w.u8(b.flags);
    w.u64(uint64_t(b.value_balance));
    w.raw(b.anchor);
    w.bincode_bytes(b.proof);
    w.bincode_bytes(b.binding_sig.span());
}

void bincode(Writer& w, const Transaction& t)
{
    w.bincode_len(t.inputs.size());
    for (auto& [op, h] : t.inputs) {
        bincode(w, op);
        w.raw(h);
    }
    bincode(w, t.proof);
    if (t.orchard_bundle) {
        w.u8(1);
        bincode(w, *t.orchard_bundle);
    } else {
        w.u8(0);
    }
    w.bincode_len(t.outputs.size());
    for (auto& o : t.outputs) bincode(w, o);
}

void bincode(Writer& w, const Authorization& a)
{
    w.raw(a.verifying_key);    // serdect::array -> tuple, 32 bytes
    w.bincode_len(64);         // serdect::slice -> bytes with u64 length
    w.raw(a.signature.R);
    w.raw(a.signature.z);
}

void bincode(Writer& w, const AuthorizedTransaction& t)
{
    bincode(w, t.transaction);
    w.bincode_len(t.authorizations.size());
    for (auto& a : t.authorizations) bincode(w, a);
}

void bincode(Writer& w, const Coinbase& c)
{
    w.bincode_bytes(c.memo);
    w.bincode_len(c.outputs.size());
    for (auto& o : c.outputs) bincode(w, o);
}

void bincode(Writer& w, const Body& b)
{
    bincode(w, b.coinbase);
    w.bincode_len(b.transactions.size());
    for (auto& t : b.transactions) bincode(w, t);
    w.bincode_len(b.authorizations.size());
    for (auto& a : b.authorizations) bincode(w, a);
}

void bincode(Writer& w, const Header& h)
{
    w.raw(h.merkle_root);
    if (h.prev_side_hash) {
        w.u8(1);
        w.raw(*h.prev_side_hash);
    } else {
        w.u8(0);
    }
    w.bincode_bytes(h.prev_main_hash.span()); // bitcoin::BlockHash serde = bytes
    w.bincode_len(h.roots.size());
    for (auto& r : h.roots) bincode(w, r);
}

void bincode(Writer& w, const Block& b)
{
    bincode(w, b.header);
    bincode(w, b.body);
}

Address de_address(Reader& r)
{
    Address a;
    a.b = r.array<20>();
    return a;
}

Content de_content(Reader& r)
{
    Content c;
    uint32_t tag = r.u32();
    if (tag == 0) {
        c.kind = Content::Value;
        c.value = r.u64();
    } else if (tag == 1) {
        c.kind = Content::Withdrawal;
        c.value = r.u64();
        c.main_fee = r.u64();
        std::string s = r.bincode_str();
        auto a = bt::btc::Address::parse(s);
        if (!a) throw DecodeError("invalid main_address");
        c.main_address = *a;
    } else {
        throw DecodeError("invalid Content tag");
    }
    return c;
}

Output de_output(Reader& r)
{
    Output o;
    o.address = de_address(r);
    o.content = de_content(r);
    return o;
}

OutPoint de_outpoint(Reader& r)
{
    OutPoint o;
    uint32_t tag = r.u32();
    if (tag > 2) throw DecodeError("invalid OutPoint tag");
    o.kind = OutPoint::Kind(tag);
    if (o.kind == OutPoint::Deposit) {
        Bytes b = r.bincode_bytes();
        if (b.size() != 32) throw DecodeError("invalid txid length");
        o.txid = Hash32::from_span(b);
    } else {
        o.txid = r.array<32>();
    }
    o.vout = r.u32();
    return o;
}

NodeHash de_nodehash(Reader& r)
{
    uint32_t tag = r.u32();
    if (tag == 0) return NodeHash::empty();
    if (tag == 1) return NodeHash{NodeHash::Placeholder, {}};
    if (tag == 2) return NodeHash::some(r.array<32>());
    throw DecodeError("invalid NodeHash tag");
}

bt::utreexo::Proof de_proof(Reader& r)
{
    bt::utreexo::Proof p;
    size_t n = r.bincode_len(8);
    p.targets.reserve(n);
    for (size_t i = 0; i < n; i++) p.targets.push_back(r.u64());
    size_t m = r.bincode_len(4);
    for (size_t i = 0; i < m; i++) p.hashes.push_back(de_nodehash(r));
    return p;
}

template <size_t N>
static bt::ByteArray<N> de_fixed_bytes(Reader& r)
{
    Bytes b = r.bincode_bytes();
    if (b.size() != N) throw DecodeError("invalid length " + std::to_string(b.size()) + ", expected an array of length " + std::to_string(N));
    return bt::ByteArray<N>::from_span(b);
}

OrchardBundle de_orchard_bundle(Reader& r)
{
    OrchardBundle b;
    size_t n = r.bincode_len(32 * 4 + 8 * 4 + 32 + 580 + 80 + 64);
    if (n == 0) throw DecodeError("Non-Empty vector is empty");
    b.actions.resize(n);
    for (auto& a : b.actions) {
        a.nf = r.array<32>();
        a.rk = r.array<32>();
        a.cmx = r.array<32>();
        a.epk = de_fixed_bytes<32>(r);
        a.enc = de_fixed_bytes<580>(r);
        a.out = de_fixed_bytes<80>(r);
        a.cv = r.array<32>();
        a.spend_auth_sig = de_fixed_bytes<64>(r);
    }
    b.flags = r.u8();
    b.value_balance = int64_t(r.u64());
    b.anchor = r.array<32>();
    b.proof = r.bincode_bytes();
    b.binding_sig = de_fixed_bytes<64>(r);
    if (!orchard_bundle_decodes(b)) throw DecodeError("invalid orchard bundle");
    return b;
}

Transaction de_transaction(Reader& r)
{
    Transaction t;
    size_t n = r.bincode_len(4 + 4 + 32);
    for (size_t i = 0; i < n; i++) {
        OutPoint op = de_outpoint(r);
        Hash32 h = r.array<32>();
        t.inputs.emplace_back(op, h);
    }
    t.proof = de_proof(r);
    uint8_t opt = r.u8();
    if (opt == 1) t.orchard_bundle = de_orchard_bundle(r);
    else if (opt != 0) throw DecodeError("invalid Option tag");
    size_t m = r.bincode_len(20 + 4 + 8);
    for (size_t i = 0; i < m; i++) t.outputs.push_back(de_output(r));
    return t;
}

Authorization de_authorization(Reader& r)
{
    Authorization a;
    a.verifying_key = r.array<32>();
    if (!bt::frost::valid_element(a.verifying_key)) throw DecodeError("invalid verifying key");
    Bytes sig = r.bincode_bytes();
    if (sig.size() != 64) throw DecodeError("MalformedSignature");
    std::memcpy(a.signature.R.data(), sig.data(), 32);
    std::memcpy(a.signature.z.data(), sig.data() + 32, 32);
    if (!bt::frost::valid_element(a.signature.R) || !bt::frost::canonical_scalar(a.signature.z))
        throw DecodeError("invalid signature encoding");
    return a;
}

AuthorizedTransaction de_authorized_transaction(Reader& r)
{
    AuthorizedTransaction t;
    t.transaction = de_transaction(r);
    size_t n = r.bincode_len(32 + 8 + 64);
    for (size_t i = 0; i < n; i++) t.authorizations.push_back(de_authorization(r));
    return t;
}

Coinbase de_coinbase(Reader& r)
{
    Coinbase c;
    c.memo = r.bincode_bytes();
    size_t n = r.bincode_len(20 + 4 + 8);
    for (size_t i = 0; i < n; i++) c.outputs.push_back(de_output(r));
    return c;
}

Body de_body(Reader& r)
{
    Body b;
    b.coinbase = de_coinbase(r);
    size_t n = r.bincode_len(8 + 16 + 8);
    for (size_t i = 0; i < n; i++) b.transactions.push_back(de_transaction(r));
    size_t m = r.bincode_len(32 + 8 + 64);
    for (size_t i = 0; i < m; i++) b.authorizations.push_back(de_authorization(r));
    return b;
}

Header de_header(Reader& r)
{
    Header h;
    h.merkle_root = r.array<32>();
    uint8_t opt = r.u8();
    if (opt == 1) h.prev_side_hash = r.array<32>();
    else if (opt != 0) throw DecodeError("invalid Option tag");
    Bytes pm = r.bincode_bytes();
    if (pm.size() != 32) throw DecodeError("invalid block hash length");
    h.prev_main_hash = Hash32::from_span(pm);
    size_t n = r.bincode_len(4);
    for (size_t i = 0; i < n; i++) h.roots.push_back(de_nodehash(r));
    return h;
}

// ---------------------------------------------------------------- borsh decode
OutPoint borsh_de_outpoint(Reader& r)
{
    OutPoint o;
    uint8_t tag = r.u8();
    if (tag > 2) throw DecodeError("invalid OutPoint tag");
    o.kind = OutPoint::Kind(tag);
    o.txid = r.array<32>();
    o.vout = r.u32();
    return o;
}

Output borsh_de_output(Reader& r)
{
    Output o;
    o.address.b = r.array<20>();
    uint8_t tag = r.u8();
    if (tag == 0) {
        o.content.kind = Content::Value;
        o.content.value = r.u64();
    } else if (tag == 1) {
        o.content.kind = Content::Withdrawal;
        o.content.value = r.u64();
        o.content.main_fee = r.u64();
        Bytes spk = r.borsh_bytes();
        // borsh carries the scriptPubKey; recover an address of the same script (network
        // information is not in borsh, mainnet forms are used).
        bt::btc::Address a;
        if (spk.size() == 25 && spk[0] == 0x76 && spk[1] == 0xa9 && spk[2] == 0x14 && spk[23] == 0x88 && spk[24] == 0xac) {
            a.kind = bt::btc::Address::Kind::P2pkh;
            a.program.assign(spk.begin() + 3, spk.begin() + 23);
        } else if (spk.size() == 23 && spk[0] == 0xa9 && spk[1] == 0x14 && spk[22] == 0x87) {
            a.kind = bt::btc::Address::Kind::P2sh;
            a.program.assign(spk.begin() + 2, spk.begin() + 22);
        } else if (spk.size() >= 4 && (spk[0] == 0 || (spk[0] >= 0x51 && spk[0] <= 0x60)) && spk[1] + 2u == spk.size()) {
            a.kind = bt::btc::Address::Kind::Segwit;
            a.witver = spk[0] == 0 ? 0 : uint8_t(spk[0] - 0x50);
            a.program.assign(spk.begin() + 2, spk.end());
        } else {
            throw DecodeError("withdrawal script is not an address");
        }
        o.content.main_address = a;
    } else {
        throw DecodeError("invalid Content tag");
    }
    return o;
}

// borsh of a bundle with auth (mod.rs:1589-1609); the action count is not encoded, so it is
// derived from the length: 1197 bytes per action in total with 41 + proof bytes besides.
static OrchardBundle borsh_de_bundle(Reader& r, size_t n_actions)
{
    OrchardBundle b;
    b.actions.resize(n_actions);
    for (auto& a : b.actions) {
        a.nf = r.array<32>();
        a.cmx = r.array<32>();
        a.epk = r.array<32>();
        auto c = r.raw(52);
        std::memcpy(a.enc.data(), c.data(), 52);
    }
    for (auto& a : b.actions) {
        auto m = r.raw(512);
        if (std::memcmp(m.data(), a.enc.data() + 32, 20) != 0) throw DecodeError("memo overlap mismatch");
        std::memcpy(a.enc.data() + 32, m.data(), 512);
        auto x = r.raw(20);
        std::memcpy(a.enc.data() + 544, x.data(), 20);
    }
    for (auto& a : b.actions) {
        a.cv = r.array<32>();
        a.rk = r.array<32>();
        auto tag = r.raw(16);
        std::memcpy(a.enc.data() + 564, tag.data(), 16);
        a.out = r.array<80>();
    }
    b.flags = r.u8();
    b.value_balance = int64_t(r.u64());
    b.anchor = r.array<32>();
    b.proof = r.borsh_bytes();
    for (auto& a : b.actions) a.spend_auth_sig = r.array<64>();
    b.binding_sig = r.array<64>();
    return b;
}

Transaction borsh_de_transaction(Reader& r)
{
    Transaction t;
    size_t n = r.borsh_len(37 + 32);
    for (size_t i = 0; i < n; i++) {
        OutPoint op = borsh_de_outpoint(r);
        Hash32 h = r.array<32>();
        t.inputs.emplace_back(op, h);
    }
    uint8_t opt = r.u8();
    if (opt == 1) {
        // The proof length (u32 after flags/balance/anchor) fixes the action count: try each n.
        bool ok = false;
        for (size_t na = 1; !ok && na * 840 <= r.remaining(); na++) {
            Reader probe = r;
            try {
                OrchardBundle b = borsh_de_bundle(probe, na);
                // after the bundle, the outputs vector must parse to the end
                Reader rest = probe;
                size_t m = rest.borsh_len(29);
                std::vector<Output> outs;
                for (size_t i = 0; i < m; i++) outs.push_back(borsh_de_output(rest));
                if (!rest.empty()) continue;
                t.orchard_bundle = std::move(b);
                t.outputs = std::move(outs);
                r = rest;
                ok = true;
            } catch (const DecodeError&) {
            }
        }
        if (!ok) throw DecodeError("invalid orchard bundle");
        return t;
    } else if (opt != 0) {
        throw DecodeError("invalid Option tag");
    }
    size_t m = r.borsh_len(29);
    for (size_t i = 0; i < m; i++) t.outputs.push_back(borsh_de_output(r));
    return t;
}

// ---------------------------------------------------------------- merkle (CKB CBMT, merkle-cbt 0.3.2)
namespace {
// merkle_cbt::CBMT::build_merkle_root, generic over a merge that may fail.
template <class T, class Merge>
std::optional<T> cbmt_root(const std::vector<T>& leaves, Merge merge, const T& dflt)
{
    if (leaves.empty()) return dflt;
    std::deque<T> q;
    size_t n = leaves.size();
    // rchunks_exact(2): pairs from the end
    size_t i = n;
    while (i >= 2) {
        auto m = merge(leaves[i - 2], leaves[i - 1]);
        if (!m) return std::nullopt;
        q.push_back(*m);
        i -= 2;
    }
    if (i == 1) q.push_front(leaves[0]);
    while (q.size() > 1) {
        T right = q.front();
        q.pop_front();
        T left = q.front();
        q.pop_front();
        auto m = merge(left, right);
        if (!m) return std::nullopt;
        q.push_back(*m);
    }
    return q.front();
}

Hash32 merge_plain(const Hash32& l, const Hash32& r)
{
    Writer w; // hashes::hash(&(&l, &r)) = blake3(l || r)
    w.raw(l);
    w.raw(r);
    return bt::blake3(w.buf);
}
} // namespace

Hash32 inputs_merkle_root(const std::vector<std::pair<OutPoint, Hash32>>& ins)
{
    std::vector<Hash32> leaves;
    for (auto& [op, h] : ins) {
        Writer w;
        borsh(w, op);
        w.raw(h);
        leaves.push_back(bt::blake3(w.buf));
    }
    return *cbmt_root<Hash32>(leaves, [](const Hash32& l, const Hash32& r) -> std::optional<Hash32> { return merge_plain(l, r); }, Hash32{});
}

// transaction/outputs.rs:60-80 (plain CBMT; thunder-rust's is value/size annotated)
Hash32 outputs_merkle_root(const std::vector<Output>& outs)
{
    std::vector<Hash32> leaves;
    for (auto& o : outs) leaves.push_back(hash(o));
    return *cbmt_root<Hash32>(leaves, [](const Hash32& l, const Hash32& r) -> std::optional<Hash32> { return merge_plain(l, r); }, Hash32{});
}

Hash32 coinbase_merkle_root(const Coinbase& cb)
{
    Writer w;
    w.borsh_bytes(cb.memo);
    w.raw(outputs_merkle_root(cb.outputs));
    return bt::blake3(w.buf);
}

// block/body.rs:112-146
Hash32 compute_merkle_root(const Coinbase& cb, const std::vector<Transaction>& txs)
{
    std::vector<Hash32> leaves;
    for (auto& t : txs) leaves.push_back(t.merkle_root());
    Hash32 txs_commitment =
        *cbmt_root<Hash32>(leaves, [](const Hash32& l, const Hash32& r) -> std::optional<Hash32> { return merge_plain(l, r); }, Hash32{});
    Writer w;
    w.raw(coinbase_merkle_root(cb));
    w.raw(txs_commitment);
    return bt::blake3(w.buf);
}

// ---------------------------------------------------------------- limits
double powi(double a, int b)
{
    const bool recip = b < 0;
    double r = 1;
    while (true) {
        if (b & 1) r *= a;
        b /= 2;
        if (b == 0) break;
        a *= a;
    }
    return recip ? 1 / r : r;
}

static uint64_t growing_limit(uint64_t start, uint32_t height)
{
    uint32_t month = height / (6 * 24 * 30);
    if (month < 120) {
        double v = double(start) * powi(1.04, int(month)); // START as f64 * 1.04f64.powi(month)
        return uint64_t(std::floor(v));
    }
    return start * 111;
}

uint64_t body_sigops_limit(uint32_t height) { return growing_limit(42800, height); }
uint64_t body_size_limit(uint32_t height) { return growing_limit(8ull * 1024 * 1024, height); }

// ---------------------------------------------------------------- authorizations
// authorization.rs:207-252: every bundle (verify_orchard), then the transparent count and
// signatures.
bool verify_authorizations(const Body& body)
{
    for (auto& tx : body.transactions)
        if (tx.orchard_bundle && orchard_verify(*tx.orchard_bundle, tx.txid()) != 0) return false;
    size_t required = body.inputs_len();
    if (body.authorizations.size() != required) return false;
    size_t k = 0;
    for (auto& tx : body.transactions) {
        Bytes msg = tx.canonical_bytes();
        for (size_t i = 0; i < tx.inputs.size(); i++, k++) {
            auto& a = body.authorizations[k];
            if (!bt::frost::verify(a.verifying_key, a.signature, msg)) return false;
        }
    }
    return true;
}

// authorization.rs:171-205: count, then verify_orchard, then (only with inputs) the batch.
bool verify_authorized_transaction(const AuthorizedTransaction& tx)
{
    if (tx.authorizations.size() != tx.transaction.inputs.size()) return false;
    if (tx.transaction.orchard_bundle && orchard_verify(*tx.transaction.orchard_bundle, tx.transaction.txid()) != 0) return false;
    if (tx.authorizations.empty()) return true;
    Bytes msg = tx.transaction.canonical_bytes();
    for (auto& a : tx.authorizations)
        if (!bt::frost::verify(a.verifying_key, a.signature, msg)) return false;
    return true;
}

// ---------------------------------------------------------------- orchard
Bytes orchard_ffi_actions(const OrchardBundle& b)
{
    Bytes v;
    v.reserve(b.actions.size() * 884);
    for (auto& a : b.actions) {
        append(v, a.nf.span());
        append(v, a.rk.span());
        append(v, a.cmx.span());
        append(v, a.epk.span());
        append(v, a.enc.span());
        append(v, a.out.span());
        append(v, a.cv.span());
        append(v, a.spend_auth_sig.span());
    }
    return v;
}

namespace {
struct BundleHandle {
    ZsBundle* p = nullptr;
    explicit BundleHandle(const OrchardBundle& b)
    {
        if (b.actions.empty()) return;
        Bytes acts = orchard_ffi_actions(b);
        p = zs_bundle_parse(acts.data(), b.actions.size(), b.flags, b.value_balance, b.anchor.data(), b.proof.data(), b.proof.size(),
                            b.binding_sig.data());
    }
    ~BundleHandle() { zs_bundle_free(p); }
    BundleHandle(const BundleHandle&) = delete;
    BundleHandle& operator=(const BundleHandle&) = delete;
};
} // namespace

bool orchard_bundle_decodes(const OrchardBundle& b) { return BundleHandle(b).p != nullptr; }

int orchard_verify(const OrchardBundle& b, const Hash32& txid)
{
    BundleHandle h(b);
    if (!h.p) return -1;
    return zs_bundle_verify(h.p, txid.data());
}

const Hash32& orchard_empty_root()
{
    static const Hash32 r = [] {
        Hash32 x;
        zs_empty_root(x.data());
        return x;
    }();
    return r;
}

} // namespace zside
