// Copyright (c) 2026 The Backbone developers
// Distributed under the MIT software license.
//
// zSide (eCash betanet slot 98) consensus types, byte-exact with iwakura-rein/thunder-orchard
// v0.18.1 (master b225827, MIT; `types/`). thunder-rust plus an Orchard bundle in each
// transaction. Every hash is BLAKE3(borsh(x)); the P2P wire uses bincode 1.3 over serde.
// Citations are thunder-orchard paths at b225827 unless marked thunder-rust.
// Orchard cryptography (point decoding, signatures, halo2 proofs, the note commitment tree,
// keys, note encryption) is the reference orchard 0.14.0 crate behind a C ABI (orchard_ffi.h).
#pragma once

#include <bt/bitcoin.h>
#include <bt/bytes.h>
#include <bt/codec.h>
#include <bt/crypto.h>
#include <bt/frost.h>
#include <bt/utreexo.h>

#include <map>
#include <optional>
#include <string>
#include <variant>
#include <vector>

namespace zside {

using bt::Bytes;
using bt::append;
using bt::ByteSpan;
using bt::Hash32;
using bt::Reader;
using bt::Writer;

constexpr uint8_t THIS_SIDECHAIN = 98; // types/lib.rs:45

/** types/address.rs TransparentAddress: 20 raw bytes, text = plain base58, no version, no
 *  checksum. */
struct Address {
    bt::Hash20 b;
    static const Address ALL_ZEROS;
    std::string to_base58() const;
    static std::optional<Address> from_base58(std::string_view s);
    /** `s98_<b58>_<hex(sha256(prefix))[..6]>` (address.rs format_for_deposit), wallet display
     *  only: deposits credit only a bare base58 address (proto.rs:446-506). */
    std::string format_for_deposit() const;
    friend auto operator<=>(const Address&, const Address&) = default;
    friend bool operator==(const Address&, const Address&) = default;
};

/** address.rs:113-160 ShieldedAddress: the 43 raw Orchard address bytes; text = Bech32m with
 *  HRP "t-shld" on every network; decode requires the canonical (re-encoded) form and bytes
 *  orchard's Address::from_raw_address_bytes accepts. */
struct ShieldedAddress {
    bt::ByteArray<43> b;
    std::string to_string() const;
    static std::optional<ShieldedAddress> parse(std::string_view s);
    friend bool operator==(const ShieldedAddress&, const ShieldedAddress&) = default;
    friend auto operator<=>(const ShieldedAddress&, const ShieldedAddress&) = default;
};

/** authorization.rs:21-29: first 20 bytes of BLAKE3-XOF(compressed VK). */
Address address_from_vk(const bt::frost::Point& vk);

/** output/content.rs:120-134. */
struct Content {
    enum Kind : uint8_t { Value = 0, Withdrawal = 1 };
    Kind kind = Value;
    uint64_t value = 0;
    uint64_t main_fee = 0;        // Withdrawal
    bt::btc::Address main_address; // Withdrawal
    /** content.rs:145-157: Withdrawal = value + main_fee, saturating at u64::MAX. */
    uint64_t get_value() const;
    bool operator==(const Content& o) const
    {
        return kind == o.kind && value == o.value && (kind == Value || (main_fee == o.main_fee && main_address == o.main_address));
    }
};

struct Output {
    Address address;
    Content content;
    uint64_t get_value() const { return content.get_value(); }
    bool operator==(const Output&) const = default;
};

/** transaction/outpoint.rs:270-290. Ord = variant index, then (txid bytes, vout). */
struct OutPoint {
    enum Kind : uint8_t { Regular = 0, Coinbase = 1, Deposit = 2 };
    Kind kind = Regular;
    Hash32 txid; // Txid / CoinbaseTxid / bitcoin Txid (internal byte order)
    uint32_t vout = 0;
    friend auto operator<=>(const OutPoint&, const OutPoint&) = default;
    friend bool operator==(const OutPoint&, const OutPoint&) = default;
    /** 37-byte borsh form, also the key of their utxos/stxos tables. */
    std::array<uint8_t, 37> key() const;
    std::string to_string() const;
};

/** Reference to a spend (transaction/mod.rs:44-55). */
struct InPoint {
    enum Kind : uint8_t { Regular = 0, Withdrawal = 1 };
    Kind kind = Regular;
    Hash32 id; // txid, or m6id (internal byte order)
    uint32_t vin = 0;
    bool operator==(const InPoint&) const = default;
};

struct SpentOutput {
    Output output;
    InPoint inpoint;
};

/** types/orchard/mod.rs Action<Signature<SpendAuth>>, raw fields (decoding is validated by
 *  orchard_bundle_decodes). */
struct OrchardAction {
    Hash32 nf, rk, cmx, epk;
    bt::ByteArray<580> enc;
    bt::ByteArray<80> out;
    Hash32 cv;
    bt::ByteArray<64> spend_auth_sig;
    bool operator==(const OrchardAction&) const = default;
};

/** types/orchard/mod.rs Bundle<Authorized> (BundleRepr :1512-1525). */
struct OrchardBundle {
    std::vector<OrchardAction> actions; // NonEmpty
    uint8_t flags = 0;                  // bit 0 spends enabled, bit 1 outputs enabled
    int64_t value_balance = 0;          // sats; > 0 leaves the pool
    Hash32 anchor;
    Bytes proof;
    bt::ByteArray<64> binding_sig;
    bool spends_enabled() const { return flags & 1; }
    bool operator==(const OrchardBundle&) const = default;
};

struct Transaction {
    std::vector<std::pair<OutPoint, Hash32>> inputs; // (outpoint, utxo_hash)
    bt::utreexo::Proof proof;                        // #[borsh(skip)], serde only
    std::optional<OrchardBundle> orchard_bundle;     // transaction/mod.rs:62-90
    std::vector<Output> outputs;

    Bytes canonical_bytes() const; // borsh: inputs, orchard_bundle (with auth), outputs
    uint64_t canonical_size() const { return canonical_bytes().size(); }
    /** transaction/mod.rs:129-160: BLAKE3 of borsh(inputs) || borsh(outputs) ||
     *  borsh(Option<bundle without auth>). Also the Orchard sighash. */
    Hash32 txid() const;
    /** transaction/mod.rs:100-127 */
    Hash32 merkle_root() const;
};

struct Authorization {
    bt::frost::Point verifying_key;
    bt::frost::Signature signature;
};

struct AuthorizedTransaction {
    Transaction transaction;
    std::vector<Authorization> authorizations;
};

struct Coinbase {
    Bytes memo;
    std::vector<Output> outputs;
};

struct Body {
    Coinbase coinbase;
    std::vector<Transaction> transactions;
    std::vector<Authorization> authorizations;
    size_t inputs_len() const;
    std::vector<AuthorizedTransaction> authorized_transactions() const;
    static Body from_authorized(std::vector<AuthorizedTransaction> txs, Coinbase cb);
};

/** block/mod.rs:28-39 */
struct Header {
    Hash32 merkle_root;
    std::optional<Hash32> prev_side_hash;
    Hash32 prev_main_hash; // bitcoin block hash, internal byte order
    std::vector<bt::utreexo::NodeHash> roots;

    Hash32 hash() const;
    Hash32 coinbase_txid() const;
    bool operator==(const Header& o) const
    {
        return merkle_root == o.merkle_root && prev_side_hash == o.prev_side_hash && prev_main_hash == o.prev_main_hash &&
               roots == o.roots;
    }
};

struct Block {
    Header header;
    Body body;
};

/** A transaction together with the outputs it spends (FilledTransaction). */
struct FilledTransaction {
    const Transaction* tx = nullptr;
    std::vector<Output> spent_utxos;
    /** The fee validate_filled_transaction computes (lib/state/mod.rs:384-430): checked
     *  sums, the bundle's value balance added to value in (> 0) or value out (<= 0). */
    std::optional<uint64_t> fee() const;
};

// ---------------------------------------------------------------- borsh
void borsh(Writer& w, const Address& a);
void borsh(Writer& w, const Content& c);
void borsh(Writer& w, const Output& o);
void borsh(Writer& w, const OutPoint& o);
void borsh(Writer& w, const OrchardBundle& b); // with authorization (mod.rs:1589-1609)
/** mod.rs:1533-1585 borsh_serialize_without_auth (ZIP-244-like order, memo from enc[32..544]). */
void borsh_without_auth(Writer& w, const OrchardBundle& b);
void borsh(Writer& w, const Transaction& t);
void borsh(Writer& w, const Authorization& a);
void borsh(Writer& w, const Coinbase& c);
void borsh(Writer& w, const Body& b);
void borsh(Writer& w, const Header& h);
template <class T>
Bytes borsh_bytes(const T& x)
{
    Writer w;
    borsh(w, x);
    return w.buf;
}
template <class T>
Hash32 hash(const T& x)
{
    return bt::blake3(borsh_bytes(x));
}

/** utxo_hash / Utreexo leaf = blake3(borsh{outpoint, output}) (output/mod.rs:55-78). */
Hash32 pointed_output_hash(const OutPoint& op, const Output& out);

// ---------------------------------------------------------------- bincode (serde)
void bincode(Writer& w, const Address& a);
void bincode(Writer& w, const Content& c);
void bincode(Writer& w, const Output& o);
void bincode(Writer& w, const OutPoint& o);
void bincode(Writer& w, const bt::utreexo::NodeHash& h);
void bincode(Writer& w, const bt::utreexo::Proof& p);
void bincode(Writer& w, const OrchardBundle& b);
void bincode(Writer& w, const Transaction& t);
void bincode(Writer& w, const Authorization& a);
void bincode(Writer& w, const AuthorizedTransaction& t);
void bincode(Writer& w, const Coinbase& c);
void bincode(Writer& w, const Body& b);
void bincode(Writer& w, const Header& h);
void bincode(Writer& w, const Block& b);

Address de_address(Reader& r);
Content de_content(Reader& r);
Output de_output(Reader& r);
OutPoint de_outpoint(Reader& r);
bt::utreexo::NodeHash de_nodehash(Reader& r);
bt::utreexo::Proof de_proof(Reader& r);
/** Bundle<Authorized> serde Deserialize: the bincode fields, then orchard_bundle_decodes. */
OrchardBundle de_orchard_bundle(Reader& r);
Transaction de_transaction(Reader& r);
Authorization de_authorization(Reader& r);
AuthorizedTransaction de_authorized_transaction(Reader& r);
Coinbase de_coinbase(Reader& r);
Body de_body(Reader& r);
Header de_header(Reader& r);

/** borsh decoders (used for the index's /tx/<txid>/hex = borsh(tx)). */
Output borsh_de_output(Reader& r);
OutPoint borsh_de_outpoint(Reader& r);
Transaction borsh_de_transaction(Reader& r);

// ---------------------------------------------------------------- merkle (plain CBMTs)
/** block/body.rs:112-146: blake3(borsh{coinbase_commitment, txs_commitment}), infallible. */
Hash32 compute_merkle_root(const Coinbase& cb, const std::vector<Transaction>& txs);
/** coinbase.rs:20-25 */
Hash32 coinbase_merkle_root(const Coinbase& cb);
/** transaction/outputs.rs:60-80: leaf blake3(borsh(output)), node blake3(l || r). */
Hash32 outputs_merkle_root(const std::vector<Output>& outs);
Hash32 inputs_merkle_root(const std::vector<std::pair<OutPoint, Hash32>>& ins);

/** coinbase.rs:99-121 */
Hash32 compute_coinbase_txid(const Hash32& merkle_root, const Hash32& prev_main_hash, const std::optional<Hash32>& prev_side);

// ---------------------------------------------------------------- limits
/** lib/state/mod.rs:445-476 (f64 powi + floor, cap START*111 from month 120). */
uint64_t body_sigops_limit(uint32_t height);
uint64_t body_size_limit(uint32_t height);
/** compiler-rt __powidf2: what Rust's f64::powi lowers to for a runtime exponent. */
double powi(double a, int b);

// ---------------------------------------------------------------- authorizations
/** verify_authorizations (authorization.rs:186-230): exact count, then every signature
 *  over borsh(tx) of its transaction. */
bool verify_authorizations(const Body& body);
bool verify_authorized_transaction(const AuthorizedTransaction& tx);

// ---------------------------------------------------------------- orchard (reference crate)
/** orchard_ffi zs_bundle_parse: every point decodes as their serde does, Action::from_parts
 *  (identity rk / invalid epk refused), flags, anchor, Strict proof size. */
bool orchard_bundle_decodes(const OrchardBundle& b);
/** authorization.rs verify_orchard (:146-157) with sighash = txid: 0 ok, 1 binding sig,
 *  2 spend-auth sig, 3 proof, -1 does not decode. */
int orchard_verify(const OrchardBundle& b, const Hash32& txid);
/** Anchor::empty_tree() (mod.rs:1044). */
const Hash32& orchard_empty_root();
/** 884-byte ABI layout per action (orchard_ffi.h). */
Bytes orchard_ffi_actions(const OrchardBundle& b);

} // namespace zside
