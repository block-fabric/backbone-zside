// Copyright (c) 2026 The Backbone developers
// Distributed under the MIT software license.
//
// zSide wallet, key-compatible with thunder-orchard b225827 (lib/wallet/mod.rs, bip32.rs):
//  * seed = BIP-39 (tiny-bip39, empty passphrase);
//  * "bip32ish" over ristretto255 with BLAKE3 (since v0.18.1, 6f54f21): master =
//    derive_key("zSide seed", seed) XOF 96 bytes (64 -> scalar mod L as a big-endian integer,
//    32 -> chain code); hardened child = keyed_blake3(chaincode, 0x00 || scalar || be32(i|2^31)),
//    non-hardened = keyed_blake3(chaincode, point || be32(i)), same XOF split, child = parent +
//    tweak. v0.18.0 wallets used thunder's HMAC-SHA512 scheme (bt::hd, top-3-bits variant);
//  * transparent keys m/43'/1899'/0'/98'/0'/i, addresses from index 0 (FROST, BLAKE3 20 bytes);
//  * Orchard: the m/43'/1899'/0'/98'/2'/0' node's secret scalar is the ZIP-32 seed of
//    SpendingKey::from_zip32_seed(seed, coin 0, account 0); shielded addresses are the
//    external-scope diversifier indexes 0, 1, 2...
// Notes are found by trial decryption of the active chain's bundles (both ivk scopes) through
// the reference orchard crate; spends against an anchor 3 blocks under the tip
// (ANCHOR_CHECKPOINT_DEPTH, wallet/mod.rs:156) with witnesses built from the chain's note
// commitments. Their LMDB wallet is not read: import by mnemonic.
#pragma once

#include <zside/node.h>

#include <bt/hd.h>
#include <bt/kv.h>

#include <array>
#include <map>
#include <memory>
#include <mutex>
#include <set>
#include <string_view>

struct ZsBuilder; // orchard_ffi.h

namespace zside {

/** types/wallet.rs Balance */
struct Balance {
    uint64_t total_shielded = 0, total_transparent = 0, available_shielded = 0, available_transparent = 0;
};

enum class KeyDerivation {
    Blake3, // thunder-orchard >= 0.18.1 ("zSide seed")
    Hmac    // thunder-orchard 0.18.0 (thunder-rust's HMAC-SHA512 bip32ish, top 3 bits cleared)
};

struct ZsXpriv {
    bt::frost::Scalar secret;
    bt::ByteArray<32> chaincode;
    static ZsXpriv master(const bt::ByteArray<64>& seed);
    ZsXpriv derive_hardened(uint32_t index) const;
    ZsXpriv derive_non_hardened(uint32_t index) const;
};

/** A note the wallet owns (confirmed, value > 0). */
struct WalletNote {
    bt::ByteArray<115> note; // orchard_ffi note layout
    uint64_t value = 0;
    uint64_t position = 0; // leaf index in the note commitment tree
    uint32_t height = 0;   // block that created it
    Hash32 nullifier;
    Hash32 txid;
};

/**
 * A note of the shielded account as the app layer shows it (doc/app.md): one the wallet received (decrypted with its
 * incoming viewing key, either scope), or one it sent to another (recovered with its outgoing viewing key), with its
 * memo. Read from the active chain and the mempool; never used to build a spend (scan() does that).
 */
struct ShieldedNote {
    Hash32 txid;
    std::optional<uint32_t> height; // nullopt: waiting in the mempool
    bool incoming = true;           // to this wallet; false: sent to another
    bool internal = false;          // to the wallet's internal scope (change)
    uint64_t value = 0;
    ShieldedAddress address; // the recipient
    std::array<uint8_t, 512> memo{};
    uint64_t position = 0;          // leaf index (a note of the chain)
    std::optional<Hash32> spent_in; // incoming: the transaction that spent it
    bool spent_pending = false;     // ... still in the mempool
};

/** The shielded account as the app layer shows it: its notes, what each transaction spent of them, the value balance
 *  of every transaction with a bundle that touches the wallet, and what can be spent now. */
struct ShieldedView {
    std::vector<ShieldedNote> notes;
    std::map<Hash32, uint64_t> spent_by_tx;
    std::map<Hash32, int64_t> value_balance;
    uint64_t available = 0; // unspent, not spent by a mempool transaction (balance's available_shielded)
    uint64_t total = 0;     // unspent (balance's total_shielded)
    uint64_t spendable = 0; // of available, the notes old enough to spend now (under the anchor 3 blocks below the tip)
    uint64_t pending_in = 0; // to this wallet in mempool transactions
};

class Wallet {
public:
    Wallet(const std::string& path, Node& node, KeyDerivation d = KeyDerivation::Blake3);
    bool has_seed();
    KeyDerivation derivation() const { return deriv_; }
    /** SHA-256(label 0x00 seed), or nothing without a seed: a public fingerprint of the seed (the app layer's), never the seed. */
    std::optional<Hash32> seed_digest(std::string_view label);
    /** The shielded account with memos (the app layer's pages). */
    ShieldedView shielded_view();
    void set_seed(const bt::ByteArray<64>& seed);
    void set_seed_from_mnemonic(const std::string& mnemonic);

    Address get_new_transparent_address();
    Address get_or_generate_last_transparent_address();
    std::vector<Address> transparent_addresses(); // sorted by base58
    ShieldedAddress get_new_shielded_address();
    std::vector<ShieldedAddress> shielded_addresses(); // sorted by bech32m

    std::vector<std::pair<OutPoint, Output>> utxos();
    std::vector<std::pair<OutPoint, SpentOutput>> stxos();
    /** Outputs of mempool txs paying our addresses; our UTXOs spent by mempool txs. */
    std::vector<std::pair<OutPoint, Output>> utxos_unconfirmed();
    std::vector<std::pair<OutPoint, SpentOutput>> stxos_unconfirmed();
    std::vector<WalletNote> notes(); // unspent confirmed notes
    Balance balance();

    Transaction create_transparent_transfer(const Address& dest, uint64_t value, uint64_t fee);
    Transaction create_withdrawal(const bt::btc::Address& main_address, uint64_t value, uint64_t main_fee, uint64_t fee);
    /** wallet/mod.rs create_shield_transaction(_from_utxos), without their optional note
     *  consolidation: transparent coins -> a new note of `value` (SPENDS_DISABLED, empty anchor). */
    Transaction create_shield(uint64_t value, uint64_t fee);
    /** create_shielded_transaction: notes -> dest + change note; the fee leaves the pool. `memo`: the recipient's
     *  note's memo (512 bytes; the app layer's), none as LayerTwo's wallet writes it. */
    Transaction create_shielded_transfer(const ShieldedAddress& dest, uint64_t value, uint64_t fee, const std::array<uint8_t, 512>* memo = nullptr);
    /** create_unshield_transaction: notes -> a transparent output of `value` + change note. */
    Transaction create_unshield(uint64_t value, uint64_t fee);
    /** Transparent authorizations over borsh(tx) (the create_* methods already signed the
     *  Orchard bundle with sighash = txid, as app.rs authorize_orchard_bundle). */
    AuthorizedTransaction authorize(const Transaction& tx);

    // keys (exposed for tests and differential checks)
    static bt::frost::SigningKey transparent_key(const bt::ByteArray<64>& seed, uint32_t index, KeyDerivation d);
    static bt::ByteArray<32> orchard_spending_key(const bt::ByteArray<64>& seed, KeyDerivation d);
    static bt::ByteArray<96> full_viewing_key(const bt::ByteArray<32>& sk);
    static ShieldedAddress shielded_address(const bt::ByteArray<96>& fvk, uint32_t index);

    struct Scan;

private:
    std::unique_ptr<bt::kv::Store> store_;
    Node& node_;
    KeyDerivation deriv_;
    std::mutex mu_;
    std::optional<bt::ByteArray<64>> seed();
    bt::ByteArray<64> need_seed();
    bt::frost::SigningKey key(uint32_t index);
    bool is_mine(const Address& a);
    std::pair<uint64_t, std::vector<std::pair<OutPoint, Output>>> select_transparent(uint64_t value);
    Scan scan();
    /** build + prove the bundle, put its effects in tx, sign it with sighash = txid. */
    void finish_orchard(Transaction& tx, ::ZsBuilder* b);
};

} // namespace zside
