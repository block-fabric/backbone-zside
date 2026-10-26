// Copyright (c) 2026 The Backbone developers
// Distributed under the MIT software license.
//
// Block archive: side headers/bodies, mainchain header infos and block infos, BMM
// verification results and fork choice. Port of thunder-rust v0.18.2 lib/archive/mod.rs
// (put_header BMM rules :886-1015, put_main_block_info :1019-1075, better_tip :1435-1650).
#pragma once

#include <zside/types.h>

#include <bt/kv.h>
#include <bt/mainchain.h>

#include <map>

namespace zside {

enum class BmmResult : uint8_t { Verified = 0, Failed = 1 };

/** 256-bit little-endian unsigned integer (bitcoin::Work arithmetic). */
struct U256 {
    std::array<uint64_t, 4> w{}; // w[0] least significant
    static U256 from_le(const Hash32& b);
    Hash32 to_le() const;
    Hash32 to_be() const;
    U256 operator+(const U256& o) const;
    friend auto operator<=>(const U256& a, const U256& b)
    {
        for (int i = 3; i >= 0; i--)
            if (auto c = a.w[i] <=> b.w[i]; c != 0) return c;
        return std::strong_ordering::equal;
    }
    friend bool operator==(const U256&, const U256&) = default;
};

struct MainHeader {
    Hash32 hash, prev;
    uint32_t height = 0;
    U256 work, total_work;
    Hash32 skip; // ancestor used for O(log n) nth-ancestor jumps
};

struct TipRef {
    Hash32 block_hash;
    Hash32 main_block_hash;
    bool operator==(const TipRef&) const = default;
};

class ArchiveError : public std::runtime_error {
public:
    using std::runtime_error::runtime_error;
};

class Archive {
public:
    enum Table : uint8_t {
        A_HEADERS = 40, A_BODIES, A_HEIGHT, A_EXP_ANC, A_SUCC, A_BMM, A_ACC, A_TX_INCL, A_MAIN_HDR, A_MAIN_INFO, A_MAIN_SUCC,
        A_INVALID, A_HEIGHT_INDEX
    };

    // ---- side chain
    std::optional<Header> header(const bt::kv::Txn& t, const Hash32& h) const;
    std::optional<Body> body(const bt::kv::Txn& t, const Hash32& h) const;
    std::optional<uint32_t> height(const bt::kv::Txn& t, const Hash32& h) const;
    bool invalid(const bt::kv::Txn& t, const Hash32& h) const;
    /** put_header: requires the parent header and main infos for prev_main's children. */
    void put_header(bt::kv::Txn& t, const Header& h) const;
    void put_body(bt::kv::Txn& t, const Hash32& h, const Body& b) const;
    void delete_body(bt::kv::Txn& t, const Hash32& h) const;
    void put_accumulator(bt::kv::Txn& t, const Hash32& h, const bt::utreexo::MemForest& f) const;
    std::optional<bt::utreexo::MemForest> accumulator(const bt::kv::Txn& t, const Hash32& h) const;
    std::map<Hash32, BmmResult> bmm_results(const bt::kv::Txn& t, const Hash32& side) const;
    std::optional<Hash32> best_main_verification(const bt::kv::Txn& t, const Hash32& side) const;
    Hash32 nth_ancestor(const bt::kv::Txn& t, Hash32 h, uint32_t n) const;
    bool is_descendant(const bt::kv::Txn& t, const Hash32& anc, const Hash32& desc) const;
    std::optional<Hash32> last_common_ancestor(const bt::kv::Txn& t, Hash32 a, Hash32 b) const;
    std::vector<Hash32> block_locator(const bt::kv::Txn& t, const Hash32& h) const;
    /** Ancestors from h (inclusive) back to genesis. */
    std::vector<Hash32> ancestors(const bt::kv::Txn& t, const Hash32& h) const;
    std::vector<Hash32> missing_bodies(const bt::kv::Txn& t, const Hash32& h, const std::optional<Hash32>& stop) const;
    std::map<Hash32, uint32_t> tx_inclusions(const bt::kv::Txn& t, const Hash32& txid) const;
    std::vector<Hash32> successors(const bt::kv::Txn& t, const std::optional<Hash32>& h) const;
    void mark_invalid(bt::kv::Txn& t, const Hash32& h) const;

    // ---- mainchain
    std::optional<MainHeader> main_header(const bt::kv::Txn& t, const Hash32& h) const;
    bt::mainchain::BlockInfo main_block_info(const bt::kv::Txn& t, const Hash32& h) const;
    bool has_main_block_info(const bt::kv::Txn& t, const Hash32& h) const;
    void put_main_header_info(bt::kv::Txn& t, const bt::mainchain::BlockHeaderInfo& hi) const;
    void put_main_block_info(bt::kv::Txn& t, const Hash32& main, const bt::mainchain::BlockInfo& bi) const;
    Hash32 nth_main_ancestor(const bt::kv::Txn& t, Hash32 h, uint32_t n) const;
    bool is_main_descendant(const bt::kv::Txn& t, const Hash32& anc, const Hash32& desc) const;
    Hash32 last_common_main_ancestor(const bt::kv::Txn& t, Hash32 a, Hash32 b) const;
    bool shared_mainchain_lineage(const bt::kv::Txn& t, Hash32 a, Hash32 b) const;
    U256 total_work(const bt::kv::Txn& t, const Hash32& main) const;
    std::vector<Hash32> main_successors(const bt::kv::Txn& t, const Hash32& main) const;

    /** better_tip(tip0, tip1): which tip wins, or nullopt if neither. */
    std::optional<TipRef> better_tip(const bt::kv::Txn& t, const TipRef& tip0, const TipRef& tip1) const;

    bool has_body(const bt::kv::Txn& t, const Hash32& h) const { return t.get(A_BODIES, h.span()).has_value(); }
    MainHeader need_main(const bt::kv::Txn& t, const Hash32& h) const;
    Header need_header(const bt::kv::Txn& t, const Hash32& h) const;

private:
    uint32_t need_height(const bt::kv::Txn& t, const Hash32& h) const;
    void put_bmm_results(bt::kv::Txn& t, const Hash32& side, const std::map<Hash32, BmmResult>& r) const;
    /** ancestor search used by better_tip: first ancestor whose prev_main is a strict
     *  ancestor of main_ancestor; returns its height (and the work of the main block
     *  following its prev_main on main_ancestor's chain, when with_work). */
    std::optional<std::pair<uint32_t, U256>> ancestor_before(const bt::kv::Txn& t, const Hash32& tip, const Hash32& main_ancestor, bool with_work) const;
};

void enc_block_info(Writer& w, const bt::mainchain::BlockInfo& bi);
bt::mainchain::BlockInfo dec_block_info(Reader& r);

} // namespace zside
