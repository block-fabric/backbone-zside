// Copyright (c) 2026 The Backbone developers
// Distributed under the MIT software license.
#include <zside/archive.h>

#include <algorithm>
#include <set>

namespace zside {

using bt::kv::Txn;

// ------------------------------------------------------------------ U256
U256 U256::from_le(const Hash32& b)
{
    U256 r;
    for (int i = 0; i < 4; i++) {
        uint64_t v = 0;
        for (int j = 7; j >= 0; j--) v = v << 8 | b[8 * i + j];
        r.w[i] = v;
    }
    return r;
}
Hash32 U256::to_le() const
{
    Hash32 b;
    for (int i = 0; i < 4; i++)
        for (int j = 0; j < 8; j++) b[8 * i + j] = uint8_t(w[i] >> (8 * j));
    return b;
}
Hash32 U256::to_be() const
{
    Hash32 le = to_le(), be;
    for (int i = 0; i < 32; i++) be[i] = le[31 - i];
    return be;
}
U256 U256::operator+(const U256& o) const
{
    U256 r;
    unsigned __int128 carry = 0;
    for (int i = 0; i < 4; i++) {
        unsigned __int128 s = (unsigned __int128)w[i] + o.w[i] + carry;
        r.w[i] = uint64_t(s);
        carry = s >> 64;
    }
    return r; // bitcoin::Work `+` on U256 (overflow unreachable in practice)
}

// ------------------------------------------------------------------ encodings
void enc_block_info(Writer& w, const bt::mainchain::BlockInfo& bi)
{
    w.u8(bi.bmm_commitment ? 1 : 0);
    if (bi.bmm_commitment) w.raw(*bi.bmm_commitment);
    w.u32(uint32_t(bi.events.size()));
    for (auto& e : bi.events) {
        if (auto d = std::get_if<bt::mainchain::Deposit>(&e)) {
            w.u8(0);
            w.u64(d->sequence_number);
            w.raw(d->txid);
            w.u32(d->vout);
            w.bincode_bytes(d->address);
            w.u64(d->value_sats);
        } else {
            auto& b = std::get<bt::mainchain::WithdrawalBundleEvent>(e);
            w.u8(1);
            w.raw(b.m6id);
            w.u8(uint8_t(b.status));
            w.u8(b.sequence_number ? 1 : 0);
            if (b.sequence_number) w.u64(*b.sequence_number);
            w.bincode_bytes(b.transaction);
        }
    }
}

bt::mainchain::BlockInfo dec_block_info(Reader& r)
{
    bt::mainchain::BlockInfo bi;
    if (r.u8()) bi.bmm_commitment = r.array<32>();
    uint32_t n = r.u32();
    for (uint32_t i = 0; i < n; i++) {
        if (r.u8() == 0) {
            bt::mainchain::Deposit d;
            d.sequence_number = r.u64();
            d.txid = r.array<32>();
            d.vout = r.u32();
            d.address = r.bincode_bytes();
            d.value_sats = r.u64();
            bi.events.emplace_back(d);
        } else {
            bt::mainchain::WithdrawalBundleEvent b;
            b.m6id = r.array<32>();
            b.status = bt::mainchain::BundleStatus(r.u8());
            if (r.u8()) b.sequence_number = r.u64();
            b.transaction = r.bincode_bytes();
            bi.events.emplace_back(b);
        }
    }
    return bi;
}

static Bytes opt_key(const std::optional<Hash32>& h)
{
    Bytes k;
    if (h) {
        k.push_back(1);
        append(k, h->span());
    } else {
        k.push_back(0);
    }
    return k;
}

static std::vector<Hash32> dec_hash_list(const std::optional<Bytes>& v)
{
    std::vector<Hash32> r;
    if (!v) return r;
    for (size_t i = 0; i + 32 <= v->size(); i += 32) r.push_back(Hash32::from_span(ByteSpan(v->data() + i, 32)));
    return r;
}
static Bytes enc_hash_list(const std::vector<Hash32>& l)
{
    Bytes b;
    for (auto& h : l) append(b, h.span());
    return b;
}

// ------------------------------------------------------------------ side chain
std::optional<Header> Archive::header(const Txn& t, const Hash32& h) const
{
    auto v = t.get(A_HEADERS, h.span());
    if (!v) return std::nullopt;
    Reader r(*v);
    return de_header(r);
}

Header Archive::need_header(const Txn& t, const Hash32& h) const
{
    auto x = header(t, h);
    if (!x) throw ArchiveError("NoHeader " + bt::hex_encode(h));
    return *x;
}

std::optional<Body> Archive::body(const Txn& t, const Hash32& h) const
{
    auto v = t.get(A_BODIES, h.span());
    if (!v) return std::nullopt;
    Reader r(*v);
    return de_body(r);
}

std::optional<uint32_t> Archive::height(const Txn& t, const Hash32& h) const
{
    auto v = t.get(A_HEIGHT, h.span());
    if (!v) return std::nullopt;
    Reader r(*v);
    return r.u32();
}

uint32_t Archive::need_height(const Txn& t, const Hash32& h) const
{
    auto x = height(t, h);
    if (!x) throw ArchiveError("NoHeight " + bt::hex_encode(h));
    return *x;
}

bool Archive::invalid(const Txn& t, const Hash32& h) const { return t.get(A_INVALID, h.span()).has_value(); }

std::vector<Hash32> Archive::successors(const Txn& t, const std::optional<Hash32>& h) const { return dec_hash_list(t.get(A_SUCC, opt_key(h))); }

std::map<Hash32, BmmResult> Archive::bmm_results(const Txn& t, const Hash32& side) const
{
    std::map<Hash32, BmmResult> r;
    auto v = t.get(A_BMM, side.span());
    if (!v) return r;
    for (size_t i = 0; i + 33 <= v->size(); i += 33) r[Hash32::from_span(ByteSpan(v->data() + i, 32))] = BmmResult((*v)[i + 32]);
    return r;
}

void Archive::put_bmm_results(Txn& t, const Hash32& side, const std::map<Hash32, BmmResult>& r) const
{
    Bytes b;
    for (auto& [m, res] : r) {
        append(b, m.span());
        b.push_back(uint8_t(res));
    }
    t.put(A_BMM, side.span(), b);
}

Hash32 Archive::nth_ancestor(const Txn& t, Hash32 h, uint32_t n) const
{
    Hash32 orig = h;
    while (n > 0) {
        uint32_t ht = need_height(t, h);
        if (n > ht) throw ArchiveError("NoAncestor " + bt::hex_encode(orig));
        if (n == 1) return *need_header(t, h).prev_side_hash;
        uint32_t idx = 31 - uint32_t(__builtin_clz(n)) - 1; // ilog2(n) - 1
        auto exp = dec_hash_list(t.get(A_EXP_ANC, h.span()));
        if (idx >= exp.size()) throw ArchiveError("exponential ancestors missing");
        h = exp[idx];
        n -= 2u << idx;
    }
    return h;
}

bool Archive::is_descendant(const Txn& t, const Hash32& anc, const Hash32& desc) const
{
    if (anc == desc) return true;
    uint32_t ha = need_height(t, anc), hd = need_height(t, desc);
    if (ha > hd) return false;
    return anc == nth_ancestor(t, desc, hd - ha);
}

std::optional<Hash32> Archive::last_common_ancestor(const Txn& t, Hash32 a, Hash32 b) const
{
    uint32_t ha = need_height(t, a), hb = need_height(t, b);
    if (ha < hb) b = nth_ancestor(t, b, hb - ha);
    else if (ha > hb) {
        a = nth_ancestor(t, a, ha - hb);
        ha = hb;
    }
    if (a == b) return a;
    if (nth_ancestor(t, a, ha) != nth_ancestor(t, b, ha)) return std::nullopt;
    uint32_t lo = 1, hi = ha;
    while (lo < hi) {
        uint32_t mid = (lo + hi) / 2;
        if (nth_ancestor(t, a, mid) == nth_ancestor(t, b, mid)) hi = mid;
        else lo = mid + 1;
    }
    return nth_ancestor(t, a, hi);
}

std::vector<Hash32> Archive::block_locator(const Txn& t, const Hash32& h) const
{
    auto hd = need_header(t, h);
    auto res = dec_hash_list(t.get(A_EXP_ANC, h.span()));
    if (hd.prev_side_hash) res.insert(res.begin(), *hd.prev_side_hash);
    return res;
}

std::vector<Hash32> Archive::ancestors(const Txn& t, const Hash32& h) const
{
    std::vector<Hash32> r;
    std::optional<Hash32> cur = h;
    while (cur) {
        r.push_back(*cur);
        cur = need_header(t, *cur).prev_side_hash;
    }
    return r;
}

std::vector<Hash32> Archive::missing_bodies(const Txn& t, const Hash32& h, const std::optional<Hash32>& stop) const
{
    std::vector<Hash32> r;
    for (auto& a : ancestors(t, h)) {
        if (stop && a == *stop) break;
        if (!t.get(A_BODIES, a.span())) r.push_back(a);
    }
    std::reverse(r.begin(), r.end());
    return r;
}

std::map<Hash32, uint32_t> Archive::tx_inclusions(const Txn& t, const Hash32& txid) const
{
    std::map<Hash32, uint32_t> r;
    auto v = t.get(A_TX_INCL, txid.span());
    if (!v) return r;
    for (size_t i = 0; i + 36 <= v->size(); i += 36) {
        Reader rd(ByteSpan(v->data() + i + 32, 4));
        r[Hash32::from_span(ByteSpan(v->data() + i, 32))] = rd.u32();
    }
    return r;
}

// archive/mod.rs:886-1015
void Archive::put_header(Txn& t, const Header& h) const
{
    uint32_t ht = 0;
    if (h.prev_side_hash) {
        auto p = height(t, *h.prev_side_hash);
        if (!p) throw ArchiveError("InvalidPrevSideHash");
        ht = *p + 1;
    }
    Hash32 bh = h.hash();
    {
        Writer w;
        w.u32(ht);
        t.put(A_HEIGHT, bh.span(), w.buf);
        Writer hw;
        bincode(hw, h);
        t.put(A_HEADERS, bh.span(), hw.buf);
    }
    auto succ = successors(t, h.prev_side_hash);
    if (std::find(succ.begin(), succ.end(), bh) == succ.end()) succ.push_back(bh);
    t.put(A_SUCC, opt_key(h.prev_side_hash), enc_hash_list(succ));
    if (!t.get(A_SUCC, opt_key(bh))) t.put(A_SUCC, opt_key(bh), {});
    // exponential ancestors
    std::vector<Hash32> exp;
    if (ht >= 2) {
        exp.push_back(nth_ancestor(t, *h.prev_side_hash, 1));
        uint64_t depth = 4;
        while (uint64_t(ht) >= depth) {
            exp.push_back(nth_ancestor(t, exp.back(), uint32_t(depth / 2)));
            depth *= 2;
        }
    }
    t.put(A_EXP_ANC, bh.span(), enc_hash_list(exp));
    // BMM verifications against already-known main blocks (children of prev_main)
    auto results = bmm_results(t, bh);
    std::optional<std::map<Hash32, BmmResult>> parent_results;
    if (h.prev_side_hash) parent_results = bmm_results(t, *h.prev_side_hash);
    for (auto& mb : main_successors(t, h.prev_main_hash)) {
        auto info = main_block_info(t, mb);
        if (!info.bmm_commitment || *info.bmm_commitment != bh) {
            results[mb] = BmmResult::Failed;
            continue;
        }
        auto mh = need_main(t, mb);
        if (h.prev_main_hash != mh.prev) {
            results[mb] = BmmResult::Failed;
            continue;
        }
        if (!parent_results) {
            results[mb] = BmmResult::Verified;
            continue;
        }
        bool ok = false;
        for (auto& [pm, pr] : *parent_results)
            if (pr == BmmResult::Verified && is_main_descendant(t, pm, mb)) {
                ok = true;
                break;
            }
        results[mb] = ok ? BmmResult::Verified : BmmResult::Failed;
    }
    put_bmm_results(t, bh, results);
}

void Archive::put_body(Txn& t, const Hash32& h, const Body& b) const
{
    need_header(t, h);
    Writer w;
    bincode(w, b);
    t.put(A_BODIES, h.span(), w.buf);
    for (uint32_t i = 0; i < b.transactions.size(); i++) {
        Hash32 txid = b.transactions[i].txid();
        auto inc = tx_inclusions(t, txid);
        inc[h] = i;
        Bytes v;
        for (auto& [bh, idx] : inc) {
            append(v, bh.span());
            Writer iw;
            iw.u32(idx);
            append(v, iw.buf);
        }
        t.put(A_TX_INCL, txid.span(), v);
    }
}

void Archive::delete_body(Txn& t, const Hash32& h) const
{
    auto b = body(t, h);
    t.del(A_BODIES, h.span());
    if (!b) return;
    for (auto& tx : b->transactions) {
        Hash32 txid = tx.txid();
        auto inc = tx_inclusions(t, txid);
        inc.erase(h);
        Bytes v;
        for (auto& [bh, idx] : inc) {
            append(v, bh.span());
            Writer iw;
            iw.u32(idx);
            append(v, iw.buf);
        }
        if (v.empty()) t.del(A_TX_INCL, txid.span());
        else t.put(A_TX_INCL, txid.span(), v);
    }
}

void Archive::put_accumulator(Txn& t, const Hash32& h, const bt::utreexo::MemForest& f) const { t.put(A_ACC, h.span(), f.serialize()); }

std::optional<bt::utreexo::MemForest> Archive::accumulator(const Txn& t, const Hash32& h) const
{
    auto v = t.get(A_ACC, h.span());
    if (!v) return std::nullopt;
    return bt::utreexo::MemForest::deserialize(*v);
}

// archive/mod.rs:509-536: Verified result with the greatest total work
std::optional<Hash32> Archive::best_main_verification(const Txn& t, const Hash32& side) const
{
    std::optional<Hash32> best;
    U256 best_work;
    for (auto& [m, r] : bmm_results(t, side)) {
        if (r != BmmResult::Verified) continue;
        U256 w = total_work(t, m);
        if (!best || w >= best_work) { // max_by_key keeps the last maximum
            best = m;
            best_work = w;
        }
    }
    return best;
}

void Archive::mark_invalid(Txn& t, const Hash32& h) const
{
    std::vector<Hash32> stack{h};
    while (!stack.empty()) {
        Hash32 b = stack.back();
        stack.pop_back();
        auto hd = header(t, b);
        if (hd) {
            auto ps = successors(t, hd->prev_side_hash);
            ps.erase(std::remove(ps.begin(), ps.end(), b), ps.end());
            t.put(A_SUCC, opt_key(hd->prev_side_hash), enc_hash_list(ps));
        }
        t.del(A_HEADERS, b.span());
        t.put(A_INVALID, b.span(), {});
        for (auto& s : successors(t, b)) stack.push_back(s);
        t.del(A_SUCC, opt_key(b));
    }
}

// ------------------------------------------------------------------ mainchain
static Bytes enc_main(const MainHeader& m)
{
    Writer w;
    w.raw(m.prev);
    w.u32(m.height);
    w.raw(m.work.to_le());
    w.raw(m.total_work.to_le());
    w.raw(m.skip);
    return w.buf;
}

std::optional<MainHeader> Archive::main_header(const Txn& t, const Hash32& h) const
{
    auto v = t.get(A_MAIN_HDR, h.span());
    if (!v) return std::nullopt;
    Reader r(*v);
    MainHeader m;
    m.hash = h;
    m.prev = r.array<32>();
    m.height = r.u32();
    m.work = U256::from_le(r.array<32>());
    m.total_work = U256::from_le(r.array<32>());
    m.skip = r.array<32>();
    return m;
}

MainHeader Archive::need_main(const Txn& t, const Hash32& h) const
{
    auto m = main_header(t, h);
    if (!m) throw ArchiveError("NoMainHeaderInfo " + bt::hex_encode_rev(h.span()));
    return *m;
}

bt::mainchain::BlockInfo Archive::main_block_info(const Txn& t, const Hash32& h) const
{
    auto v = t.get(A_MAIN_INFO, h.span());
    if (!v) return {};
    Reader r(*v);
    return dec_block_info(r);
}

bool Archive::has_main_block_info(const Txn& t, const Hash32& h) const { return t.get(A_MAIN_INFO, h.span()).has_value(); }

U256 Archive::total_work(const Txn& t, const Hash32& main) const { return need_main(t, main).total_work; }

std::vector<Hash32> Archive::main_successors(const Txn& t, const Hash32& main) const { return dec_hash_list(t.get(A_MAIN_SUCC, main.span())); }

static uint32_t invert_lowest_one(uint32_t n) { return n & (n - 1); }
static uint32_t skip_height(uint32_t h)
{
    if (h < 2) return 0;
    return (h & 1) ? invert_lowest_one(invert_lowest_one(h - 1)) + 1 : invert_lowest_one(h);
}

Hash32 Archive::nth_main_ancestor(const Txn& t, Hash32 h, uint32_t n) const
{
    if (n == 0) return h;
    MainHeader cur = need_main(t, h);
    if (n > cur.height) throw ArchiveError("NoMainAncestor");
    uint32_t target = cur.height - n;
    while (cur.height > target) {
        uint32_t hs = skip_height(cur.height), hsp = skip_height(cur.height - 1);
        if (cur.height >= 2 && (hs == target || (hs > target && !(hsp + 2 < hs && hsp >= target)))) cur = need_main(t, cur.skip);
        else {
            if (cur.prev.is_zero()) throw ArchiveError("NoMainAncestor");
            cur = need_main(t, cur.prev);
        }
    }
    return cur.hash;
}

// archive/mod.rs:1077-1160
void Archive::put_main_header_info(Txn& t, const bt::mainchain::BlockHeaderInfo& hi) const
{
    MainHeader m;
    m.hash = hi.block_hash;
    m.prev = hi.prev_block_hash;
    m.work = U256::from_le(hi.work);
    if (hi.prev_block_hash.is_zero()) {
        m.height = 0;
        m.total_work = m.work;
    } else {
        auto p = main_header(t, hi.prev_block_hash);
        if (!p) throw ArchiveError("NoMainHeaderInfo (parent)");
        m.height = p->height + 1;
        m.total_work = p->total_work + m.work;
        uint32_t sh = skip_height(m.height);
        m.skip = sh == m.height - 1 ? p->hash : nth_main_ancestor(t, p->hash, p->height - sh);
    }
    t.put(A_MAIN_HDR, m.hash.span(), enc_main(m));
    auto s = main_successors(t, hi.prev_block_hash);
    if (std::find(s.begin(), s.end(), m.hash) == s.end()) s.push_back(m.hash);
    t.put(A_MAIN_SUCC, hi.prev_block_hash.span(), enc_hash_list(s));
}

// archive/mod.rs:1019-1075
void Archive::put_main_block_info(Txn& t, const Hash32& main, const bt::mainchain::BlockInfo& bi) const
{
    auto mh = need_main(t, main);
    Writer w;
    enc_block_info(w, bi);
    t.put(A_MAIN_INFO, main.span(), w.buf);
    if (!bi.bmm_commitment) return;
    auto hd = header(t, *bi.bmm_commitment);
    if (!hd) return;
    BmmResult res;
    if (hd->prev_main_hash != mh.prev) res = BmmResult::Failed;
    else if (hd->prev_side_hash) {
        bool ok = false;
        for (auto& [pm, pr] : bmm_results(t, *hd->prev_side_hash))
            if (pr == BmmResult::Verified && is_main_descendant(t, pm, main)) {
                ok = true;
                break;
            }
        res = ok ? BmmResult::Verified : BmmResult::Failed;
    } else {
        res = BmmResult::Verified;
    }
    auto r = bmm_results(t, *bi.bmm_commitment);
    r[main] = res;
    put_bmm_results(t, *bi.bmm_commitment, r);
}

bool Archive::is_main_descendant(const Txn& t, const Hash32& anc, const Hash32& desc) const
{
    if (anc == desc) return true;
    uint32_t ha = need_main(t, anc).height, hd = need_main(t, desc).height;
    if (ha > hd) return false;
    return anc == nth_main_ancestor(t, desc, hd - ha);
}

Hash32 Archive::last_common_main_ancestor(const Txn& t, Hash32 a, Hash32 b) const
{
    uint32_t ha = need_main(t, a).height, hb = need_main(t, b).height;
    if (ha < hb) b = nth_main_ancestor(t, b, hb - ha);
    else if (ha > hb) {
        a = nth_main_ancestor(t, a, ha - hb);
        ha = hb;
    }
    if (a == b) return a;
    uint32_t lo = 1, hi = ha;
    while (lo < hi) {
        uint32_t mid = (lo + hi) / 2;
        if (nth_main_ancestor(t, a, mid) == nth_main_ancestor(t, b, mid)) hi = mid;
        else lo = mid + 1;
    }
    return nth_main_ancestor(t, a, hi);
}

bool Archive::shared_mainchain_lineage(const Txn& t, Hash32 a, Hash32 b) const
{
    uint32_t ha = need_main(t, a).height, hb = need_main(t, b).height;
    if (ha < hb) b = nth_main_ancestor(t, b, hb - ha);
    else if (ha > hb) a = nth_main_ancestor(t, a, ha - hb);
    return a == b;
}

std::optional<std::pair<uint32_t, U256>> Archive::ancestor_before(const Txn& t, const Hash32& tip, const Hash32& main_ancestor, bool with_work) const
{
    uint32_t mah = need_main(t, main_ancestor).height;
    std::optional<Hash32> cur = tip;
    while (cur) {
        Header hd = need_header(t, *cur);
        if (is_main_descendant(t, hd.prev_main_hash, main_ancestor) && hd.prev_main_hash != main_ancestor) {
            uint32_t h = need_height(t, *cur);
            U256 w;
            if (with_work) {
                uint32_t mheight = need_main(t, hd.prev_main_hash).height + 1;
                Hash32 mb = nth_main_ancestor(t, main_ancestor, mah - mheight);
                w = total_work(t, mb);
            }
            return std::make_pair(h, w);
        }
        cur = hd.prev_side_hash;
    }
    return std::nullopt;
}

// archive/mod.rs:1435-1650
std::optional<TipRef> Archive::better_tip(const Txn& t, const TipRef& tip0, const TipRef& tip1) const
{
    if (tip0 == tip1) return std::nullopt;
    uint32_t h0 = need_height(t, tip0.block_hash), h1 = need_height(t, tip1.block_hash);
    if (h0 == 0 && h1 == 0) return std::nullopt; // the first genesis seen sticks
    if (h0 == 0) return tip1;
    if (h1 == 0) return tip0;
    U256 w0 = total_work(t, tip0.main_block_hash), w1 = total_work(t, tip1.main_block_hash);
    auto cw = w0 <=> w1;
    auto ch = h0 <=> h1;
    using std::strong_ordering;
    if ((cw <= 0) && ch < 0) return tip1;
    if ((cw >= 0) && ch > 0) return tip0;
    if (cw < 0 && ch == 0) // within one mainchain lineage prefer LOWER work
        return shared_mainchain_lineage(t, tip0.main_block_hash, tip1.main_block_hash) ? tip0 : tip1;
    if (cw > 0 && ch == 0) return !shared_mainchain_lineage(t, tip0.main_block_hash, tip1.main_block_hash) ? tip0 : tip1;
    if (cw < 0 && ch > 0) {
        Hash32 ma = last_common_main_ancestor(t, tip0.main_block_hash, tip1.main_block_hash);
        auto a0 = ancestor_before(t, tip0.block_hash, ma, false);
        std::optional<uint32_t> ah0 = a0 ? std::optional<uint32_t>(a0->first) : std::nullopt;
        if (ah0 >= std::optional<uint32_t>(h1)) return tip0;
        return tip1;
    }
    if (cw > 0 && ch < 0) {
        Hash32 ma = last_common_main_ancestor(t, tip0.main_block_hash, tip1.main_block_hash);
        auto a1 = ancestor_before(t, tip1.block_hash, ma, false);
        std::optional<uint32_t> ah1 = a1 ? std::optional<uint32_t>(a1->first) : std::nullopt;
        if (ah1 < std::optional<uint32_t>(h0)) return tip0;
        return tip1;
    }
    // equal work, equal height
    if (tip0.block_hash == tip1.block_hash) return tip0;
    Hash32 ma = last_common_main_ancestor(t, tip0.main_block_hash, tip1.main_block_hash);
    auto a0 = ancestor_before(t, tip0.block_hash, ma, true);
    auto a1 = ancestor_before(t, tip1.block_hash, ma, true);
    std::optional<U256> aw0 = a0 ? std::optional<U256>(a0->second) : std::nullopt;
    std::optional<U256> aw1 = a1 ? std::optional<U256>(a1->second) : std::nullopt;
    std::optional<uint32_t> ah0 = a0 ? std::optional<uint32_t>(a0->first) : std::nullopt;
    std::optional<uint32_t> ah1 = a1 ? std::optional<uint32_t>(a1->first) : std::nullopt;
    auto cwa = aw0 <=> aw1;
    auto cha = ah0 <=> ah1;
    if ((cwa <= 0 && cha == 0) || cha > 0) return tip0;
    return tip1;
}

} // namespace zside
