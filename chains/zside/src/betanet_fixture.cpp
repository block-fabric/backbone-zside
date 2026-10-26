// Copyright (c) 2026 The Backbone developers
// Distributed under the MIT software license.
#include <univalue.h>

#include <zside/betanet_fixture.h>

#include <algorithm>
#include <cstring>
#include <fstream>
#include <sstream>

namespace zside::fixture {

using bt::mainchain::TwoWayPegData;

static std::string slurp(const std::string& p)
{
    std::ifstream f(p, std::ios::binary);
    std::ostringstream o;
    o << f.rdbuf();
    return o.str();
}

std::optional<Data> load(const std::string& dir, std::string& err)
{
    Data d;
    {
        std::istringstream in(slurp(dir + "/blocks.jsonl"));
        std::string line;
        while (std::getline(in, line)) {
            if (line.empty()) continue;
            UniValue v;
            if (!v.read(line)) { err = "bad blocks.jsonl line"; return std::nullopt; }
            IndexBlock b;
            b.height = uint32_t(v["height"].getInt<int64_t>());
            b.id = *bt::hex_to_array<32>(v["id"].get_str());
            b.merkle_root = *bt::hex_to_array<32>(v["merkle_root"].get_str());
            if (v["previousblockhash"].isStr()) b.prev = *bt::hex_to_array<32>(v["previousblockhash"].get_str());
            b.prev_main = *bt::hash_from_rev_hex(v["mainchain_blockhash"].get_str());
            b.main_height = uint32_t(v["mainchain_height"].getInt<int64_t>());
            b.fees = uint64_t(v["fees"].getInt<int64_t>());
            if (b.height != d.blocks.size()) { err = "blocks.jsonl not contiguous"; return std::nullopt; }
            d.blocks.push_back(b);
        }
    }
    if (std::ifstream(dir + "/txs.jsonl")) {
        std::istringstream in(slurp(dir + "/txs.jsonl"));
        std::string line;
        while (std::getline(in, line)) {
            if (line.empty()) continue;
            UniValue v;
            if (!v.read(line)) { err = "bad txs.jsonl"; return std::nullopt; }
            d.txs[uint32_t(v["height"].getInt<int64_t>())] = v["txs"].getValues();
        }
    }
    if (std::ifstream(dir + "/txhex.jsonl")) {
        std::istringstream in(slurp(dir + "/txhex.jsonl"));
        std::string line;
        while (std::getline(in, line)) {
            if (line.empty()) continue;
            UniValue v;
            if (!v.read(line)) { err = "bad txhex.jsonl"; return std::nullopt; }
            d.txhex[v["txid"].get_str()] = v["hex"].get_str();
        }
    }
    {
        UniValue v;
        if (!v.read(slurp(dir + "/twpd98.json"))) { err = "bad twpd98.json"; return std::nullopt; }
        const UniValue& arr = v.isArray() ? v : v["blocks"];
        for (auto& item : arr.getValues()) {
            auto hi = bt::mainchain::header_info_from_json(item["blockHeaderInfo"]);
            auto bi = bt::mainchain::block_info_from_json(item["blockInfo"]);
            if (!hi || !bi) { err = "bad twpd item"; return std::nullopt; }
            d.main_height_of[hi->block_hash] = hi->height;
            d.main_by_height[hi->height] = MainBlock{*hi, *bi};
        }
    }
    return d;
}

std::vector<std::pair<uint32_t, Bytes>> load_blocks_bin(const std::string& path)
{
    std::vector<std::pair<uint32_t, Bytes>> r;
    std::string all = slurp(path);
    size_t p = 0;
    while (p + 8 <= all.size()) {
        uint32_t h, n;
        std::memcpy(&h, all.data() + p, 4);
        std::memcpy(&n, all.data() + p + 4, 4);
        p += 8;
        if (p + n > all.size()) break;
        r.emplace_back(h, Bytes(all.begin() + p, all.begin() + p + n));
        p += n;
    }
    std::stable_sort(r.begin(), r.end(), [](auto& a, auto& b) { return a.first < b.first; });
    r.erase(std::unique(r.begin(), r.end(), [](auto& a, auto& b) { return a.first == b.first; }), r.end());
    return r;
}

FullReplayResult replay_full(const Data& d, const std::vector<std::pair<uint32_t, Bytes>>& blocks, State& st, bt::kv::Store& store,
                             std::vector<ReplayStep>* steps)
{
    FullReplayResult res;
    std::optional<uint32_t> prev_main_height;
    std::map<Hash32, uint32_t> bmm_at; // commitment -> mainchain height (first seen)
    for (auto& [h, mb] : d.main_by_height)
        if (mb.info.bmm_commitment) bmm_at.emplace(*mb.info.bmm_commitment, h);
    uint32_t expect = 0;
    for (auto& [height, raw] : blocks) {
        if (height != expect) { res.error = "non-contiguous block file at " + std::to_string(height); return res; }
        expect++;
        Block b;
        try {
            Reader r(raw);
            if (r.u32() != 0) { res.error = "not a Block response at " + std::to_string(height); return res; }
            b.header = de_header(r);
            b.body = de_body(r);
            if (!r.empty()) { res.error = "trailing bytes at " + std::to_string(height); return res; }
        } catch (const std::exception& e) {
            res.error = "decode at " + std::to_string(height) + ": " + e.what();
            return res;
        }
        Writer w;
        w.u32(0); // ResponseMessage::Block
        bincode(w, b);
        if (w.buf == raw) res.reencoded_exact++;
        Hash32 id = b.header.hash();
        if (height >= d.blocks.size()) { res.error = "block " + std::to_string(height) + " not in the index data"; return res; }
        Hash32 index_id = d.blocks[height].id;
        if (id != index_id) { res.error = "hash mismatch at " + std::to_string(height); return res; }
        res.hashes_match_index++;
        // BMM (archive/mod.rs:886-1015): the commitment to this header sits in the child of
        // prev_main_hash; the child's height minus one is prev_main's height.
        auto bh = bmm_at.find(id);
        if (bh == bmm_at.end()) { res.error = "no BMM commitment for height " + std::to_string(height); return res; }
        const MainBlock& bmm = d.main_by_height.at(bh->second);
        if (bmm.header.prev_block_hash != b.header.prev_main_hash) { res.error = "BMM block not a child of prev_main at " + std::to_string(height); return res; }
        res.bmm_verified++;
        uint32_t main_height = bh->second - 1;
        bt::kv::Txn txn(store);
        try {
            auto pre = st.prevalidate(txn, b.header, b.body); // every check enabled
            res.signatures += uint32_t(b.body.authorizations.size());
            for (auto& t : b.body.transactions) {
                if (!t.proof.targets.empty()) res.proofs++;
                if (t.orchard_bundle) {
                    res.orchard_bundles++;
                    res.orchard_actions += uint32_t(t.orchard_bundle->actions.size());
                    if (t.orchard_bundle->value_balance < 0) res.shields++;
                    else if (t.orchard_bundle->value_balance > 0) res.unshields++;
                    else res.shielded_transfers++;
                }
            }
            st.connect_prevalidated(txn, b.header, b.body, pre);
            TwoWayPegData win;
            for (auto& [h, mb] : d.main_by_height) {
                if (h > main_height) break;
                if (prev_main_height && h <= *prev_main_height) continue;
                for (auto& ev : mb.info.events)
                    if (std::holds_alternative<bt::mainchain::Deposit>(ev)) res.deposits++;
                win.block_info.emplace_back(mb.header.block_hash, mb.info);
            }
            st.connect_2wpd(txn, win);
            if (steps) steps->push_back(ReplayStep{b, win, st.accumulator(txn).serialize(), st.orchard_frontier(txn)});
        } catch (const StateError& e) {
            res.error = "height " + std::to_string(height) + ": " + e.what();
            return res;
        }
        txn.commit();
        prev_main_height = main_height;
        res.blocks++;
    }
    return res;
}

} // namespace zside::fixture
