// Copyright (c) 2026 The Backbone developers
// Distributed under the MIT software license.
//
// Public eCash betanet zSide (slot 98) data: every block as served over P2P by the public seed
// peers (zside-fetch-blocks), the seed index's block list (seed.beta.ecash.eu.com/zside) and
// the public enforcer's GetTwoWayPegData for slot 98; replayed through the state machine with
// every check.
#pragma once

#include <zside/state.h>

#include <bt/mainchain.h>

#include <univalue.h>

#include <map>
#include <string>
#include <vector>

namespace zside::fixture {

struct IndexBlock {
    uint32_t height = 0;
    Hash32 id;
    Hash32 merkle_root;
    std::optional<Hash32> prev;
    Hash32 prev_main; // internal order
    uint32_t main_height = 0;
    uint64_t fees = 0;
    std::vector<UniValue>* txs = nullptr;
};

struct MainBlock {
    bt::mainchain::BlockHeaderInfo header;
    bt::mainchain::BlockInfo info;
};

struct Data {
    std::vector<IndexBlock> blocks;            // by height
    std::map<uint32_t, std::vector<UniValue>> txs; // height -> esplora tx json
    std::map<std::string, std::string> txhex;  // txid -> borsh hex
    std::map<uint32_t, MainBlock> main_by_height; // enforcer 2WPD rows (blocks with BMM or events)
    std::map<Hash32, uint32_t> main_height_of;
};

/** Load blocks.jsonl, twpd98.json and (optional) txs.jsonl, txhex.jsonl from dir. */
std::optional<Data> load(const std::string& dir, std::string& err);

/** Full blocks as fetched from public peers (zside-fetch-blocks: u32 height, u32 len,
 *  bincode(ResponseMessage::Block)). */
std::vector<std::pair<uint32_t, Bytes>> load_blocks_bin(const std::string& path);

struct FullReplayResult {
    uint32_t blocks = 0;            // connected with every consensus check enabled
    uint32_t reencoded_exact = 0;   // bincode re-encoding identical to the bytes received
    uint32_t hashes_match_index = 0;
    uint32_t signatures = 0;        // FROST signatures verified
    uint32_t proofs = 0;            // non-empty Utreexo proofs verified
    uint32_t bmm_verified = 0;
    uint32_t deposits = 0;
    uint32_t orchard_bundles = 0, orchard_actions = 0; // halo2 proofs + signatures verified
    uint32_t shields = 0, shielded_transfers = 0, unshields = 0;
    std::string error;
};
struct ReplayStep {
    Block block;
    bt::mainchain::TwoWayPegData window;
    Bytes accumulator; // serialized forest after the block and its 2WPD
    Bytes frontier;    // Orchard note commitment frontier after the block
};
/** Replay real blocks with all checks (signatures, Utreexo proofs and roots, merkle, BMM). */
FullReplayResult replay_full(const Data& d, const std::vector<std::pair<uint32_t, Bytes>>& blocks, State& st, bt::kv::Store& store,
                             std::vector<ReplayStep>* steps = nullptr);

} // namespace zside::fixture
