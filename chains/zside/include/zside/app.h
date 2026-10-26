// Copyright (c) 2026 The Backbone developers
// Distributed under the MIT software license.
//
// zSide application: node + wallet, block templates, BMM mining and deposits
// (thunder-rust app/app.rs), and the JSON-RPC surface (rpc-api/lib.rs, app/rpc_server.rs).
#pragma once

#include <zside/node.h>
#include <zside/wallet.h>

#include <bt/jsonrpc.h>

namespace zside {

struct BlockTemplate {
    uint64_t bribe = 0;
    Header header;
    Body body;
    uint64_t fees = 0;
};

class App {
public:
    App(Node& node, Wallet& wallet) : node(node), wallet(wallet) {}
    Node& node;
    Wallet& wallet;

    static constexpr uint64_t EMPTY_BLOCK_BMM_BRIBE = 1000; // app.rs:475
    BlockTemplate build_block_template(std::optional<uint64_t> fee);
    void mine(std::optional<uint64_t> fee);
    bool connect_block(const Header& h, const Body& b, const Hash32& main_block_hash);
    Hash32 deposit(const Address& a, uint64_t value, uint64_t fee);
    std::function<void()> on_stop;
};

/** Register the RPC methods; `public_only` = the public server when --private-rpc-addr differs. */
void register_rpc(bt::jsonrpc::Server& s, App& app, bool public_api, bool private_api);

} // namespace zside
