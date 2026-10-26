// Copyright (c) 2026 The Backbone developers
// Distributed under the MIT software license.
//
// zSide's app layer (doc/app.md): what our app of zSide and the unified wallet need of this node, on the app RPC
// (bt/appui), beside the LayerTwo JSON-RPC, which it does not touch. It reads and acts through the same Node, Wallet
// and App the LayerTwo methods use: the LayerTwo reads are served as they are (the same handlers, the same JSON),
// every spend is a confirmed method (asked in the app's trusted dialog, bound to a one-time token), and the wallet's
// history (transparent and shielded), the shielded account and its memos, the explorer, the shielded pool, the peg,
// the link to the mainchain and the backup phrase are host methods of the pages.
#pragma once

#include <zside/app.h>

#include <bt/appui/dropin.h>
#include <bt/appui/host.h>
#include <bt/appui/rpcserver.h>
#include <bt/jsonrpc.h>

#include <array>
#include <memory>
#include <optional>
#include <string>

namespace zside {

/** A memo as the pages show it (ZIP 302): text (no memo: none), or the bytes of one that is not text, in hex. */
struct MemoView {
    std::optional<std::string> text;
    std::string hex; // when it is not text
    bool empty() const { return !text && hex.empty(); }
};
MemoView memo_view(const std::array<uint8_t, 512>& memo);

/** Why a memo text cannot be sent ("" when it can): at most 512 bytes, and what core says of free text shown in a trusted
 *  dialog (bt::appui::display_text_problem: valid UTF-8, no control, format or invisible character). */
std::string memo_problem(const std::string& text);
/** The 512 bytes of a memo text (ZIP 302: the text, zeros after it). */
std::array<uint8_t, 512> memo_bytes(const std::string& text);

class AppLayer {
public:
    /** `network`: the LayerTwo name of the network (betanet, regtest...). */
    AppLayer(App& app, std::string network, std::string datadir, bt::appui::AppOptions options);
    ~AppLayer();
    AppLayer(const AppLayer&) = delete;
    AppLayer& operator=(const AppLayer&) = delete;

    bool start(std::string& err);
    void stop();
    uint16_t port() const;

    /** The LayerTwo methods the pages read (the same handlers and JSON as the LayerTwo server's). */
    static const std::vector<std::string>& l2l_reads();
    /** Every method of the app RPC, host method and confirmed method: the pack's manifest is checked against it. */
    std::vector<std::string> app_methods() const;
    UniValue manifest() const;

    /** The host, for tests (webuihost without HTTP). */
    bt::appui::RemoteHost& host() { return *host_; }
    bt::appui::RpcServer& server() { return *server_; }

    /** The wallet's history (dropin.history): one row a transaction touching the wallet, transparent or shielded, newest first. */
    UniValue history(size_t limit);

private:
    struct Impl;
    std::unique_ptr<Impl> m_;
    std::unique_ptr<bt::appui::RpcServer> server_;
    std::unique_ptr<bt::appui::RemoteHost> host_;
};

} // namespace zside
