// Copyright (c) 2026 The Backbone developers
// Distributed under the MIT software license.
//
// `thunder-orchard-cli`: same subcommands and output as thunder-orchard's thunder_orchard_app_cli
// (cli/lib.rs), over the node's JSON-RPC.
#include <bt/jsonrpc.h>
#include <bt/parse.h>

#include <algorithm>
#include <cstdio>
#include <map>
#include <string>
#include <vector>

struct Spec {
    std::string rpc;
    std::vector<std::string> positional;              // positional CLI args, in RPC param order
    std::vector<std::pair<std::string, std::string>> flags; // --flag -> rpc param name
    enum Out { Pretty, Plain, Empty, Raw } out = Pretty;
    std::vector<std::string> param_order;             // full RPC param order
    std::vector<std::string> json_positional;         // positional args that are JSON
};

static std::map<std::string, Spec> specs()
{
    using S = Spec;
    std::map<std::string, Spec> m;
    m["balance"] = {"balance", {}, {}, S::Pretty, {}, {}};
    m["connect-block"] = {"connect_block", {"block", "main_block_hash"}, {}, S::Plain, {"block", "main_block_hash"}, {"block"}};
    m["connect-peer"] = {"connect_peer", {"addr"}, {}, S::Empty, {"addr"}, {}};
    m["create-deposit"] = {"create_deposit", {"address"}, {{"--value-sats", "value_sats"}, {"--fee-sats", "fee_sats"}}, S::Raw, {"address", "value_sats", "fee_sats"}, {}};
    m["create-shield"] = {"create_shield", {}, {{"--value-sats", "value_sats"}, {"--fee-sats", "fee_sats"}}, S::Raw, {"value_sats", "fee_sats"}, {}};
    m["create-shielded-transfer"] = {"create_shielded_transfer", {"dest"}, {{"--value-sats", "value_sats"}, {"--fee-sats", "fee_sats"}}, S::Raw, {"dest", "value_sats", "fee_sats"}, {}};
    m["create-transparent-transfer"] = {"create_transparent_transfer", {"dest"}, {{"--value-sats", "value_sats"}, {"--fee-sats", "fee_sats"}}, S::Raw, {"dest", "value_sats", "fee_sats"}, {}};
    m["create-unshield"] = {"create_unshield", {}, {{"--value-sats", "value_sats"}, {"--fee-sats", "fee_sats"}}, S::Raw, {"value_sats", "fee_sats"}, {}};
    m["create-withdrawal"] = {"create_withdrawal", {"mainchain_address"}, {{"--amount-sats", "amount_sats"}, {"--fee-sats", "fee_sats"}, {"--mainchain-fee-sats", "mainchain_fee_sats"}}, S::Raw, {"mainchain_address", "amount_sats", "fee_sats", "mainchain_fee_sats"}, {}};
    m["format-deposit-address"] = {"format_deposit_address", {"address"}, {}, S::Raw, {"address"}, {}};
    m["forget-peer"] = {"forget_peer", {"addr"}, {}, S::Empty, {"addr"}, {}};
    m["generate-mnemonic"] = {"generate_mnemonic", {}, {}, S::Raw, {}, {}};
    m["get-best-mainchain-block-hash"] = {"get_best_mainchain_block_hash", {}, {}, S::Pretty, {}, {}};
    m["get-best-sidechain-block-hash"] = {"get_best_sidechain_block_hash", {}, {}, S::Pretty, {}, {}};
    m["get-block"] = {"get_block", {"block_hash", "verbose"}, {}, S::Pretty, {"block_hash", "verbose"}, {"verbose"}};
    m["get-blockcount"] = {"getblockcount", {}, {}, S::Plain, {}, {}};
    m["get-block-hash"] = {"get_block_hash", {"height"}, {}, S::Pretty, {"height"}, {"height"}};
    m["get-block-template"] = {"get_block_template", {}, {}, S::Pretty, {}, {}};
    m["get-bmm-inclusions"] = {"get_bmm_inclusions", {"block_hash"}, {}, S::Pretty, {"block_hash"}, {}};
    m["get-new-shielded-address"] = {"get_new_shielded_address", {}, {}, S::Raw, {}, {}};
    m["get-new-transparent-address"] = {"get_new_transparent_address", {}, {}, S::Raw, {}, {}};
    m["get-shielded-wallet-addresses"] = {"get_shielded_wallet_addresses", {}, {}, S::Pretty, {}, {}};
    m["get-transaction"] = {"get_transaction", {"txid"}, {}, S::Pretty, {"txid"}, {}};
    m["get-transparent-wallet-addresses"] = {"get_transparent_wallet_addresses", {}, {}, S::Pretty, {}, {}};
    m["get-wallet-stxos"] = {"get_wallet_stxos", {}, {}, S::Pretty, {}, {}};
    m["get-wallet-stxos-unconfirmed"] = {"get_wallet_stxos_unconfirmed", {}, {}, S::Pretty, {}, {}};
    m["get-wallet-utxos"] = {"get_wallet_utxos", {}, {}, S::Pretty, {}, {}};
    m["get-wallet-utxos-unconfirmed"] = {"get_wallet_utxos_unconfirmed", {}, {}, S::Pretty, {}, {}};
    m["get-withdrawal-bundle"] = {"get_withdrawal_bundle", {"m6id"}, {}, S::Pretty, {"m6id"}, {}};
    m["invalidate-block"] = {"invalidate_block", {"block_hash"}, {}, S::Empty, {"block_hash"}, {}};
    m["latest-failed-withdrawal-bundle-height"] = {"latest_failed_withdrawal_bundle_height", {}, {}, S::Pretty, {}, {}};
    m["list-peers"] = {"list_peers", {}, {}, S::Pretty, {}, {}};
    m["list-utxos"] = {"list_utxos", {}, {}, S::Pretty, {}, {}};
    m["mine"] = {"mine", {}, {{"--fee-sats", "fee"}}, S::Empty, {"fee"}, {}};
    m["pending-withdrawal-bundle"] = {"pending_withdrawal_bundle", {}, {}, S::Pretty, {}, {}};
    m["openapi-schema"] = {"openapi_schema", {}, {}, S::Pretty, {}, {}};
    m["remove-from-mempool"] = {"remove_from_mempool", {"txid"}, {}, S::Empty, {"txid"}, {}};
    m["set-seed-from-mnemonic"] = {"set_seed_from_mnemonic", {"mnemonic"}, {}, S::Empty, {"mnemonic"}, {}};
    m["sidechain-wealth"] = {"sidechain_wealth", {}, {}, S::Plain, {}, {}};
    m["sign-transaction"] = {"sign_transaction", {"transaction", "broadcast"}, {}, S::Pretty, {"transaction", "broadcast"}, {"transaction", "broadcast"}};
    m["submit-transaction"] = {"submit_transaction", {"transaction"}, {}, S::Raw, {"transaction"}, {"transaction"}};
    m["stop"] = {"stop", {}, {}, S::Empty, {}, {}};
    return m;
}

// serde_json::to_string_pretty: as UniValue's write(2), but an empty array or object stays "[]" / "{}".
static std::string pretty(const UniValue& v)
{
    std::string s = v.write(2), o;
    for (size_t i = 0; i < s.size(); i++) {
        char c = s[i];
        o += c;
        if (c == '[' || c == '{') {
            size_t j = i + 1;
            if (j < s.size() && s[j] == '\n') {
                size_t k = j + 1;
                while (k < s.size() && s[k] == ' ') k++;
                if (k < s.size() && s[k] == (c == '[' ? ']' : '}')) {
                    o += s[k];
                    i = k;
                }
            }
        }
    }
    return o;
}

int main(int argc, char** argv)
{
    std::string url = "http://localhost:6098";
    int i = 1;
    for (; i < argc; i++) {
        std::string a = argv[i];
        if (a == "--rpc-url" && i + 1 < argc) url = argv[++i];
        else if (a.rfind("--rpc-url=", 0) == 0) url = a.substr(10);
        else if ((a == "--timeout") && i + 1 < argc) ++i;
        else if (a == "-v" || a == "--verbose") {
        } else break;
    }
    auto all = specs();
    if (i >= argc || std::string(argv[i]) == "--help" || std::string(argv[i]) == "help") {
        std::printf("Usage: thunder-orchard-cli [--rpc-url URL] <COMMAND>\n\nCommands:\n");
        for (auto& [k, _] : all) std::printf("  %s\n", k.c_str());
        return argc > i ? 0 : 2;
    }
    std::string cmd = argv[i++];
    // multi-address commands
    std::string host = "localhost";
    uint16_t port = 6098;
    {
        std::string r = url;
        if (r.rfind("http://", 0) == 0) r = r.substr(7);
        auto slash = r.find('/');
        if (slash != std::string::npos) r = r.substr(0, slash);
        auto hp = bt::split_hostport(r, uint16_t(80));
        if (!hp) {
            std::fprintf(stderr, "error: invalid --rpc-url\n");
            return 2;
        }
        host = hp->first;
        port = hp->second;
    }
    UniValue params(UniValue::VOBJ);
    Spec spec;
    if (cmd == "get-stxos" || cmd == "get-utxos") {
        spec = {cmd == "get-stxos" ? "get_stxos" : "get_utxos", {}, {}, Spec::Pretty, {}, {}};
        UniValue a(UniValue::VARR);
        for (; i < argc; i++) a.push_back(argv[i]);
        if (a.empty()) {
            std::fprintf(stderr, "error: the following required arguments were not provided: <ADDRESSES>...\n");
            return 2;
        }
        params.pushKV("addresses", a);
    } else {
        auto it = all.find(cmd);
        if (it == all.end()) {
            std::fprintf(stderr, "error: unrecognized subcommand '%s'\n", cmd.c_str());
            return 2;
        }
        spec = it->second;
        size_t pos = 0;
        for (; i < argc; i++) {
            std::string a = argv[i];
            bool matched = false;
            for (auto& [flag, name] : spec.flags)
                if (a == flag && i + 1 < argc) {
                    UniValue v;
                    v.read(argv[++i]);
                    params.pushKV(name, v);
                    matched = true;
                }
            if (matched) continue;
            if (pos >= spec.positional.size()) {
                std::fprintf(stderr, "error: unexpected argument '%s'\n", a.c_str());
                return 2;
            }
            const std::string& name = spec.positional[pos++];
            bool is_json = std::find(spec.json_positional.begin(), spec.json_positional.end(), name) != spec.json_positional.end();
            UniValue v;
            if (is_json) {
                if (!v.read(a)) {
                    std::fprintf(stderr, "error: invalid JSON for <%s>\n", name.c_str());
                    return 2;
                }
            } else {
                v = UniValue(a);
            }
            params.pushKV(name, v);
        }
    }
    std::string err;
    UniValue resp = bt::jsonrpc::call(host, port, spec.rpc, params, err);
    if (!err.empty()) {
        std::fprintf(stderr, "Error: %s\n", err.c_str());
        return 1;
    }
    if (!resp["error"].isNull()) {
        std::fprintf(stderr, "Error: %s\n", resp["error"]["message"].getValStr().c_str());
        return 1;
    }
    const UniValue& r = resp["result"];
    switch (spec.out) {
    case Spec::Pretty: std::printf("%s\n", pretty(r).c_str()); break;
    case Spec::Plain: std::printf("%s\n", r.isStr() ? r.get_str().c_str() : r.write().c_str()); break;
    case Spec::Raw: std::printf("%s\n", r.isStr() ? r.get_str().c_str() : r.write().c_str()); break;
    case Spec::Empty: std::printf("\n"); break;
    }
    return 0;
}
