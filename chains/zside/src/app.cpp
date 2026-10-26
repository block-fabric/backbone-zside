// Copyright (c) 2026 The Backbone developers
// Distributed under the MIT software license.
#include <zside/app.h>
#include <zside/json.h>

#include <bt/hd.h>
#include <bt/log.h>

namespace zside {

using bt::jsonrpc::app_error;
using bt::jsonrpc::Params;
using bt::kv::Txn;

// app.rs:479-678. Roots are computed the way validation computes them (AccumulatorDiff),
// so a template we produce is always one our own validation accepts.
BlockTemplate App::build_block_template(std::optional<uint64_t> fee)
{
    auto tipr = node.enforcer().get_chain_tip();
    if (!bt::enforcer::ok(tipr)) throw app_error(bt::enforcer::err(tipr).what());
    Hash32 prev_main = bt::enforcer::val(tipr).block_hash;
    auto tip_hash = node.tip();
    std::optional<Hash32> prev_side;
    if (tip_hash) {
        if (!node.request_mainchain_ancestor_infos(prev_main)) throw app_error("RequestMainchainAncestorInfos failed");
        std::lock_guard<std::recursive_mutex> l(node.lock());
        Txn t(node.store());
        Header th = *node.archive().header(t, *tip_hash);
        Hash32 lcma = node.archive().last_common_main_ancestor(t, prev_main, th.prev_main_hash);
        if (lcma == th.prev_main_hash) prev_side = tip_hash;
        else {
            std::optional<Hash32> cur = tip_hash;
            while (cur) {
                Header h = *node.archive().header(t, *cur);
                if (h.prev_main_hash != lcma && node.archive().is_main_descendant(t, h.prev_main_hash, lcma)) {
                    prev_side = cur;
                    break;
                }
                cur = h.prev_side_hash;
            }
        }
    }
    BlockTemplate bt_;
    std::vector<std::pair<AuthorizedTransaction, std::vector<Output>>> txs;
    uint64_t tx_fees = 0;
    if (prev_side == tip_hash) {
        auto r = node.mempool_transactions(1000);
        txs = std::move(r.first);
        tx_fees = r.second;
        if (tx_fees) bt_.body.coinbase.outputs.push_back(Output{wallet.get_or_generate_last_transparent_address(), Content{Content::Value, tx_fees, 0, {}}});
    }
    std::vector<AuthorizedTransaction> ats;
    for (auto& [tx, _] : txs) ats.push_back(tx);
    bt_.body = Body::from_authorized(ats, bt_.body.coinbase);
    bt_.header.merkle_root = compute_merkle_root(bt_.body.coinbase, bt_.body.transactions);
    bt_.header.prev_side_hash = prev_side;
    bt_.header.prev_main_hash = prev_main;
    {
        std::lock_guard<std::recursive_mutex> l(node.lock());
        Txn t(node.store());
        bt::utreexo::MemForest acc;
        if (prev_side) {
            auto a = node.archive().accumulator(t, *prev_side);
            if (!a) throw app_error("missing accumulator");
            acc = *a;
        }
        AccumulatorDiff diff;
        Hash32 cbtxid = bt_.header.coinbase_txid();
        for (uint32_t v = 0; v < bt_.body.coinbase.outputs.size(); v++)
            diff.insert(bt::utreexo::NodeHash::some(pointed_output_hash(OutPoint{OutPoint::Coinbase, cbtxid, v}, bt_.body.coinbase.outputs[v])));
        for (auto& tx : bt_.body.transactions) {
            Hash32 txid = tx.txid();
            for (auto& [op, uh] : tx.inputs) diff.remove(bt::utreexo::NodeHash::some(uh));
            for (uint32_t v = 0; v < tx.outputs.size(); v++) diff.insert(bt::utreexo::NodeHash::some(pointed_output_hash(OutPoint{OutPoint::Regular, txid, v}, tx.outputs[v])));
        }
        std::vector<bt::utreexo::NodeHash> ins, dels;
        diff.split(ins, dels);
        if (auto e = acc.modify(ins, dels)) throw app_error("utreexo: " + *e);
        bt_.header.roots = acc.get_roots();
    }
    bt_.fees = tx_fees;
    bt_.bribe = fee ? *fee : (tx_fees ? tx_fees : EMPTY_BLOCK_BMM_BRIBE);
    return bt_;
}

// app.rs:703-760, miner.rs:60-149
void App::mine(std::optional<uint64_t> fee)
{
    auto tpl = build_block_template(fee);
    Hash32 h = tpl.header.hash();
    auto r = node.enforcer().create_bmm_critical_data_tx(tpl.bribe, 0, h, tpl.header.prev_main_hash);
    if (!bt::enforcer::ok(r)) throw app_error(bt::enforcer::err(r).what());
    LOG_INFO("attempt BMM: created TX: %s", bt::hex_encode_rev(bt::enforcer::val(r).span()).c_str());
    // confirm_bmm: only the first event of a new subscription is considered
    std::optional<Hash32> main_hash;
    std::atomic<bool> cancel{false};
    node.enforcer().subscribe_events(
        [&](const bt::enforcer::SubscribeEvent& ev) {
            if (ev.kind == bt::enforcer::SubscribeEvent::Connect && ev.info.bmm_commitment == h) main_hash = ev.header.block_hash;
            return false; // stop after the first event
        },
        &cancel);
    if (!main_hash) {
        LOG_DEBUG("confirm BMM: verification failed for %s", bt::hex_encode(h).c_str());
        return;
    }
    if (!node.submit_block(*main_hash, tpl.header, tpl.body)) LOG_WARN("mine: BMM not accepted as new tip");
}

bool App::connect_block(const Header& h, const Body& b, const Hash32& main_block_hash) { return node.submit_block(main_block_hash, h, b); }

Hash32 App::deposit(const Address& a, uint64_t value, uint64_t fee)
{
    auto r = node.enforcer().create_deposit_tx(a.to_base58(), value, fee);
    if (!bt::enforcer::ok(r)) throw app_error(bt::enforcer::err(r).what());
    return bt::enforcer::val(r);
}

// ------------------------------------------------------------------ RPC
static UniValue null_or(const std::optional<UniValue>& v) { return v ? *v : UniValue(); }

static std::set<Address> parse_addresses(const UniValue& v)
{
    std::set<Address> s;
    if (!v.isArray()) throw bt::jsonrpc::RpcError(-32602, "Invalid params");
    for (auto& a : v.getValues()) s.insert(json::parse_address(a));
    return s;
}

static UniValue openapi_schema()
{
    // Their utoipa document, byte for byte (MIT, thunder-orchard b225827); parsed once.
    static const UniValue doc = [] {
        UniValue d;
        if (!d.read(std::string_view{
#include "openapi_schema.inc"
            }))
            throw std::runtime_error("openapi_schema.inc does not parse");
        return d;
    }();
    return doc;
}

void register_rpc(bt::jsonrpc::Server& s, App& app, bool public_api, bool private_api)
{
    Node& n = app.node;
    Wallet& w = app.wallet;
    s.add("openapi_schema", {}, 0, [](const Params&) { return openapi_schema(); });
    s.add("get_block", {"block_hash", "verbose"}, 1, [&n](const Params& p) -> UniValue {
        Hash32 h = json::parse_hash(p[0]);
        bool verbose = p[1].isBool() && p[1].get_bool();
        auto hd = n.header(h);
        if (!hd) return UniValue();
        auto b = n.body(h);
        if (!b) throw app_error("missing body for " + bt::hex_encode(h));
        return json::block(*hd, *b, verbose);
    });
    if (public_api) {
        s.add("connect_block", {"block", "main_block_hash"}, 2, [&app](const Params& p) {
            json::require_struct(p[0], "Block", {"header", "body"});
            Header h = json::parse_header(p[0]["header"]);
            Body b = json::parse_body(p[0]["body"]);
            return UniValue(app.connect_block(h, b, json::parse_btc_hash(p[1])));
        });
        s.add("get_block_hash", {"height"}, 1, [&n](const Params& p) {
            uint64_t h = json::parse_u32(p[0]);
            auto r = h > UINT32_MAX ? std::nullopt : n.block_hash_at(uint32_t(h));
            return r ? json::hash(*r) : UniValue();
        });
        s.add("get_bmm_inclusions", {"block_hash"}, 1, [&n](const Params& p) {
            UniValue a(UniValue::VARR);
            for (auto& m : n.bmm_inclusions(json::parse_hash(p[0]))) a.push_back(json::btc_hash(m));
            return a;
        });
        s.add("get_best_mainchain_block_hash", {}, 0, [&n](const Params&) -> UniValue {
            auto t = n.tip();
            if (!t) return UniValue();
            auto m = n.best_main_verification(*t);
            if (!m) throw app_error("NoBmmResult");
            return json::btc_hash(*m);
        });
        s.add("get_best_sidechain_block_hash", {}, 0, [&n](const Params&) {
            auto t = n.tip();
            return t ? json::hash(*t) : UniValue();
        });
        s.add("get_stxos", {"addresses"}, 1, [&n](const Params& p) {
            UniValue a(UniValue::VARR);
            for (auto& [op, so] : n.stxos_by_addresses(parse_addresses(p[0]))) a.push_back(json::pointed_spent_output(op, so));
            return a;
        });
        s.add("get_transaction", {"txid"}, 1, [&n](const Params& p) -> UniValue {
            auto r = n.transaction(json::parse_hash(p[0]));
            if (!r) return UniValue();
            UniValue o(UniValue::VOBJ);
            o.pushKV("tx", json::transaction(r->first));
            o.pushKV("block_hash", r->second ? json::hash(*r->second) : UniValue());
            return o;
        });
        s.add("get_utxos", {"addresses"}, 1, [&n](const Params& p) {
            UniValue a(UniValue::VARR);
            for (auto& [op, o] : n.utxos_by_addresses(parse_addresses(p[0]))) a.push_back(json::pointed_output(op, o));
            return a;
        });
        s.add("get_withdrawal_bundle", {"m6id"}, 1, [&n](const Params& p) -> UniValue {
            auto r = n.withdrawal_bundle(json::parse_btc_hash(p[0]));
            if (!r) return UniValue();
            UniValue o(UniValue::VOBJ);
            o.pushKV("info", json::withdrawal_bundle_info(r->first));
            o.pushKV("status", to_string(r->second));
            return o;
        });
        s.add("getblockcount", {}, 0, [&n](const Params&) {
            auto h = n.height();
            return UniValue(uint64_t(h ? *h + 1 : 0));
        });
        s.add("latest_failed_withdrawal_bundle_height", {}, 0, [&n](const Params&) {
            auto h = n.latest_failed_withdrawal_bundle_height();
            return h ? UniValue(uint64_t(*h)) : UniValue();
        });
        s.add("list_peers", {}, 0, [&n](const Params&) {
            UniValue a(UniValue::VARR);
            for (auto& pv : n.peers()) {
                UniValue o(UniValue::VOBJ);
                o.pushKV("address", pv.address.to_string());
                o.pushKV("status", pv.connected ? "Connected" : "Connecting");
                a.push_back(o);
            }
            return a;
        });
        s.add("list_utxos", {}, 0, [&n](const Params&) {
            UniValue a(UniValue::VARR);
            for (auto& [op, o] : n.utxos()) a.push_back(json::pointed_output(op, o));
            return a;
        });
        s.add("pending_withdrawal_bundle", {}, 0, [&n](const Params&) {
            auto b = n.pending_withdrawal_bundle();
            return b ? json::withdrawal_bundle(*b) : UniValue();
        });
        s.add("sidechain_wealth", {}, 0, [&n](const Params&) { return UniValue(n.sidechain_wealth()); });
        s.add("submit_transaction", {"transaction"}, 1, [&n](const Params& p) {
            auto tx = json::parse_authorized_transaction(p[0]);
            n.submit_transaction(tx);
            return json::hash(tx.transaction.txid());
        });
    }
    if (private_api) {
        s.add("connect_peer", {"addr"}, 1, [&n](const Params& p) {
            std::string err;
            if (!p[0].isStr()) throw bt::jsonrpc::RpcError(-32602, "Invalid params");
            std::string a = p[0].get_str();
            if (a.rfind(':') == std::string::npos) a += ":" + std::to_string(net::DEFAULT_PORT);
            if (!n.connect_peer(a, err)) throw app_error(err);
            return UniValue();
        });
        s.add("forget_peer", {"addr"}, 1, [&n](const Params& p) {
            std::string a = p[0].getValStr();
            if (a.rfind(':') == std::string::npos) a += ":" + std::to_string(net::DEFAULT_PORT);
            n.forget_peer(a);
            return UniValue();
        });
        s.add("invalidate_block", {"block_hash"}, 1, [&n](const Params& p) {
            n.invalidate_block(json::parse_hash(p[0]));
            return UniValue();
        });
        s.add("remove_from_mempool", {"txid"}, 1, [&n](const Params& p) {
            n.remove_from_mempool(json::parse_hash(p[0]));
            return UniValue();
        });
        s.add("stop", {}, 0, [&app](const Params&) {
            if (app.on_stop) app.on_stop();
            return UniValue();
        });
        // wallet
        s.add("balance", {}, 0, [&w](const Params&) {
            auto b = w.balance(); // types/wallet.rs Balance field order
            UniValue o(UniValue::VOBJ);
            o.pushKV("total_shielded_sats", UniValue(b.total_shielded));
            o.pushKV("total_transparent_sats", UniValue(b.total_transparent));
            o.pushKV("available_shielded_sats", UniValue(b.available_shielded));
            o.pushKV("available_transparent_sats", UniValue(b.available_transparent));
            return o;
        });
        s.add("create_deposit", {"address", "value_sats", "fee_sats"}, 3, [&app](const Params& p) {
            return json::btc_hash(app.deposit(json::parse_address(p[0]), json::parse_u64(p[1]), json::parse_u64(p[2])));
        });
        auto sign_and_send = [&n, &w](const Transaction& tx) {
            auto at = w.authorize(tx);
            n.submit_transaction(at);
            return json::hash(at.transaction.txid());
        };
        s.add("create_shield", {"value_sats", "fee_sats"}, 2, [&w, sign_and_send](const Params& p) {
            return sign_and_send(w.create_shield(json::parse_u64(p[0]), json::parse_u64(p[1])));
        });
        s.add("create_shielded_transfer", {"dest", "value_sats", "fee_sats"}, 3, [&w, sign_and_send](const Params& p) {
            return sign_and_send(w.create_shielded_transfer(json::parse_shielded_address(p[0]), json::parse_u64(p[1]), json::parse_u64(p[2])));
        });
        s.add("create_transparent_transfer", {"dest", "value_sats", "fee_sats"}, 3, [&w, sign_and_send](const Params& p) {
            return sign_and_send(w.create_transparent_transfer(json::parse_address(p[0]), json::parse_u64(p[1]), json::parse_u64(p[2])));
        });
        s.add("create_unshield", {"value_sats", "fee_sats"}, 2, [&w, sign_and_send](const Params& p) {
            return sign_and_send(w.create_unshield(json::parse_u64(p[0]), json::parse_u64(p[1])));
        });
        s.add("create_withdrawal", {"mainchain_address", "amount_sats", "fee_sats", "mainchain_fee_sats"}, 4, [&w, sign_and_send](const Params& p) {
            return sign_and_send(w.create_withdrawal(json::parse_btc_address(p[0]), json::parse_u64(p[1]), json::parse_u64(p[3]), json::parse_u64(p[2])));
        });
        s.add("format_deposit_address", {"address"}, 1, [](const Params& p) { return UniValue(json::parse_address(p[0]).format_for_deposit()); });
        s.add("generate_mnemonic", {}, 0, [](const Params&) { return UniValue(bt::hd::generate_mnemonic(12)); });
        s.add("get_block_template", {}, 0, [&app](const Params&) {
            auto t = app.build_block_template(std::nullopt);
            UniValue o(UniValue::VOBJ);
            o.pushKV("critical_hash", json::hash(t.header.hash()));
            o.pushKV("block", json::block(t.header, t.body));
            o.pushKV("fees_sats", UniValue(t.fees));
            return o;
        });
        s.add("get_new_shielded_address", {}, 0, [&w](const Params&) { return json::shielded_address(w.get_new_shielded_address()); });
        s.add("get_new_transparent_address", {}, 0, [&w](const Params&) { return json::address(w.get_new_transparent_address()); });
        s.add("get_shielded_wallet_addresses", {}, 0, [&w](const Params&) {
            UniValue a(UniValue::VARR);
            for (auto& x : w.shielded_addresses()) a.push_back(json::shielded_address(x));
            return a;
        });
        s.add("get_transparent_wallet_addresses", {}, 0, [&w](const Params&) {
            UniValue a(UniValue::VARR);
            for (auto& x : w.transparent_addresses()) a.push_back(json::address(x));
            return a;
        });
        s.add("get_wallet_utxos", {}, 0, [&w](const Params&) {
            UniValue a(UniValue::VARR);
            for (auto& [op, o] : w.utxos()) a.push_back(json::pointed_output(op, o));
            return a;
        });
        s.add("get_wallet_utxos_unconfirmed", {}, 0, [&w](const Params&) {
            UniValue a(UniValue::VARR);
            for (auto& [op, o] : w.utxos_unconfirmed()) a.push_back(json::pointed_output(op, o));
            return a;
        });
        // SpentOutput<PointedOutput>: {"output": {"outpoint", "output"}, "inpoint"}
        auto spent_pointed = [](const OutPoint& op, const SpentOutput& so) {
            UniValue o(UniValue::VOBJ);
            o.pushKV("output", json::pointed_output(op, so.output));
            o.pushKV("inpoint", json::spent_output(so)["inpoint"]);
            return o;
        };
        s.add("get_wallet_stxos", {}, 0, [&w, spent_pointed](const Params&) {
            UniValue a(UniValue::VARR);
            for (auto& [op, so] : w.stxos()) a.push_back(spent_pointed(op, so));
            return a;
        });
        s.add("get_wallet_stxos_unconfirmed", {}, 0, [&w, spent_pointed](const Params&) {
            UniValue a(UniValue::VARR);
            for (auto& [op, so] : w.stxos_unconfirmed()) a.push_back(spent_pointed(op, so));
            return a;
        });
        s.add("mine", {"fee"}, 0, [&app](const Params& p) {
            std::optional<uint64_t> fee;
            if (!p[0].isNull()) fee = json::parse_u64(p[0]);
            app.mine(fee);
            return UniValue();
        });
        s.add("set_seed_from_mnemonic", {"mnemonic"}, 1, [&w](const Params& p) {
            w.set_seed_from_mnemonic(p[0].getValStr());
            return UniValue();
        });
        s.add("sign_transaction", {"transaction", "broadcast"}, 1, [&n, &w](const Params& p) {
            auto at = w.authorize(json::parse_transaction(p[0]));
            if (p[1].isBool() && p[1].get_bool()) n.submit_transaction(at);
            return json::authorized_transaction(at);
        });
    }
}

} // namespace zside
