// zSide's app layer (doc/app.md): the LayerTwo JSON-RPC is the same with the app layer running (same methods, same
// bytes for every reply); the app RPC's reads are the LayerTwo handlers' own JSON; the backup phrase's flows (made, its
// words only in a question, restored, refused over another) and the unified wallet's phrase (BIP-85, zside), which is
// the whole wallet's (the Orchard spending key comes from its seed too); wallet ownership and the shielded account only
// for their readers; every spend's sum checked; memos (ZIP 302); the manifest of app/manifest.json is the node's.
#include "test.h"

#include <zside/app.h>
#include <zside/appui.h>

#include <bt/appui/auth.h>
#include <bt/appui/phrase.h>
#include <bt/frost.h>
#include <bt/hd.h>

#include <filesystem>
#include <functional>
#include <fstream>
#include <memory>

using namespace zside;

namespace {
struct Harness {
    std::string dir;
    std::unique_ptr<Node> node;
    std::unique_ptr<Wallet> wallet;
    std::unique_ptr<App> app;
    explicit Harness(const std::string& name)
    {
        bt::frost::init();
        dir = (std::filesystem::temp_directory_path() / ("bt-zside-appui-" + name + "-" + bt::appui::random_hex(6))).string();
        std::filesystem::create_directories(dir);
        NodeConfig cfg;
        cfg.datadir = dir;
        cfg.network = net::Network::Regtest;
        cfg.p2p = false;
        cfg.use_seeds = false;
        cfg.mainchain_grpc_url = "http://127.0.0.1:1";
        node = std::make_unique<Node>(cfg);
        std::string err;
        CHECK(node->start(err));
        wallet = std::make_unique<Wallet>(dir + "/backbone-wallet.sqlite", *node);
        app = std::make_unique<App>(*node, *wallet);
    }
    ~Harness()
    {
        app.reset();
        wallet.reset();
        if (node) node->stop();
        node.reset();
        std::error_code ec;
        std::filesystem::remove_all(dir, ec);
    }
};

std::string reply(bt::jsonrpc::Server& s, const std::string& method, const std::string& params)
{
    return s.handle(R"({"jsonrpc":"2.0","id":7,"method":")" + method + R"(","params":)" + params + "}");
}

UniValue host_call(AppLayer& layer, const std::string& user, const std::string& method, const std::string& params, const std::string& token = "")
{
    UniValue req{UniValue::VOBJ};
    req.pushKV("kind", "host");
    req.pushKV("method", method);
    UniValue p;
    CHECK(p.read(params));
    req.pushKV("params", p);
    return layer.host().run(req, token, "", UniValue{}, user);
}

bool refused(const std::function<void()>& f, const std::string& words = "")
{
    try {
        f();
    } catch (const std::exception& e) {
        if (!words.empty() && std::string{e.what()}.find(words) == std::string::npos) {
            std::fprintf(stderr, "  refused, but: %s\n", e.what());
            return false;
        }
        return true;
    }
    return false;
}

bt::appui::AppOptions options()
{
    bt::appui::AppOptions o;
    o.enabled = true;
    o.port = 0;
    // The app's user (a reader of both accounts), a reader of the chain only, the cookie unrestricted.
    o.whitelist = {"app:webuihost,describeconfirmation,webuievents,getblockchaininfo,getbalances,balance,get_transparent_wallet_addresses,"
                   "get_shielded_wallet_addresses,get_wallet_utxos,dropin.checkAddress,dropin.block,dropin.seed.status,dropin.seed.prepare,"
                   "dropin.seed.create,dropin.seed.restore,dropin.seed.show,create_transparent_transfer,create_shielded_transfer,get_block,"
                   "dropin.history,zside.shielded,zside.memos,zside.pool",
                   "chainonly:webuihost,getblockchaininfo,get_block,dropin.checkAddress,dropin.overview,balance,getblockcount"};
    o.whitelist_default = false;
    return o;
}

const std::string MASTER{"abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"};
} // namespace

TEST(appui_l2l_rpc_byte_identical_with_and_without_the_app_layer)
{
    Harness h("l2l");
    // Without the app layer: the LayerTwo server as main.cpp makes it.
    bt::jsonrpc::Server before;
    register_rpc(before, *h.app, true, true);
    // With it running (its own server, its pollers, its store) beside the same node and wallet.
    AppLayer layer(*h.app, "regtest", h.dir, options());
    std::string err;
    CHECK(layer.start(err));
    bt::jsonrpc::Server after;
    register_rpc(after, *h.app, true, true);
    CHECK(before.methods() == after.methods());
    CHECK_EQ(before.methods().size(), size_t{44});
    // Every method, with no parameters, with wrong ones, and (the reads) with right ones: the same bytes.
    const std::vector<std::string> bad{"[]", "[1,2,3,4,5]", R"(["x"])", R"({"nope":1})", "[null]", R"([true,"x",-1])"};
    static const std::set<std::string> changes{"stop", "mine", "get_new_shielded_address", "get_new_transparent_address", "generate_mnemonic",
                                               "set_seed_from_mnemonic", "create_deposit", "create_shield", "create_shielded_transfer",
                                               "create_transparent_transfer", "create_unshield", "create_withdrawal", "connect_peer", "forget_peer",
                                               "invalidate_block", "remove_from_mempool", "submit_transaction", "connect_block", "get_block_template",
                                               "sign_transaction"};
    size_t compared{0};
    for (const std::string& m : before.methods()) {
        // What changes the node or the wallet runs once only (on `after`, after the comparison of its errors).
        for (const std::string& p : bad) {
            if (changes.contains(m) && (p == "[]" || p == "[null]")) continue;
            // A fresh phrase each call (it ignores its parameters): the same form, not the same words.
            if (m == "generate_mnemonic") {
                UniValue a, b;
                CHECK(a.read(reply(before, m, p)));
                CHECK(b.read(reply(after, m, p)));
                CHECK(a["result"].isStr() && b["result"].isStr() && a.getKeys() == b.getKeys());
                continue;
            }
            const std::string a{reply(before, m, p)}, b{reply(after, m, p)};
            if (a != b) std::fprintf(stderr, "  %s %s:\n    %s\n    %s\n", m.c_str(), p.c_str(), a.c_str(), b.c_str());
            CHECK(a == b);
            ++compared;
        }
    }
    CHECK(compared > 200);
    const std::vector<std::pair<std::string, std::string>> reads{
        {"getblockcount", "[]"}, {"get_best_sidechain_block_hash", "[]"}, {"list_utxos", "[]"}, {"list_peers", "[]"}, {"pending_withdrawal_bundle", "[]"},
        {"sidechain_wealth", "[]"}, {"balance", "[]"}, {"get_transparent_wallet_addresses", "[]"}, {"get_shielded_wallet_addresses", "[]"},
        {"get_wallet_utxos", "[]"}, {"get_wallet_stxos", "[]"}, {"get_wallet_utxos_unconfirmed", "[]"}, {"get_wallet_stxos_unconfirmed", "[]"},
        {"openapi_schema", "[]"}, {"latest_failed_withdrawal_bundle_height", "[]"}, {"get_block_hash", "[0]"},
        {"format_deposit_address", R"(["4XrMw8bmnhchFspSyP4XRUuB5vaR"])"}, {"get_utxos", R"([["4XrMw8bmnhchFspSyP4XRUuB5vaR"]])"},
        {"get_stxos", R"([["4XrMw8bmnhchFspSyP4XRUuB5vaR"]])"}, {"get_transaction", R"(["0000000000000000000000000000000000000000000000000000000000000000"])"},
        {"get_block", R"(["0000000000000000000000000000000000000000000000000000000000000000"])"},
        {"get_withdrawal_bundle", R"(["0000000000000000000000000000000000000000000000000000000000000000"])"},
        {"get_bmm_inclusions", R"(["0000000000000000000000000000000000000000000000000000000000000000"])"}, {"get_best_mainchain_block_hash", "[]"}};
    for (const auto& [m, p] : reads) CHECK(reply(before, m, p) == reply(after, m, p));
    // The app RPC's own read of a LayerTwo method answers its result, the same JSON; an error of theirs is an error of it.
    for (const auto& [m, p] : reads) {
        if (!layer.server().has(m)) continue; // the _unconfirmed reads: LayerTwo's only, not the pages'
        UniValue r;
        CHECK(r.read(reply(before, m, p)));
        bt::appui::Call c;
        c.method = m;
        CHECK(c.params.read(p));
        c.user = "__cookie__";
        if (!r.find_value("error").isNull()) {
            CHECK(refused([&] { layer.server().dispatch(c); }));
            continue;
        }
        CHECK_EQ(layer.server().dispatch(c).write(), r.find_value("result").write());
    }
    // A wallet now (the same with the layer): the wallet's reads and its addresses the same bytes too.
    h.wallet->set_seed_from_mnemonic(MASTER);
    for (const char* m : {"get_new_transparent_address", "get_new_shielded_address"}) {
        // Made on one server, read on both.
        CHECK(!reply(after, m, "[]").empty());
    }
    for (const char* m : {"balance", "get_transparent_wallet_addresses", "get_shielded_wallet_addresses", "get_wallet_utxos", "get_wallet_stxos"}) {
        CHECK(reply(before, m, "[]") == reply(after, m, "[]"));
    }
    layer.stop();
    // And once it stopped: the LayerTwo server as it was.
    for (const auto& [m, p] : reads) CHECK(reply(before, m, p) == reply(after, m, p));
}

TEST(appui_phrase_made_in_a_question_restored_refused_over_another)
{
    Harness h("seed");
    AppLayer layer(*h.app, "regtest", h.dir, options());
    std::string err;
    CHECK(layer.start(err));
    // Made: an id for the page, the words only in the question, the wallet set on the yes.
    const UniValue prep{host_call(layer, "app", "dropin.seed.prepare", "{}")["result"]};
    const std::string id{prep["id"].get_str()};
    CHECK(id.size() == 32);
    CHECK(!prep.exists("phrase") && !prep.exists("words_list"));
    const std::string create{"{\"id\":\"" + id + "\"}"};
    const UniValue q{host_call(layer, "app", "dropin.seed.create", create)["confirm"]};
    CHECK_EQ(q["kind"].get_str(), std::string{"phrase.create"});
    CHECK(q["details"].get_str().find(" 1. ") != std::string::npos);
    CHECK(!h.wallet->has_seed());
    const UniValue done{host_call(layer, "app", "dropin.seed.create", create, q["token"].get_str())["result"]};
    CHECK(h.wallet->has_seed());
    const std::string fp{done["fingerprint"].get_str()};
    const UniValue status{host_call(layer, "app", "dropin.seed.status", "{}")["result"]};
    CHECK_EQ(status["fingerprint"].get_str(), fp);
    CHECK(status["phraseKept"].isTrue());
    CHECK_EQ(status["from"].get_str(), std::string{"app"});
    CHECK_EQ(status["derivation"].get_str(), std::string{"v0.18.1"});
    // Shown again: a question, never a result with words.
    const UniValue shown{host_call(layer, "app", "dropin.seed.show", "{}")};
    CHECK(shown.exists("confirm") && !shown.exists("result"));
    // Another phrase over it: refused before any question.
    CHECK(refused([&] { host_call(layer, "app", "dropin.seed.restore", "{\"phrase\":\"" + MASTER + "\"}"); }));
    // The unified wallet's setup (its own user, the cookie): the same refusal over another phrase.
    bt::appui::Call c;
    c.method = "setwalletphrase";
    c.params = UniValue{UniValue::VARR};
    c.params.push_back(MASTER);
    c.user = "__cookie__";
    CHECK(refused([&] { layer.server().dispatch(c); }));
    // The app's user may not call it at all, nor the chain's reader.
    c.user = "app";
    CHECK(refused([&] { layer.server().dispatch(c); }));
    c.user = "chainonly";
    CHECK(refused([&] { layer.server().dispatch(c); }));
    layer.stop();
}

TEST(appui_unified_phrase_is_the_whole_wallets)
{
    // BIP-85 of the unified wallet's seed (sidechain/dropin/v1, zside), checked against an independent implementation
    // (Python, from BIP-85's own vector): the phrase and the fingerprint of each network.
    auto master{bt::hd::parse_mnemonic(MASTER)};
    const auto mseed{bt::hd::mnemonic_to_seed(*master)};
    CHECK_EQ(bt::appui::dropin_phrase_index("zside", "betanet"), uint32_t{859980934});
    CHECK_EQ(bt::appui::dropin_phrase_index("zside", "regtest"), uint32_t{2109803093});
    const std::string betanet{bt::appui::dropin_phrase(mseed.span(), "zside", "betanet")};
    const std::string regtest{bt::appui::dropin_phrase(mseed.span(), "zside", "regtest")};
    CHECK_EQ(betanet, std::string{"debate wedding craft path drip afraid special renew text wrong flag praise"});
    CHECK_EQ(regtest, std::string{"civil fox reject monitor clock vacant captain allow hood buffalo maze social"});
    CHECK_EQ(bt::appui::seed_fingerprint(bt::hd::mnemonic_to_seed(*bt::hd::parse_mnemonic(betanet)).span()), std::string{"879486a2c5decd21"});
    CHECK_EQ(bt::appui::seed_fingerprint(bt::hd::mnemonic_to_seed(*bt::hd::parse_mnemonic(regtest)).span()), std::string{"c6669596e00dd339"});

    Harness h("unified");
    AppLayer layer(*h.app, "regtest", h.dir, options());
    std::string err;
    CHECK(layer.start(err));
    bt::appui::Call c;
    c.method = "setwalletphrase";
    c.params = UniValue{UniValue::VARR};
    c.params.push_back(regtest);
    c.user = "__cookie__";
    CHECK_EQ(layer.server().dispatch(c)["fingerprint"].get_str(), std::string{"c6669596e00dd339"});
    bt::appui::Call info;
    info.method = "getwalletphraseinfo";
    info.user = "__cookie__";
    const UniValue i{layer.server().dispatch(info)};
    CHECK_EQ(i["fingerprint"].get_str(), std::string{"c6669596e00dd339"});
    CHECK_EQ(i["from"].get_str(), std::string{"unified"});
    CHECK(i["hasSeed"].isTrue());
    // The same phrase again: accepted (the same seed).
    CHECK_EQ(layer.server().dispatch(c)["fingerprint"].get_str(), std::string{"c6669596e00dd339"});
    // The whole wallet comes from it: the transparent keys and the Orchard spending key (a wallet given the phrase by
    // LayerTwo's set_seed_from_mnemonic has the same addresses of both kinds).
    Harness other("unified-other");
    other.wallet->set_seed_from_mnemonic(regtest);
    CHECK(h.wallet->get_new_transparent_address() == other.wallet->get_new_transparent_address());
    CHECK(h.wallet->get_new_shielded_address() == other.wallet->get_new_shielded_address());
    const auto seed{bt::hd::mnemonic_to_seed(*bt::hd::parse_mnemonic(regtest))};
    const auto fvk{Wallet::full_viewing_key(Wallet::orchard_spending_key(seed, KeyDerivation::Blake3))};
    CHECK(h.wallet->shielded_addresses().front() == Wallet::shielded_address(fvk, 0));
    // A bad phrase: tiny-bip39's words.
    bt::appui::Call bad{c};
    bad.params = UniValue{UniValue::VARR};
    bad.params.push_back("abandon abandon");
    CHECK(refused([&] { layer.server().dispatch(bad); }));
    layer.stop();
}

TEST(appui_wallet_and_shielded_account_only_for_their_readers)
{
    Harness h("mine");
    h.wallet->set_seed_from_mnemonic(MASTER);
    const std::string own{h.wallet->get_new_transparent_address().to_base58()};
    const std::string zown{h.wallet->get_new_shielded_address().to_string()};
    AppLayer layer(*h.app, "regtest", h.dir, options());
    std::string err;
    CHECK(layer.start(err));
    for (const std::string& a : {own, zown}) {
        const std::string p{"{\"address\":\"" + a + "\"}"};
        const UniValue reader{host_call(layer, "app", "dropin.checkAddress", p)["result"]};
        CHECK(reader["valid"].isTrue());
        CHECK(reader["mine"].isTrue());
        const UniValue chain_only{host_call(layer, "chainonly", "dropin.checkAddress", p)["result"]};
        CHECK(chain_only["valid"].isTrue());
        CHECK(!chain_only.exists("mine"));
        CHECK(!chain_only.exists("error"));
    }
    CHECK_EQ(host_call(layer, "app", "dropin.checkAddress", "{\"address\":\"" + zown + "\"}")["result"]["kind"].get_str(), std::string{"shielded"});
    // A formatted deposit address (it would burn: zSide credits only the bare address) is not a zSide address.
    const UniValue s98{host_call(layer, "app", "dropin.checkAddress", "{\"address\":\"" + h.wallet->transparent_addresses().front().format_for_deposit() + "\"}")["result"]};
    CHECK(s98["valid"].isFalse());
    // The deposit address the pages show is the bare address.
    // (dropin.newAddress needs get_new_transparent_address: the cookie.)
    const UniValue na{host_call(layer, "__cookie__", "dropin.newAddress", "{}")["result"]};
    CHECK_EQ(na["depositAddress"].get_str(), na["address"].get_str());
    // The shielded account, its memos, the history: refused to a reader of the chain only; the pool (the chain's) is not.
    CHECK(refused([&] { host_call(layer, "chainonly", "zside.shielded", "{}"); }));
    CHECK(refused([&] { host_call(layer, "chainonly", "zside.memos", "{}"); }));
    CHECK(refused([&] { host_call(layer, "chainonly", "dropin.history", "{}"); }));
    CHECK(refused([&] { host_call(layer, "chainonly", "zside.newShieldedAddress", "{}"); }));
    CHECK(host_call(layer, "app", "zside.pool", "{}")["result"].exists("root"));
    const UniValue z{host_call(layer, "app", "zside.shielded", "{}")["result"]};
    CHECK(z["hasSeed"].isTrue());
    CHECK_EQ(z["addresses"].size(), size_t{1});
    CHECK_EQ(z["balance"]["available"].getInt<int64_t>(), int64_t{0});
    // A spend the wallet cannot pay: refused before any question.
    CHECK(refused([&] { layer.host().describe("create_transparent_transfer", [] {
        UniValue a{UniValue::VARR};
        a.push_back("4XrMw8bmnhchFspSyP4XRUuB5vaR");
        a.push_back(1000);
        a.push_back(10);
        return a;
    }(), "app"); }, "Not enough"));
    CHECK(refused([&] {
        UniValue a{UniValue::VARR};
        a.push_back(zown);
        a.push_back(1000);
        a.push_back(10);
        layer.host().describe("create_shielded_transfer", a, "app");
    }, "Not enough in the shielded balance"));
    // An address of the other kind: said.
    CHECK(refused([&] {
        UniValue a{UniValue::VARR};
        a.push_back(own);
        a.push_back(1000);
        a.push_back(10);
        layer.host().describe("create_shielded_transfer", a, "app");
    }, "a transparent address, not a shielded one"));
    CHECK(refused([&] {
        UniValue a{UniValue::VARR};
        a.push_back(zown);
        a.push_back(1000);
        a.push_back(10);
        layer.host().describe("create_transparent_transfer", a, "app");
    }, "a shielded address, not a transparent one"));
    layer.stop();
}

TEST(appui_spends_refused_when_their_sum_wraps_or_passes_max_money)
{
    Harness h("overflow");
    h.wallet->set_seed_from_mnemonic(MASTER);
    const std::string zown{h.wallet->get_new_shielded_address().to_string()};
    AppLayer layer(*h.app, "regtest", h.dir, options());
    std::string err;
    CHECK(layer.start(err));
    const auto overflow{[&layer](const std::string& method, const std::string& params) {
        UniValue p;
        CHECK(p.read(params));
        try {
            layer.host().describe(method, p, "__cookie__"); // a caller of every spend
        } catch (const std::exception& e) {
            const bool ok{std::string{e.what()}.find("amount overflow") != std::string::npos};
            if (!ok) std::fprintf(stderr, "  %s %s: %s\n", method.c_str(), params.c_str(), e.what());
            return ok;
        }
        return false;
    }};
    // 2^63 + 2^63 + (2^63 + 1) wraps past the amount and still looks larger than it: refused before any question.
    CHECK(overflow("create_withdrawal", R"(["bcrt1qqypqxpq9qcrsszg2pvxq6rs0zqg3yyc5phstwt", 9223372036854775808, 9223372036854775808, 9223372036854775809])"));
    CHECK(overflow("create_withdrawal", R"(["bcrt1qqypqxpq9qcrsszg2pvxq6rs0zqg3yyc5phstwt", 18446744073709551606, 5, 20])"));
    CHECK(overflow("create_transparent_transfer", R"(["4XrMw8bmnhchFspSyP4XRUuB5vaR", 18446744073709551615, 1])"));
    CHECK(overflow("create_transparent_transfer", R"(["4XrMw8bmnhchFspSyP4XRUuB5vaR", 2100000000000001, 0])"));
    CHECK(overflow("create_shielded_transfer", "[\"" + zown + "\", 18446744073709551615, 1]"));
    CHECK(overflow("create_shielded_transfer", "[\"" + zown + "\", 2100000000000000, 1, \"a memo\"]"));
    CHECK(overflow("create_shield", "[18446744073709551615, 1]"));
    CHECK(overflow("create_shield", "[1, 2100000000000000]"));
    CHECK(overflow("create_unshield", "[9223372036854775808, 9223372036854775808]"));
    CHECK(overflow("create_deposit", R"(["4XrMw8bmnhchFspSyP4XRUuB5vaR", 18446744073709551615, 1000])"));
    CHECK(overflow("mine", "[2100000000000001]"));
    // Not a number of satoshis: refused before any question.
    UniValue neg;
    CHECK(neg.read(R"(["4XrMw8bmnhchFspSyP4XRUuB5vaR", -5, 1])"));
    CHECK(refused([&] { layer.host().describe("create_transparent_transfer", neg, "__cookie__"); }, "whole number"));
    layer.stop();
}

TEST(appui_memos_as_zip302_and_refused_when_not_one_line_of_text)
{
    std::array<uint8_t, 512> zeros{};
    CHECK(memo_view(zeros).empty());
    std::array<uint8_t, 512> none{};
    none[0] = 0xf6;
    CHECK(memo_view(none).empty());
    const MemoView text{memo_view(memo_bytes("Thanks for lunch"))};
    CHECK(text.text && *text.text == "Thanks for lunch");
    std::array<uint8_t, 512> binary{};
    binary[0] = 0xff;
    binary[1] = 0x01;
    const MemoView bin{memo_view(binary)};
    CHECK(!bin.text && bin.hex == "ff01");
    std::array<uint8_t, 512> bad_utf8{};
    bad_utf8[0] = 'a';
    bad_utf8[1] = 0xc3;
    CHECK(!memo_view(bad_utf8).text && memo_view(bad_utf8).hex == "61c3");
    CHECK(memo_problem("Thanks for lunch \xf0\x9f\x8d\x9c").empty());
    CHECK(memo_problem(std::string(512, 'x')).empty());
    CHECK(!memo_problem(std::string(513, 'x')).empty());
    CHECK(!memo_problem("two\nlines").empty());
    CHECK(!memo_problem("bell\x07").empty());
    CHECK(!memo_problem("\xc3").empty());
    CHECK(!memo_problem("turn \xe2\x80\xae it").empty()); // U+202E
    CHECK(!memo_problem("hidden \xe2\x80\x8b mark").empty()); // U+200B
    CHECK(!memo_problem("filler \xe3\x85\xa4 here").empty()); // U+3164, a default ignorable letter
    CHECK(!memo_problem("soft\xc2\xadhyphen").empty()); // U+00AD
    CHECK(!memo_problem("tag \xf3\xa0\x80\x81").empty()); // U+E0001

    Harness h("memo");
    h.wallet->set_seed_from_mnemonic(MASTER);
    const std::string zown{h.wallet->get_new_shielded_address().to_string()};
    AppLayer layer(*h.app, "regtest", h.dir, options());
    std::string err;
    CHECK(layer.start(err));
    // A memo that is not one line of text: refused before any question (before the balance is looked at).
    UniValue p{UniValue::VARR};
    p.push_back(zown);
    p.push_back(1000);
    p.push_back(10);
    p.push_back("two\nlines");
    CHECK(refused([&] { layer.host().describe("create_shielded_transfer", p, "__cookie__"); }, "No control, format or invisible character (U+000A)"));
    UniValue q{UniValue::VARR};
    q.push_back(zown);
    q.push_back(1000);
    q.push_back(10);
    q.push_back(5);
    CHECK(refused([&] { layer.host().describe("create_shielded_transfer", q, "__cookie__"); }, "memo"));
    layer.stop();
}

TEST(appui_manifest_is_the_nodes)
{
    Harness h("manifest");
    AppLayer layer(*h.app, "regtest", h.dir, options());
    std::string err;
    CHECK(layer.start(err));
    std::ifstream f(std::string{BT_SOURCE_DIR} + "/app/manifest.json");
    std::string text((std::istreambuf_iterator<char>(f)), std::istreambuf_iterator<char>());
    UniValue file;
    CHECK(file.read(text));
    const UniValue node{layer.manifest()};
    for (const char* group : {"reads", "confirmed", "host", "protocol"}) {
        std::set<std::string> a, b;
        for (const UniValue& v : file[group].getValues()) a.insert(v.get_str());
        for (const UniValue& v : node[group].getValues()) b.insert(v.get_str());
        if (a != b) std::fprintf(stderr, "  manifest %s differs\n", group);
        CHECK(a == b);
    }
    CHECK_EQ(file["program"].get_str(), std::string{"thunder-orchard"});
    CHECK_EQ(file["rpcPort"].getInt<int>(), int{net::DEFAULT_RPC_PORT});
    CHECK_EQ(file["p2pPort"].getInt<int>(), int{net::DEFAULT_PORT});
    // Every read and protocol method is served by the app RPC; every confirmed one is a LayerTwo method.
    for (const UniValue& v : file["reads"].getValues()) CHECK(layer.server().has(v.get_str()));
    for (const UniValue& v : file["protocol"].getValues()) CHECK(layer.server().has(v.get_str()));
    bt::jsonrpc::Server l2l;
    register_rpc(l2l, *h.app, true, true);
    const auto names{l2l.methods()};
    for (const UniValue& v : file["confirmed"].getValues()) CHECK(std::find(names.begin(), names.end(), v.get_str()) != names.end());
    layer.stop();
}
