// Copyright (c) 2026 The Backbone developers
// Distributed under the MIT software license.
#include <zside/appui.h>
#include <zside/json.h>

#include <bt/appui/phrase.h>
#include <bt/appui/text.h>
#include <bt/fsperm.h>
#include <bt/hd.h>
#include <bt/log.h>

#include <sodium.h>

#include <algorithm>
#include <cctype>
#include <set>

namespace zside {

using bt::appui::Confirmed;
using bt::appui::HostEnv;
using bt::appui::HostError;
using bt::appui::Question;
using bt::appui::Row;
using bt::appui::RpcError;

namespace {
const char* WALLET_NAME = "main";
/** The LayerTwo read that stands for knowing the wallet's transparent addresses: what tells a caller which outputs are
 *  the wallet's (wallet ownership, wallet.tx events). */
const char* WALLET_READ = "get_transparent_wallet_addresses";
/** The LayerTwo read that stands for the shielded account: its notes, memos and shielded addresses. */
const char* SHIELDED_READ = "get_shielded_wallet_addresses";
const char* VERSION_TEXT = "0.1.0 (thunder-orchard 0.18.1 compatible)";
/** What a shielded address looks like (Bech32m, HRP t-shld on every network). */
const char* SHIELDED_PREFIX = "t-shld1";

const UniValue NULLV;
const UniValue& param(const UniValue& p, const std::string& key) { return p.isObject() ? p.find_value(key) : NULLV; }

std::string str_param(const UniValue& p, const std::string& key)
{
    const UniValue& v{param(p, key)};
    if (!v.isStr()) throw HostError(bt::appui::HOST_INVALID_REQUEST, key + ": a string is needed");
    return v.get_str();
}

uint64_t u64_of(const UniValue& v, const std::string& what)
{
    if (!v.isNum()) throw HostError(bt::appui::HOST_INVALID_REQUEST, what + ": a whole number of satoshis is needed");
    const std::string s{v.getValStr()};
    if (s.empty() || s.find_first_not_of("0123456789") != std::string::npos) throw HostError(bt::appui::HOST_INVALID_REQUEST, what + ": a whole number of satoshis is needed");
    auto n{bt::parse_u64(s)};
    if (!n) throw HostError(bt::appui::HOST_INVALID_REQUEST, what + ": too large");
    return *n;
}

std::string coins(uint64_t sats) { return bt::appui::format_sats(sats) + " ECX"; }

std::string net_label(const std::string& network) { return network == "betanet" ? "" : network; }

/** Whether a mainchain address is of the mainchain network this node follows (betanet and forknet follow eCash's
 *  betanet, whose addresses are Bitcoin's main ones; regtest's are regtest ones, signet's test ones). */
bool main_address_of_network(const bt::btc::Address& a, const std::string& network)
{
    using A = bt::btc::Address;
    if (a.kind == A::Kind::Segwit) {
        if (network == "regtest") return a.hrp == A::Hrp::Regtest;
        if (network == "signet") return a.hrp == A::Hrp::Testnets;
        return a.hrp == A::Hrp::Mainnet;
    }
    if (network == "regtest" || network == "signet") return a.net == A::NetKind::Test;
    return a.net == A::NetKind::Main;
}

UniValue n64(uint64_t v) { return UniValue(v); }

/** Valid UTF-8; the code points, or nullopt. */
std::optional<std::vector<uint32_t>> utf8_points(std::string_view s)
{
    std::vector<uint32_t> out;
    for (size_t i{0}; i < s.size();) {
        const auto c{static_cast<unsigned char>(s[i])};
        uint32_t cp;
        size_t n;
        if (c < 0x80) {
            cp = c, n = 1;
        } else if ((c & 0xe0) == 0xc0) {
            cp = c & 0x1f, n = 2;
        } else if ((c & 0xf0) == 0xe0) {
            cp = c & 0x0f, n = 3;
        } else if ((c & 0xf8) == 0xf0) {
            cp = c & 0x07, n = 4;
        } else {
            return std::nullopt;
        }
        if (i + n > s.size()) return std::nullopt;
        for (size_t k{1}; k < n; ++k) {
            const auto d{static_cast<unsigned char>(s[i + k])};
            if ((d & 0xc0) != 0x80) return std::nullopt;
            cp = (cp << 6) | (d & 0x3f);
        }
        const bool overlong{(n == 2 && cp < 0x80) || (n == 3 && cp < 0x800) || (n == 4 && cp < 0x10000)};
        if (overlong || cp > 0x10ffff || (cp >= 0xd800 && cp <= 0xdfff)) return std::nullopt;
        out.push_back(cp);
        i += n;
    }
    return out;
}
} // namespace

std::string memo_problem(const std::string& text)
{
    if (text.size() > 512) return "A memo of at most 512 bytes";
    // Shown in the trusted dialog: core's rule for free text there (no control, format or invisible character).
    if (auto why{bt::appui::display_text_problem(text)}; !why.empty()) return "Memo: " + why;
    return {};
}

std::array<uint8_t, 512> memo_bytes(const std::string& text)
{
    std::array<uint8_t, 512> m{};
    std::memcpy(m.data(), text.data(), std::min<size_t>(text.size(), m.size()));
    return m;
}

MemoView memo_view(const std::array<uint8_t, 512>& memo)
{
    MemoView v;
    size_t end{memo.size()};
    while (end > 0 && memo[end - 1] == 0) --end;
    if (end == 0) return v;                    // all zeros: no memo (what LayerTwo's wallet writes)
    if (memo[0] == 0xf6 && end == 1) return v; // ZIP 302's "no memo"
    if (memo[0] <= 0xf4) {
        const std::string_view s{reinterpret_cast<const char*>(memo.data()), end};
        if (utf8_points(s)) {
            v.text = std::string{s};
            return v;
        }
    }
    v.hex = bt::hex_encode(bt::ByteSpan{memo.data(), end});
    return v;
}

struct AppLayer::Impl {
    App& app;
    Node& node;
    Wallet& wallet;
    std::string network, datadir;
    bt::appui::AppOptions options;
    bt::jsonrpc::Server l2l;
    std::unique_ptr<bt::appui::AppStore> store;
    std::unique_ptr<bt::appui::LinkMonitor> link;
    std::unique_ptr<bt::appui::Poller> poller;
    bt::appui::PendingPhrases phrases;
    std::chrono::system_clock::time_point started{std::chrono::system_clock::now()};

    Impl(App& a, std::string net, std::string dir, bt::appui::AppOptions o)
        : app(a), node(a.node), wallet(a.wallet), network(std::move(net)), datadir(std::move(dir)), options(std::move(o))
    {
        // Every LayerTwo method, on a server that does not listen: the reads the pages make and the spends run after
        // a yes go through the very handlers (and JSON) of the LayerTwo RPC.
        register_rpc(l2l, app, true, true);
    }

    /** One LayerTwo method, through its own handler: its result, or its error as an app RPC error. */
    UniValue l2l_call(const std::string& method, const UniValue& params)
    {
        UniValue req{UniValue::VOBJ};
        req.pushKV("jsonrpc", "2.0");
        req.pushKV("id", 1);
        req.pushKV("method", method);
        req.pushKV("params", params.isNull() ? UniValue{UniValue::VARR} : params);
        UniValue resp;
        if (!resp.read(l2l.handle(req.write())) || !resp.isObject()) throw RpcError(bt::appui::RPC_INTERNAL_ERROR, "no answer from " + method);
        const UniValue& err{resp.find_value("error")};
        if (err.isObject()) {
            const UniValue& data{err.find_value("data")};
            throw RpcError(err.find_value("code").isNum() ? err.find_value("code").getInt<int>() : -1,
                           err.find_value("message").getValStr() + (data.isStr() ? ": " + data.get_str() : std::string{}));
        }
        return resp.find_value("result");
    }

    std::set<Address> addresses()
    {
        auto a{wallet.transparent_addresses()};
        return {a.begin(), a.end()};
    }

    std::set<ShieldedAddress> shielded_addresses()
    {
        auto a{wallet.shielded_addresses()};
        return {a.begin(), a.end()};
    }

    std::optional<std::pair<uint32_t, Hash32>> block_of(const Hash32& block)
    {
        std::lock_guard<std::recursive_mutex> l(node.lock());
        bt::kv::Txn t(node.store());
        auto h{node.archive().height(t, block)};
        auto hd{node.archive().header(t, block)};
        if (!h || !hd) return std::nullopt;
        return std::make_pair(*h, hd->prev_main_hash);
    }

    std::optional<uint64_t> main_time(const Hash32& main) { return link ? link->block_time(main) : std::nullopt; }

    std::optional<std::pair<Hash32, std::optional<uint32_t>>> followed()
    {
        auto tip{node.tip()};
        if (!tip) return std::nullopt;
        auto hd{node.header(*tip)};
        if (!hd) return std::nullopt;
        return std::make_pair(hd->prev_main_hash, link ? link->block_height(hd->prev_main_hash) : std::nullopt);
    }

    // ---------------------------------------------------------- the shielded account (cached: a scan of the chain)
    struct ViewCache {
        std::optional<Hash32> tip;
        std::vector<Hash32> mempool;
        std::string wallet;
        std::shared_ptr<const ShieldedView> view;
    };
    std::mutex view_mu;
    ViewCache view_cache;

    std::vector<Hash32> mempool_ids()
    {
        std::vector<Hash32> ids;
        for (const auto& at : node.mempool()) ids.push_back(at.transaction.txid());
        std::sort(ids.begin(), ids.end());
        return ids;
    }

    /** The wallet's shielded account, read again only when the tip, the mempool or the wallet changed. */
    std::shared_ptr<const ShieldedView> shielded()
    {
        const auto tip{node.tip()};
        auto ids{mempool_ids()};
        const std::string w{wallet_id()};
        {
            std::lock_guard<std::mutex> l(view_mu);
            if (view_cache.view && view_cache.tip == tip && view_cache.mempool == ids && view_cache.wallet == w) return view_cache.view;
        }
        auto v{std::make_shared<const ShieldedView>(wallet.shielded_view())};
        std::lock_guard<std::mutex> l(view_mu);
        view_cache = ViewCache{tip, std::move(ids), w, v};
        return v;
    }

    // ---------------------------------------------------------- wallet
    struct Balances {
        uint64_t available{0}, withdrawing{0}, pending_in{0}, pending_out{0};
        uint64_t shielded_available{0}, shielded_total{0}, shielded_spendable{0}, shielded_pending_in{0};
    };

    Balances balances(const std::set<Address>& mine)
    {
        Balances b;
        std::set<OutPoint> spent_pending;
        auto [txs, fees] = node.mempool_transactions(1000);
        (void)fees;
        for (auto& [atx, spent] : txs) {
            for (const auto& [op, uh] : atx.transaction.inputs) spent_pending.insert(op);
            for (const Output& s : spent) {
                if (mine.contains(s.address)) b.pending_out += s.get_value();
            }
            for (const Output& o : atx.transaction.outputs) {
                if (mine.contains(o.address) && o.content.kind == Content::Value) b.pending_in += o.get_value();
            }
        }
        // As LayerTwo's balance: a coin a mempool transaction spends is not available.
        for (auto& [op, o] : node.utxos_by_addresses(mine)) {
            if (o.content.kind == Content::Withdrawal) b.withdrawing += o.get_value();
            else if (!spent_pending.contains(op)) b.available += o.get_value();
        }
        if (wallet.has_seed()) {
            auto v{shielded()};
            b.shielded_available = v->available;
            b.shielded_total = v->total;
            b.shielded_spendable = v->spendable;
            b.shielded_pending_in = v->pending_in;
        }
        return b;
    }

    std::string wallet_id()
    {
        // The fingerprint of the seed, or none: a token for one wallet is never taken for another.
        return seed_fingerprint();
    }

    /** bt::appui::seed_fingerprint of the wallet's seed (the same definition), "" without one. */
    std::string seed_fingerprint()
    {
        auto d{wallet.seed_digest("sidechain/dropin/fingerprint/v1")};
        return d ? bt::hex_encode(bt::ByteSpan{d->data(), 8}) : std::string{};
    }

    std::string derivation() { return wallet.derivation() == KeyDerivation::Hmac ? "v0.18.0" : "v0.18.1"; }

    /** Set the wallet's seed from a phrase checked before; the phrase kept for the backup (owner-only store). */
    UniValue set_phrase(const std::string& phrase, const std::string& from)
    {
        auto p{bt::hd::parse_mnemonic(phrase)};
        if (!p) throw HostError(bt::hd::mnemonic_error(phrase));
        const bt::appui::WipeOnExit wipe_parsed{*p};
        auto seed{bt::hd::mnemonic_to_seed(*p)};
        const std::string fp{bt::appui::seed_fingerprint(seed.span())};
        try {
            wallet.set_seed(seed);
        } catch (const std::exception& e) {
            sodium_memzero(seed.data(), seed.size());
            throw HostError(bt::appui::RPC_WALLET_ERROR, std::string{"This wallet has a backup phrase already ("} + e.what() + ")");
        }
        sodium_memzero(seed.data(), seed.size());
        store->put("phrase", *p);
        store->put("phrase.from", from);
        if (poller) poller->poke();
        UniValue out{UniValue::VOBJ};
        out.pushKV("fingerprint", fp);
        return out;
    }

    /** The phrase the app layer kept, only when it is the one of the wallet's seed now (a wallet file replaced since: none). */
    std::optional<std::string> kept_phrase()
    {
        auto phrase{store->get("phrase")};
        if (!phrase || !wallet.has_seed()) return std::nullopt;
        auto p{bt::hd::parse_mnemonic(*phrase)};
        if (!p) {
            sodium_memzero(phrase->data(), phrase->size());
            return std::nullopt;
        }
        auto seed{bt::hd::mnemonic_to_seed(*p)};
        sodium_memzero(p->data(), p->size());
        const bool same{bt::appui::seed_fingerprint(seed.span()) == seed_fingerprint()};
        sodium_memzero(seed.data(), seed.size());
        if (!same) {
            sodium_memzero(phrase->data(), phrase->size());
            return std::nullopt;
        }
        return phrase;
    }

    UniValue seed_status()
    {
        UniValue s{UniValue::VOBJ};
        const bool has{wallet.has_seed()};
        s.pushKV("hasSeed", has);
        s.pushKV("phraseKept", has && kept_phrase().has_value());
        s.pushKV("from", has ? store->get("phrase.from").value_or("outside") : "");
        s.pushKV("fingerprint", has ? seed_fingerprint() : "");
        s.pushKV("derivation", derivation());
        return s;
    }

    static std::string words_block(const std::string& phrase)
    {
        std::string out;
        size_t n{0}, at{0};
        while (at < phrase.size()) {
            size_t sp{phrase.find(' ', at)};
            if (sp == std::string::npos) sp = phrase.size();
            ++n;
            out += (n < 10 ? " " : "") + std::to_string(n) + ". " + phrase.substr(at, sp - at) + (n % 3 == 0 ? "\n" : "    ");
            at = sp + 1;
        }
        return out;
    }

    // ---------------------------------------------------------- history
    struct Hist {
        std::string id, kind;
        // Transparent: what the wallet received, spent (its value coins), sent into withdrawals.
        uint64_t received{0}, spent{0}, withdrawing{0};
        // Shielded: the wallet's notes the transaction made, and those it spent.
        uint64_t z_received{0}, z_spent{0};
        bool pending{false}, ours_in{false};
        size_t ours_in_count{0};
        std::optional<Hash32> txid, block, m6id;
        std::vector<std::pair<std::string, uint64_t>> to;   // transparent outputs to others
        std::vector<std::pair<std::string, uint64_t>> z_to; // shielded notes to others
        std::optional<int64_t> value_balance;
        std::optional<uint64_t> fee;
        std::string main_address;
        //! The wallet's address it paid (what a receipt was received at): transparent, or shielded.
        std::string own_address;
        std::optional<std::string> memo;
        std::string memo_hex;
        bool memo_sent{false};
        // A transaction of the mempool: its transparent inputs (all the wallet's?), their total and the outputs'.
        bool mp_all_ours{true};
        uint64_t mp_in{0}, mp_out{0};
        size_t mp_inputs{0};
    };

    std::string seen_key(const std::string& id) { return "seen:" + id; }

    std::optional<std::pair<int64_t, int64_t>> seen(const std::string& id)
    {
        auto v{store->get(seen_key(id))};
        if (!v) return std::nullopt;
        const size_t c{v->find(':')};
        if (c == std::string::npos) return std::nullopt;
        return std::make_pair(std::atoll(v->substr(0, c).c_str()), std::atoll(v->substr(c + 1).c_str()));
    }

    void note_seen(const std::string& id)
    {
        if (store->get(seen_key(id))) return;
        auto h{node.height()};
        const int64_t now{std::chrono::duration_cast<std::chrono::seconds>(std::chrono::system_clock::now().time_since_epoch()).count()};
        store->put(seen_key(id), std::to_string(h ? int64_t(*h) : int64_t{-1}) + ":" + std::to_string(now));
    }

    std::map<std::string, Hist> gather(const std::set<Address>& mine)
    {
        std::map<std::string, Hist> rows;
        auto row_of = [&](const OutPoint& op) -> Hist& {
            std::string id;
            std::string kind;
            if (op.kind == OutPoint::Deposit) {
                id = "deposit:" + bt::hex_encode_rev(op.txid.span());
                kind = "deposit";
            } else if (op.kind == OutPoint::Coinbase) {
                id = "coinbase:" + bt::hex_encode(op.txid);
                kind = "mined";
            } else {
                id = bt::hex_encode(op.txid);
            }
            Hist& h{rows[id]};
            if (h.id.empty()) {
                h.id = id;
                h.kind = kind;
                if (op.kind == OutPoint::Regular) h.txid = op.txid;
            }
            return h;
        };
        auto credit = [&](const OutPoint& op, const Output& o) {
            Hist& h{row_of(op)};
            if (o.content.kind == Content::Withdrawal) {
                h.withdrawing += o.get_value();
                h.main_address = o.content.main_address.to_string();
            } else {
                h.received += o.get_value();
                if (h.own_address.empty()) h.own_address = o.address.to_base58();
            }
        };
        for (auto& [op, o] : node.utxos_by_addresses(mine)) credit(op, o);
        for (auto& [op, s] : node.stxos_by_addresses(mine)) {
            credit(op, s.output);
            std::string id;
            if (s.inpoint.kind == InPoint::Withdrawal) {
                id = "bundle:" + bt::hex_encode_rev(s.inpoint.id.span());
                Hist& h{rows[id]};
                if (h.id.empty()) {
                    h.id = id;
                    h.kind = "bundle";
                    h.m6id = s.inpoint.id;
                }
                // Our withdrawal paid out of the chain into a bundle: counted when it was asked for.
                if (s.output.content.kind == Content::Withdrawal) h.withdrawing += s.output.get_value();
                else h.spent += s.output.get_value();
                continue;
            }
            id = bt::hex_encode(s.inpoint.id);
            Hist& h{rows[id]};
            if (h.id.empty()) {
                h.id = id;
                h.txid = s.inpoint.id;
            }
            h.ours_in = true;
            ++h.ours_in_count;
            if (s.output.content.kind == Content::Value) h.spent += s.output.get_value();
        }
        // What waits in the mempool: our spends and what comes in.
        auto [txs, fees] = node.mempool_transactions(1000);
        (void)fees;
        for (auto& [atx, spent] : txs) {
            const Transaction& tx{atx.transaction};
            const Hash32 txid{tx.txid()};
            bool touches{false};
            for (const Output& s : spent) touches = touches || mine.contains(s.address);
            for (const Output& o : tx.outputs) touches = touches || mine.contains(o.address);
            if (!touches) continue;
            Hist& h{rows[bt::hex_encode(txid)]};
            h.id = bt::hex_encode(txid);
            h.txid = txid;
            h.pending = true;
            h.received = h.spent = h.withdrawing = 0;
            h.mp_in = h.mp_out = 0;
            h.mp_inputs = tx.inputs.size();
            h.mp_all_ours = true;
            for (const Output& s : spent) {
                h.mp_in += s.get_value();
                if (mine.contains(s.address)) {
                    h.ours_in = true;
                    if (s.content.kind == Content::Value) h.spent += s.get_value();
                } else {
                    h.mp_all_ours = false;
                }
            }
            h.to.clear();
            for (const Output& o : tx.outputs) {
                h.mp_out += o.get_value();
                if (mine.contains(o.address)) {
                    if (o.content.kind == Content::Withdrawal) {
                        h.withdrawing += o.get_value();
                        h.main_address = o.content.main_address.to_string();
                    } else {
                        h.received += o.get_value();
                        if (h.own_address.empty()) h.own_address = o.address.to_base58();
                    }
                } else {
                    h.to.emplace_back(o.address.to_base58(), o.get_value());
                }
            }
        }
        // The shielded account: the notes it got and sent (with their memos), what each transaction spent of it.
        if (wallet.has_seed()) {
            auto v{shielded()};
            auto row_tx = [&](const Hash32& txid) -> Hist& {
                const std::string id{bt::hex_encode(txid)};
                Hist& h{rows[id]};
                if (h.id.empty()) {
                    h.id = id;
                    h.txid = txid;
                    h.mp_all_ours = true;
                    h.mp_in = h.mp_out = 0;
                }
                return h;
            };
            for (const ShieldedNote& n : v->notes) {
                Hist& h{row_tx(n.txid)};
                if (!n.height) h.pending = true;
                const MemoView mv{memo_view(n.memo)};
                if (n.incoming) {
                    h.z_received += n.value;
                    if (!n.internal && h.own_address.empty()) h.own_address = n.address.to_string();
                    if (!n.internal && !mv.empty() && !h.memo && h.memo_hex.empty()) {
                        h.memo = mv.text;
                        h.memo_hex = mv.hex;
                    }
                } else {
                    h.z_to.emplace_back(n.address.to_string(), n.value);
                    if (!mv.empty()) {
                        h.memo = mv.text;
                        h.memo_hex = mv.hex;
                        h.memo_sent = true;
                    }
                }
            }
            for (const auto& [txid, value] : v->spent_by_tx) {
                Hist& h{row_tx(txid)};
                h.z_spent += value;
                h.ours_in = true;
                for (const ShieldedNote& n : v->notes) {
                    if (n.spent_in == txid && n.spent_pending) h.pending = true;
                }
            }
            for (const auto& [txid, vb] : v->value_balance) row_tx(txid).value_balance = vb;
        }
        return rows;
    }

    static int64_t delta_of(const Hist& h)
    {
        // Every part at most 21,000,000 ECX (each a sum of a wallet's coins): no wrap in an int64.
        return static_cast<int64_t>(h.received) - static_cast<int64_t>(h.spent) + static_cast<int64_t>(h.z_received) - static_cast<int64_t>(h.z_spent);
    }

    static std::string kind_of(const Hist& h)
    {
        if (!h.kind.empty()) return h.kind;
        if (h.withdrawing > 0) return "withdrawal";
        if (h.z_spent > 0 && !h.z_to.empty()) return "zsend";
        if (h.z_received > 0 && h.spent > 0 && h.to.empty() && h.z_to.empty() && h.z_spent == 0) return "shield";
        if (h.z_spent > 0 && h.received > 0 && h.to.empty() && h.z_to.empty()) return "unshield";
        if (h.z_received > 0 && !h.ours_in) return "zreceive";
        if (h.z_spent > 0) return "zself";
        if (!h.ours_in) return "receive";
        if (h.to.empty()) return "self";
        return "send";
    }

    UniValue history(size_t limit)
    {
        const auto mine{addresses()};
        auto rows{gather(mine)};
        struct Out {
            UniValue v;
            int64_t order_height;
            int64_t order_time;
        };
        std::vector<Out> list;
        for (auto& [id, h] : rows) {
            note_seen(id);
            std::optional<uint32_t> height;
            std::optional<uint64_t> time;
            std::string block_hex;
            // A transaction of a block: where, when (the time of the mainchain block it was merged-mined in), its other
            // outputs and its fee.
            if (h.txid && !h.pending) {
                if (auto t{node.transaction(*h.txid)}) {
                    if (t->second) {
                        block_hex = bt::hex_encode(*t->second);
                        if (auto b{block_of(*t->second)}) {
                            height = b->first;
                            time = main_time(b->second);
                        }
                    }
                    h.to.clear();
                    uint64_t out_total{0};
                    for (const Output& o : t->first.outputs) {
                        out_total += o.get_value();
                        if (!mine.contains(o.address)) h.to.emplace_back(o.address.to_base58(), o.get_value());
                    }
                    // Every input the wallet's (its transparent coins, its notes): the fee is what went in and did not
                    // come out (a bundle's value balance > 0 leaves the shielded pool).
                    const bool all_ours{h.ours_in && h.ours_in_count == t->first.inputs.size()};
                    if (all_ours) {
                        const int64_t vb{t->first.orchard_bundle ? t->first.orchard_bundle->value_balance : 0};
                        const int64_t f{static_cast<int64_t>(h.spent) + vb - static_cast<int64_t>(out_total)};
                        if (f >= 0) h.fee = static_cast<uint64_t>(f);
                    }
                }
            } else if (h.pending && h.ours_in && h.mp_all_ours) {
                const int64_t f{static_cast<int64_t>(h.mp_in) + h.value_balance.value_or(0) - static_cast<int64_t>(h.mp_out)};
                if (f >= 0 && (h.mp_inputs > 0 || h.z_spent > 0)) h.fee = static_cast<uint64_t>(f);
            }
            bool approx{false};
            if (!height || !time) {
                if (auto s{seen(id)}) {
                    if (!height && s->first >= 0) height = static_cast<uint32_t>(s->first);
                    if (!time) time = static_cast<uint64_t>(s->second);
                    approx = true;
                }
            }
            const std::string kind{kind_of(h)};
            UniValue o{UniValue::VOBJ};
            o.pushKV("id", id);
            o.pushKV("kind", kind);
            if (h.txid) o.pushKV("txid", bt::hex_encode(*h.txid));
            if (h.m6id) {
                o.pushKV("m6id", bt::hex_encode_rev(h.m6id->span()));
                if (auto b{node.withdrawal_bundle(*h.m6id)}) o.pushKV("bundleStatus", to_string(b->second));
            }
            o.pushKV("amount", delta_of(h));
            o.pushKV("received", n64(h.received + h.z_received));
            o.pushKV("sent", n64(h.spent + h.z_spent));
            if (h.withdrawing) o.pushKV("withdrawing", n64(h.withdrawing));
            if (!h.main_address.empty()) o.pushKV("mainAddress", h.main_address);
            if (!h.own_address.empty()) o.pushKV("ownAddress", h.own_address);
            if (h.fee) o.pushKV("fee", n64(*h.fee));
            UniValue to{UniValue::VARR};
            for (const auto* list_to : {&h.z_to, &h.to}) {
                for (auto& [a, v] : *list_to) {
                    if (to.size() >= 50) break;
                    UniValue t{UniValue::VOBJ};
                    t.pushKV("address", a);
                    t.pushKV("amount", n64(v));
                    to.push_back(t);
                }
            }
            o.pushKV("to", to);
            o.pushKV("recipients", static_cast<uint64_t>(h.to.size() + h.z_to.size()));
            // zSide's: the shielded part, a move between the balances, the memo (text anyone who paid chose: data).
            UniValue z{UniValue::VOBJ};
            z.pushKV("received", n64(h.z_received));
            z.pushKV("spent", n64(h.z_spent));
            if (h.value_balance) z.pushKV("valueBalance", *h.value_balance);
            o.pushKV("shielded", z);
            if (kind == "shield") o.pushKV("moved", n64(h.z_received));
            if (kind == "unshield") o.pushKV("moved", n64(h.received));
            if (h.memo) o.pushKV("memo", *h.memo);
            else if (!h.memo_hex.empty()) o.pushKV("memoHex", h.memo_hex);
            if (h.memo || !h.memo_hex.empty()) o.pushKV("memoSent", h.memo_sent);
            o.pushKV("pending", h.pending);
            o.pushKV("height", height ? UniValue(uint64_t(*height)) : UniValue{});
            o.pushKV("time", time ? UniValue(*time) : UniValue{});
            o.pushKV("approxTime", approx);
            if (!block_hex.empty()) o.pushKV("block", block_hex);
            list.push_back(Out{o, h.pending ? INT64_MAX : height ? int64_t(*height) : -1, time ? int64_t(*time) : 0});
        }
        std::sort(list.begin(), list.end(), [](const Out& a, const Out& b) {
            if (a.order_height != b.order_height) return a.order_height > b.order_height;
            if (a.order_time != b.order_time) return a.order_time > b.order_time;
            return a.v.find_value("id").get_str() < b.v.find_value("id").get_str();
        });
        UniValue out{UniValue::VARR};
        for (auto& o : list) {
            if (out.size() >= limit) break;
            out.push_back(std::move(o.v));
        }
        return out;
    }

    // ---------------------------------------------------------- the node as events
    bt::appui::NodeLook look()
    {
        bt::appui::NodeLook l;
        l.height = node.height();
        if (auto t{node.tip()}) {
            l.tip = bt::hex_encode(*t);
            if (auto hd{node.header(*t)}) {
                if (auto tm{main_time(hd->prev_main_hash)}) l.tip_time = *tm;
            }
        }
        // In step with eCash: as fresh as eCash's tip (blocks of this chain come only when merge-mined); behind it, as old
        // as what this chain last acted on.
        if (link && link->connected() && link->info().find_value("state").getValStr() == "ok") {
            if (auto tm{link->tip_time()}) l.tip_time = std::max(l.tip_time, *tm);
        }
        for (auto& p : node.peers()) l.connections += p.connected ? 1 : 0;
        l.wallet = wallet.has_seed();
        if (l.wallet) {
            const auto mine{addresses()};
            const Balances b{balances(mine)};
            // The wallet's worth to the kit's shell: both balances.
            l.trusted = b.available + b.shielded_available;
            l.pending = b.pending_in + b.shielded_pending_in;
            l.immature = b.withdrawing;
            for (auto& [id, h] : gather(mine)) {
                l.txs[id] = !h.pending;
                note_seen(id);
            }
        }
        if (link && !link->connected()) l.warnings.push_back("The mainchain interface does not answer: this chain cannot follow it.");
        return l;
    }

    UniValue info()
    {
        UniValue i{UniValue::VOBJ};
        i.pushKV("name", "zSide");
        i.pushKV("version", VERSION_TEXT);
        i.pushKV("bugreport", "https://github.com/block-fabric/backbone-zside/issues");
        i.pushKV("network", network);
        i.pushKV("networkLabel", net_label(network));
        i.pushKV("datadir", "");
        i.pushKV("blockSpacing", 600);
        if (auto h{node.height()}) i.pushKV("blockWeight", n64(body_size_limit(*h + 1)));
        i.pushKV("walletEnabled", true);
        i.pushKV("devtools", false);
        i.pushKV("language", "");
        i.pushKV("test", false);
        i.pushKV("platform", "other");
        i.pushKV("dropin", "zside");
        i.pushKV("slot", static_cast<int>(THIS_SIDECHAIN));
        return i;
    }

    // ---------------------------------------------------------- explorer
    static UniValue shielded_json(const OrchardBundle& b)
    {
        UniValue z{UniValue::VOBJ};
        z.pushKV("actions", static_cast<uint64_t>(b.actions.size()));
        z.pushKV("valueBalance", b.value_balance);
        z.pushKV("spends", b.spends_enabled());
        z.pushKV("outputs", (b.flags & 2) != 0);
        return z;
    }

    UniValue block_summary(uint32_t height, const Hash32& hash, const Header& hd, const Body& b)
    {
        UniValue o{UniValue::VOBJ};
        o.pushKV("height", static_cast<uint64_t>(height));
        o.pushKV("hash", bt::hex_encode(hash));
        o.pushKV("mainHash", bt::hex_encode_rev(hd.prev_main_hash.span()));
        if (auto t{main_time(hd.prev_main_hash)}) o.pushKV("time", *t);
        uint64_t fees{0};
        for (const Output& c : b.coinbase.outputs) fees += c.get_value();
        o.pushKV("txs", static_cast<uint64_t>(b.transactions.size()));
        o.pushKV("inputs", static_cast<uint64_t>(b.inputs_len()));
        size_t outs{0}, shielded{0}, actions{0};
        for (const auto& tx : b.transactions) {
            outs += tx.outputs.size();
            if (tx.orchard_bundle) {
                ++shielded;
                actions += tx.orchard_bundle->actions.size();
            }
        }
        o.pushKV("outputs", static_cast<uint64_t>(outs));
        o.pushKV("shieldedTxs", static_cast<uint64_t>(shielded));
        o.pushKV("actions", static_cast<uint64_t>(actions));
        o.pushKV("fees", n64(fees));
        o.pushKV("bytes", static_cast<uint64_t>(borsh_bytes(b).size()));
        o.pushKV("limit", n64(body_size_limit(height)));
        return o;
    }

    /** Which addresses are the wallet's, for a caller that may read the wallet's addresses; nothing for another (its chain
     *  reads must not tell it which outputs are the wallet's). */
    using Mine = std::optional<std::set<Address>>;
    Mine mine_for(HostEnv& env) { return env.may_call(WALLET_READ) ? Mine{addresses()} : std::nullopt; }

    UniValue output_json(const Output& o, const Mine& mine)
    {
        UniValue r{UniValue::VOBJ};
        r.pushKV("address", o.address.to_base58());
        r.pushKV("amount", n64(o.get_value()));
        r.pushKV("kind", o.content.kind == Content::Withdrawal ? "withdrawal" : "value");
        if (o.content.kind == Content::Withdrawal) {
            r.pushKV("mainAddress", o.content.main_address.to_string());
            r.pushKV("mainFee", n64(o.content.main_fee));
        }
        if (mine) r.pushKV("mine", mine->contains(o.address));
        return r;
    }

    std::optional<Hash32> parse_hash(const std::string& s)
    {
        auto b{bt::hex_to_array<32>(s)};
        if (!b) return std::nullopt;
        return Hash32{*b};
    }

    UniValue block_detail(const Hash32& hash, const Mine& mine)
    {
        auto hd{node.header(hash)};
        auto b{node.body(hash)};
        auto at{block_of(hash)};
        if (!hd || !b || !at) throw HostError("No such block");
        UniValue o{block_summary(at->first, hash, *hd, *b)};
        o.pushKV("prevHash", hd->prev_side_hash ? bt::hex_encode(*hd->prev_side_hash) : "");
        o.pushKV("merkleRoot", bt::hex_encode(hd->merkle_root));
        o.pushKV("onChain", node.block_hash_at(at->first) == hash);
        UniValue cb{UniValue::VARR};
        for (const Output& c : b->coinbase.outputs) cb.push_back(output_json(c, mine));
        o.pushKV("coinbase", cb);
        UniValue txs{UniValue::VARR};
        for (const auto& tx : b->transactions) {
            if (txs.size() >= 1000) break;
            UniValue t{UniValue::VOBJ};
            t.pushKV("txid", bt::hex_encode(tx.txid()));
            t.pushKV("inputs", static_cast<uint64_t>(tx.inputs.size()));
            UniValue outs{UniValue::VARR};
            for (const Output& out : tx.outputs) outs.push_back(output_json(out, mine));
            t.pushKV("outputs", outs);
            if (tx.orchard_bundle) t.pushKV("shielded", shielded_json(*tx.orchard_bundle));
            txs.push_back(t);
        }
        o.pushKV("transactions", txs);
        return o;
    }

    UniValue tx_detail(const Hash32& txid, const Mine& mine)
    {
        auto t{node.transaction(txid)};
        UniValue o{UniValue::VOBJ};
        o.pushKV("txid", bt::hex_encode(txid));
        if (!t) {
            // Waiting in the mempool?
            auto [txs, fees] = node.mempool_transactions(1000);
            (void)fees;
            for (auto& [atx, spent] : txs) {
                if (atx.transaction.txid() != txid) continue;
                o.pushKV("pending", true);
                UniValue ins{UniValue::VARR};
                uint64_t in_total{0}, out_total{0};
                for (const Output& s : spent) {
                    ins.push_back(output_json(s, mine));
                    in_total += s.get_value();
                }
                UniValue outs{UniValue::VARR};
                for (const Output& out : atx.transaction.outputs) {
                    outs.push_back(output_json(out, mine));
                    out_total += out.get_value();
                }
                o.pushKV("inputs", ins);
                o.pushKV("outputs", outs);
                const int64_t vb{atx.transaction.orchard_bundle ? atx.transaction.orchard_bundle->value_balance : 0};
                if (atx.transaction.orchard_bundle) o.pushKV("shielded", shielded_json(*atx.transaction.orchard_bundle));
                const int64_t f{static_cast<int64_t>(in_total) + vb - static_cast<int64_t>(out_total)};
                if (f >= 0) o.pushKV("fee", n64(static_cast<uint64_t>(f)));
                return o;
            }
            throw HostError("No such transaction");
        }
        o.pushKV("pending", false);
        if (t->second) {
            o.pushKV("block", bt::hex_encode(*t->second));
            if (auto b{block_of(*t->second)}) {
                o.pushKV("height", static_cast<uint64_t>(b->first));
                if (auto tm{main_time(b->second)}) o.pushKV("time", *tm);
                if (auto h{node.height()}) o.pushKV("confirmations", static_cast<uint64_t>(*h >= b->first ? *h - b->first + 1 : 0));
            }
        }
        UniValue ins{UniValue::VARR};
        for (const auto& [op, uh] : t->first.inputs) {
            UniValue i{UniValue::VOBJ};
            i.pushKV("outpoint", json::outpoint(op));
            ins.push_back(i);
        }
        UniValue outs{UniValue::VARR};
        for (const Output& out : t->first.outputs) outs.push_back(output_json(out, mine));
        o.pushKV("inputs", ins);
        o.pushKV("outputs", outs);
        if (t->first.orchard_bundle) o.pushKV("shielded", shielded_json(*t->first.orchard_bundle));
        return o;
    }

    UniValue address_detail(const Address& a, const Mine& mine)
    {
        const std::set<Address> one{a};
        uint64_t balance{0};
        UniValue utxos{UniValue::VARR};
        for (auto& [op, o] : node.utxos_by_addresses(one)) {
            balance += o.get_value();
            if (utxos.size() < 500) {
                UniValue u{output_json(o, mine)};
                u.pushKV("outpoint", json::outpoint(op));
                utxos.push_back(u);
            }
        }
        UniValue stxos{UniValue::VARR};
        for (auto& [op, s] : node.stxos_by_addresses(one)) {
            if (stxos.size() >= 500) break;
            UniValue u{output_json(s.output, mine)};
            u.pushKV("outpoint", json::outpoint(op));
            u.pushKV("spentBy", s.inpoint.kind == InPoint::Withdrawal ? "bundle:" + bt::hex_encode_rev(s.inpoint.id.span()) : bt::hex_encode(s.inpoint.id));
            stxos.push_back(u);
        }
        UniValue o{UniValue::VOBJ};
        o.pushKV("address", a.to_base58());
        if (mine) o.pushKV("mine", mine->contains(a));
        o.pushKV("balance", n64(balance));
        o.pushKV("utxos", utxos);
        o.pushKV("spent", stxos);
        // What a deposit from eCash must name: the bare address (zSide credits only that; the s98_… form burns).
        o.pushKV("depositAddress", a.to_base58());
        return o;
    }

    // ---------------------------------------------------------- the shielded pool (the chain's: no wallet data)
    struct PoolCache {
        std::optional<Hash32> tip;
        UniValue pool;
    };
    std::mutex pool_mu;
    PoolCache pool_cache;

    UniValue pool()
    {
        const auto tip{node.tip()};
        {
            std::lock_guard<std::mutex> l(pool_mu);
            if (!pool_cache.pool.isNull() && pool_cache.tip == tip) return pool_cache.pool;
        }
        uint64_t commitments{0}, bundles{0}, shields{0}, unshields{0}, private_only{0};
        int64_t pool_value{0};
        struct Recent {
            uint32_t height;
            Hash32 txid;
            size_t actions;
            int64_t vb;
            size_t t_in, t_out;
        };
        std::vector<Recent> recent;
        UniValue per_block{UniValue::VARR};
        if (auto h{node.height()}) {
            for (uint32_t height{0}; height <= *h; ++height) {
                auto hash{node.block_hash_at(height)};
                auto body{hash ? node.body(*hash) : std::nullopt};
                if (!body) break;
                size_t acts{0};
                for (const auto& tx : body->transactions) {
                    if (!tx.orchard_bundle) continue;
                    const auto& b{*tx.orchard_bundle};
                    ++bundles;
                    acts += b.actions.size();
                    commitments += b.actions.size();
                    pool_value -= b.value_balance;
                    if (b.value_balance < 0) ++shields;
                    else if (!tx.outputs.empty()) ++unshields;
                    else ++private_only;
                    recent.push_back(Recent{height, tx.txid(), b.actions.size(), b.value_balance, tx.inputs.size(), tx.outputs.size()});
                    if (recent.size() > 50) recent.erase(recent.begin());
                }
                if (*h - height < 60) {
                    UniValue r{UniValue::VOBJ};
                    r.pushKV("height", static_cast<uint64_t>(height));
                    r.pushKV("actions", static_cast<uint64_t>(acts));
                    per_block.push_back(r);
                }
            }
        }
        UniValue o{UniValue::VOBJ};
        {
            std::lock_guard<std::recursive_mutex> l(node.lock());
            bt::kv::Txn t(node.store());
            o.pushKV("root", bt::hex_encode(node.state().orchard_frontier_root(t)));
            o.pushKV("nullifiers", static_cast<uint64_t>(node.state().orchard_nullifiers(t).size()));
            o.pushKV("historicalRoots", static_cast<uint64_t>(node.state().orchard_historical_roots(t).size()));
        }
        o.pushKV("commitments", commitments);
        o.pushKV("bundles", bundles);
        o.pushKV("shields", shields);
        o.pushKV("unshields", unshields);
        o.pushKV("privateOnly", private_only);
        o.pushKV("value", pool_value);
        o.pushKV("wealth", n64(node.sidechain_wealth()));
        UniValue rec{UniValue::VARR};
        for (auto it{recent.rbegin()}; it != recent.rend(); ++it) {
            UniValue r{UniValue::VOBJ};
            r.pushKV("height", static_cast<uint64_t>(it->height));
            r.pushKV("txid", bt::hex_encode(it->txid));
            r.pushKV("actions", static_cast<uint64_t>(it->actions));
            r.pushKV("valueBalance", it->vb);
            r.pushKV("kind", it->vb < 0 ? "shield" : it->t_out > 0 ? "unshield" : "private");
            if (auto hash{node.block_hash_at(it->height)}) {
                r.pushKV("block", bt::hex_encode(*hash));
                if (auto hd{node.header(*hash)}) {
                    if (auto tm{main_time(hd->prev_main_hash)}) r.pushKV("time", *tm);
                }
            }
            rec.push_back(r);
        }
        o.pushKV("recent", rec);
        o.pushKV("blocks", per_block);
        o.pushKV("height", node.height() ? int64_t(*node.height()) : int64_t{-1});
        std::lock_guard<std::mutex> l(pool_mu);
        pool_cache = PoolCache{tip, o};
        return o;
    }

    // ---------------------------------------------------------- peg
    UniValue peg()
    {
        const auto mine{addresses()};
        UniValue o{UniValue::VOBJ};
        auto pending{node.pending_withdrawal_bundle()};
        std::set<OutPoint> in_pending;
        if (pending) {
            UniValue p{UniValue::VOBJ};
            p.pushKV("m6id", bt::hex_encode_rev(pending->m6id().span()));
            uint64_t total{0};
            for (auto& [op, out] : pending->spend_utxos) {
                total += out.get_value();
                in_pending.insert(op);
            }
            p.pushKV("withdrawals", static_cast<uint64_t>(pending->spend_utxos.size()));
            p.pushKV("total", n64(total));
            o.pushKV("pendingBundle", p);
        } else {
            o.pushKV("pendingBundle", UniValue{});
        }
        auto failed{node.latest_failed_withdrawal_bundle_height()};
        o.pushKV("lastFailedHeight", failed ? UniValue(uint64_t(*failed)) : UniValue{});
        UniValue w{UniValue::VARR};
        auto withdrawal = [&](const OutPoint& op, const Output& out, const std::string& state, const std::optional<Hash32>& m6id) {
            UniValue r{UniValue::VOBJ};
            r.pushKV("outpoint", json::outpoint(op));
            r.pushKV("txid", bt::hex_encode(op.txid));
            r.pushKV("mainAddress", out.content.main_address.to_string());
            r.pushKV("amount", n64(out.content.value));
            r.pushKV("mainFee", n64(out.content.main_fee));
            r.pushKV("state", state);
            if (m6id) {
                r.pushKV("m6id", bt::hex_encode_rev(m6id->span()));
                if (auto b{node.withdrawal_bundle(*m6id)}) r.pushKV("bundleStatus", to_string(b->second));
            }
            w.push_back(r);
        };
        for (auto& [op, out] : node.utxos_by_addresses(mine)) {
            if (out.content.kind != Content::Withdrawal) continue;
            withdrawal(op, out, in_pending.contains(op) ? "in-pending-bundle" : "waiting", pending && in_pending.contains(op) ? std::optional<Hash32>{pending->m6id()} : std::nullopt);
        }
        for (auto& [op, s] : node.stxos_by_addresses(mine)) {
            if (s.output.content.kind != Content::Withdrawal || s.inpoint.kind != InPoint::Withdrawal) continue;
            auto b{node.withdrawal_bundle(s.inpoint.id)};
            std::string state{"submitted"};
            if (b && b->second == BundleStatus::Confirmed) state = "paid";
            else if (b && b->second == BundleStatus::Failed) state = "failed";
            withdrawal(op, s.output, state, s.inpoint.id);
        }
        o.pushKV("withdrawals", w);
        o.pushKV("wealth", n64(node.sidechain_wealth()));
        o.pushKV("mainchain", link ? link->info() : UniValue{});
        o.pushKV("slot", static_cast<int>(THIS_SIDECHAIN));
        return o;
    }

    // ---------------------------------------------------------- questions of the spends
    Address side_address(const UniValue& v, const std::string& what)
    {
        if (!v.isStr()) throw HostError(bt::appui::HOST_INVALID_REQUEST, what + ": a zSide transparent address");
        auto a{Address::from_base58(v.get_str())};
        if (!a) {
            if (ShieldedAddress::parse(v.get_str())) throw HostError(bt::appui::HOST_INVALID_REQUEST, what + ": a shielded address, not a transparent one");
            throw HostError(bt::appui::HOST_INVALID_REQUEST, what + ": not a zSide transparent address (" + v.get_str() + ")");
        }
        return *a;
    }

    ShieldedAddress shielded_address(const UniValue& v, const std::string& what)
    {
        if (!v.isStr()) throw HostError(bt::appui::HOST_INVALID_REQUEST, what + ": a zSide shielded address");
        auto a{ShieldedAddress::parse(v.get_str())};
        if (!a) {
            if (Address::from_base58(v.get_str())) throw HostError(bt::appui::HOST_INVALID_REQUEST, what + ": a transparent address, not a shielded one");
            throw HostError(bt::appui::HOST_INVALID_REQUEST, what + ": not a zSide shielded address (" + v.get_str() + ")");
        }
        return *a;
    }

    bt::btc::Address main_address(const UniValue& v)
    {
        if (!v.isStr()) throw HostError(bt::appui::HOST_INVALID_REQUEST, "mainchain_address: an eCash address");
        auto a{bt::btc::Address::parse(v.get_str())};
        if (!a) throw HostError(bt::appui::HOST_INVALID_REQUEST, "Not an eCash address: " + v.get_str());
        if (!main_address_of_network(*a, network)) throw HostError(bt::appui::HOST_INVALID_REQUEST, "This eCash address is of another network than the one this node follows (" + network + ")");
        return *a;
    }

    void enough(uint64_t need)
    {
        const uint64_t have{balances(addresses()).available};
        if (need > have) throw HostError(bt::appui::RPC_WALLET_ERROR, "Not enough available in the transparent balance: " + coins(have) + " for " + coins(need));
    }

    void enough_shielded(uint64_t need)
    {
        if (!wallet.has_seed()) throw HostError(bt::appui::RPC_WALLET_ERROR, "The wallet has no backup phrase yet: set it up first");
        auto v{shielded()};
        if (need > v->spendable) {
            std::string why{"Not enough in the shielded balance: " + coins(v->spendable) + " can be spent now, for " + coins(need)};
            if (v->available > v->spendable) why += " (" + coins(v->available - v->spendable) + " more once its notes are 3 blocks deep)";
            throw HostError(bt::appui::RPC_WALLET_ERROR, why);
        }
    }

    static UniValue same_numbers(const UniValue& p, size_t n, const std::vector<size_t>& numbers)
    {
        if (!p.isArray() || p.size() < n) throw HostError(bt::appui::HOST_INVALID_REQUEST, "params: " + std::to_string(n) + " parameters");
        UniValue out{UniValue::VARR};
        for (size_t i{0}; i < p.size() && i < n; ++i) {
            if (std::find(numbers.begin(), numbers.end(), i) != numbers.end()) out.push_back(n64(u64_of(p[i], "param " + std::to_string(i))));
            else out.push_back(p[i]);
        }
        return out;
    }

    /** Signed and sent as LayerTwo's own spends are (app.cpp sign_and_send): its txid as theirs writes it. */
    UniValue sign_and_send(const Transaction& tx)
    {
        auto at{wallet.authorize(tx)};
        node.submit_transaction(at);
        return json::hash(at.transaction.txid());
    }

    std::map<std::string, Confirmed> confirmed()
    {
        std::map<std::string, Confirmed> c;
        c["create_transparent_transfer"] = Confirmed{
            [](const UniValue& p) { return same_numbers(p, 3, {1, 2}); },
            [this](const UniValue& p) {
                const Address to{side_address(p[0], "dest")};
                const uint64_t value{p[1].getInt<uint64_t>()}, fee{p[2].getInt<uint64_t>()};
                if (value == 0) throw HostError(bt::appui::HOST_INVALID_REQUEST, "Nothing to send");
                const uint64_t total{bt::appui::spend_total({value, fee})};
                enough(total);
                Question q;
                q.title = "Send " + coins(value);
                q.message = addresses().contains(to) ? "To a transparent address of this wallet." :
                                                       "From your transparent balance, to this transparent address on zSide: the payment, its amount and both "
                                                       "addresses are public. A payment cannot be taken back.";
                q.accept = "Send";
                q.kind = "send";
                q.rows = {{"To", to.to_base58(), "address"}, {"Amount", coins(value), "amount"}, {"Fee", coins(fee), "amount"}, {"Total", coins(total), "total"}};
                return q;
            },
            [this](const UniValue& p) { return l2l_call("create_transparent_transfer", p); }};
        // LayerTwo's create_shielded_transfer [dest, value_sats, fee_sats]; ours also takes a memo (4th, text): their RPC
        // has none (their wallet writes an empty one), the memo is inside the recipient's encrypted note.
        c["create_shielded_transfer"] = Confirmed{
            [](const UniValue& p) {
                UniValue out{same_numbers(p, 3, {1, 2})};
                if (p.size() > 3 && !p[3].isNull()) {
                    if (!p[3].isStr()) throw HostError(bt::appui::HOST_INVALID_REQUEST, "memo: text");
                    if (!p[3].get_str().empty()) out.push_back(p[3].get_str());
                }
                return out;
            },
            [this](const UniValue& p) {
                const ShieldedAddress to{shielded_address(p[0], "dest")};
                const uint64_t value{p[1].getInt<uint64_t>()}, fee{p[2].getInt<uint64_t>()};
                if (value == 0) throw HostError(bt::appui::HOST_INVALID_REQUEST, "Nothing to send");
                std::string memo;
                if (p.size() > 3) {
                    memo = p[3].get_str();
                    if (auto why{memo_problem(memo)}; !why.empty()) throw HostError(bt::appui::HOST_INVALID_REQUEST, why);
                }
                const uint64_t total{bt::appui::spend_total({value, fee})};
                enough_shielded(total);
                Question q;
                q.title = "Send " + coins(value) + " privately";
                q.message = shielded_addresses().contains(to) ? "To a shielded address of this wallet." :
                                                                "From your shielded balance. Only the recipient sees the amount and the memo; the chain shows "
                                                                "neither who paid nor who was paid. A payment cannot be taken back.";
                q.accept = "Send";
                q.kind = "send-shielded";
                q.rows = {{"To", to.to_string(), "address"}, {"Amount", coins(value), "amount"}};
                if (!memo.empty()) q.rows.push_back({"Memo", memo, "text"});
                q.rows.push_back({"Fee", coins(fee), "amount"});
                q.rows.push_back({"Total", coins(total), "total"});
                return q;
            },
            [this](const UniValue& p) {
                if (p.size() <= 3) return l2l_call("create_shielded_transfer", p);
                const auto to{ShieldedAddress::parse(p[0].getValStr())};
                if (!to || !p[3].isStr() || !memo_problem(p[3].get_str()).empty()) throw HostError(bt::appui::HOST_INVALID_REQUEST, "dest or memo");
                const auto memo{memo_bytes(p[3].get_str())};
                try {
                    return sign_and_send(wallet.create_shielded_transfer(*to, p[1].getInt<uint64_t>(), p[2].getInt<uint64_t>(), &memo));
                } catch (const RpcError&) {
                    throw;
                } catch (const std::exception& e) {
                    throw RpcError(-1, e.what());
                }
            }};
        c["create_shield"] = Confirmed{
            [](const UniValue& p) { return same_numbers(p, 2, {0, 1}); },
            [this](const UniValue& p) {
                const uint64_t value{p[0].getInt<uint64_t>()}, fee{p[1].getInt<uint64_t>()};
                if (value == 0) throw HostError(bt::appui::HOST_INVALID_REQUEST, "Nothing to shield");
                if (!wallet.has_seed()) throw HostError(bt::appui::RPC_WALLET_ERROR, "The wallet has no backup phrase yet: set it up first");
                const uint64_t total{bt::appui::spend_total({value, fee})};
                enough(total);
                Question q;
                q.title = "Shield " + coins(value);
                q.message = "Transparent coins of this wallet go into the shielded pool, to a new shielded address of this wallet. The amount is "
                            "public as it goes in; once shielded, nobody sees what you hold or whom you pay.";
                q.accept = "Shield";
                q.kind = "shield";
                q.rows = {{"Into your shielded balance", coins(value), "amount"}, {"Fee", coins(fee), "amount"}, {"Total (from the transparent balance)", coins(total), "total"}};
                return q;
            },
            [this](const UniValue& p) { return l2l_call("create_shield", p); }};
        c["create_unshield"] = Confirmed{
            [](const UniValue& p) { return same_numbers(p, 2, {0, 1}); },
            [this](const UniValue& p) {
                const uint64_t value{p[0].getInt<uint64_t>()}, fee{p[1].getInt<uint64_t>()};
                if (value == 0) throw HostError(bt::appui::HOST_INVALID_REQUEST, "Nothing to unshield");
                const uint64_t total{bt::appui::spend_total({value, fee})};
                enough_shielded(total);
                Question q;
                q.title = "Unshield " + coins(value);
                q.message = "Coins leave the shielded pool to a new transparent address of this wallet. The amount is public as it comes out.";
                q.accept = "Unshield";
                q.kind = "unshield";
                q.rows = {{"Into your transparent balance", coins(value), "amount"}, {"Fee", coins(fee), "amount"}, {"Total (from the shielded balance)", coins(total), "total"}};
                return q;
            },
            [this](const UniValue& p) { return l2l_call("create_unshield", p); }};
        c["create_withdrawal"] = Confirmed{
            [](const UniValue& p) { return same_numbers(p, 4, {1, 2, 3}); },
            [this](const UniValue& p) {
                const bt::btc::Address to{main_address(p[0])};
                const uint64_t value{p[1].getInt<uint64_t>()}, fee{p[2].getInt<uint64_t>()}, main_fee{p[3].getInt<uint64_t>()};
                if (value == 0) throw HostError(bt::appui::HOST_INVALID_REQUEST, "Nothing to withdraw");
                const uint64_t total{bt::appui::spend_total({value, fee, main_fee})};
                enough(total);
                Question q;
                q.title = "Withdraw " + coins(value) + " to eCash";
                q.message = "From your transparent balance: your coins leave zSide now. eCash pays them to the address below once a withdrawal "
                            "bundle with them is accepted by eCash's miners, which takes a long time (their votes). Until then they show as being withdrawn.";
                q.accept = "Withdraw";
                q.kind = "withdraw";
                q.rows = {{"To (on eCash)", to.to_string(), "address"}, {"Amount", coins(value), "amount"}, {"Fee on eCash", coins(main_fee), "amount"},
                          {"Fee on zSide", coins(fee), "amount"}, {"Total", coins(total), "total"}};
                return q;
            },
            [this](const UniValue& p) { return l2l_call("create_withdrawal", p); }};
        c["create_deposit"] = Confirmed{
            [](const UniValue& p) { return same_numbers(p, 3, {1, 2}); },
            [this](const UniValue& p) {
                // A bare transparent address only: zSide credits a deposit to it, and burns one to anything else.
                const Address to{side_address(p[0], "address")};
                const uint64_t value{p[1].getInt<uint64_t>()}, fee{p[2].getInt<uint64_t>()};
                if (value == 0) throw HostError(bt::appui::HOST_INVALID_REQUEST, "Nothing to deposit");
                const uint64_t total{bt::appui::spend_total({value, fee})};
                const bool ours{addresses().contains(to)};
                Question q;
                q.title = "Deposit " + coins(value) + " into zSide";
                q.message = "Paid on eCash by the wallet of the mainchain interface this node uses (" + node.enforcer().url() +
                            "), into zSide's slot " + std::to_string(int(THIS_SIDECHAIN)) + ", to a transparent address. It is credited on zSide in the first block after eCash mines it.";
                if (!ours) {
                    q.message += " The address is NOT one of this wallet: the coins go to whoever holds it.";
                    q.level = "danger";
                }
                q.accept = "Deposit";
                q.kind = "deposit";
                q.rows = {{"Into (zSide)", to.to_base58(), "address"}, {"Amount", coins(value), "amount"}, {"Fee on eCash", coins(fee), "amount"},
                          {"Total (paid on eCash)", coins(total), "total"}};
                return q;
            },
            [this](const UniValue& p) { return l2l_call("create_deposit", p); }};
        c["mine"] = Confirmed{
            [](const UniValue& p) {
                UniValue out{UniValue::VARR};
                if (p.isArray() && p.size() > 0 && !p[0].isNull()) out.push_back(n64(u64_of(p[0], "fee")));
                return out;
            },
            [this](const UniValue& p) {
                const uint64_t bid{bt::appui::spend_total({p.size() > 0 ? p[0].getInt<uint64_t>() : App::EMPTY_BLOCK_BMM_BRIBE})};
                Question q;
                q.title = "Merge-mine a block of zSide";
                q.message = "Asks eCash's miners to include the next block of zSide (blind merged mining), with a bid paid on eCash by the "
                            "wallet of the mainchain interface (" + node.enforcer().url() + "). The bid is paid whether or not the block is taken.";
                q.accept = "Bid";
                q.kind = "mine";
                q.rows = {{"Bid (at most)", p.size() > 0 ? coins(bid) : "the block's fees, or " + coins(App::EMPTY_BLOCK_BMM_BRIBE), "amount"}};
                return q;
            },
            [this](const UniValue& p) { return l2l_call("mine", p); }};
        // Every spend's balance looked at again at once.
        for (auto& [name, conf] : c) {
            auto run{conf.run};
            conf.run = [this, run](const UniValue& p) {
                UniValue r{run(p)};
                if (poller) poller->poke();
                return r;
            };
        }
        return c;
    }
};

const std::vector<std::string>& AppLayer::l2l_reads()
{
    static const std::vector<std::string> reads{"balance", "format_deposit_address", "get_best_mainchain_block_hash", "get_best_sidechain_block_hash", "get_block",
                                                "get_block_hash", "get_bmm_inclusions", "get_shielded_wallet_addresses", "get_stxos", "get_transaction",
                                                "get_transparent_wallet_addresses", "get_utxos", "get_wallet_stxos", "get_wallet_utxos", "get_withdrawal_bundle",
                                                "getblockcount", "latest_failed_withdrawal_bundle_height", "list_peers", "list_utxos", "openapi_schema",
                                                "pending_withdrawal_bundle", "sidechain_wealth"};
    return reads;
}

AppLayer::AppLayer(App& app, std::string network, std::string datadir, bt::appui::AppOptions options)
    : m_(std::make_unique<Impl>(app, std::move(network), std::move(datadir), std::move(options)))
{
}

AppLayer::~AppLayer() { stop(); }

uint16_t AppLayer::port() const { return server_ ? server_->port() : 0; }

UniValue AppLayer::history(size_t limit) { return m_->history(limit); }

namespace {
const std::vector<const char*> CONFIRMED{"create_deposit", "create_shield", "create_shielded_transfer", "create_transparent_transfer", "create_unshield",
                                         "create_withdrawal", "mine"};
const std::vector<const char*> HOST_METHODS{"dropin.overview", "dropin.history", "dropin.newAddress", "dropin.addresses", "dropin.blocks", "dropin.block",
                                            "dropin.transaction", "dropin.address", "dropin.search", "dropin.checkAddress", "dropin.peg", "dropin.peers",
                                            "dropin.peers.connect", "dropin.peers.forget", "dropin.seed.status", "dropin.seed.prepare", "dropin.seed.create",
                                            "dropin.seed.restore", "dropin.seed.show", "dropin.seed.save", "zside.shielded", "zside.newShieldedAddress",
                                            "zside.memos", "zside.pool"};
const std::vector<const char*> SHELL_READS{"getmainchaininfo", "getbalances", "getblockchaininfo", "getnetworkinfo", "uptime"};
} // namespace

bool AppLayer::start(std::string& err)
{
    Impl& m{*m_};
    if (!bt::fsperm::private_dir(m.datadir)) {
        err = "cannot make " + m.datadir;
        return false;
    }
    m.store = std::make_unique<bt::appui::AppStore>(m.datadir + "/backbone-app.sqlite");
    std::string why;
    bt::appui::ServerOptions so{bt::appui::server_options(m.options, m.datadir, why)};
    if (!why.empty()) {
        err = why;
        return false;
    }
    server_ = std::make_unique<bt::appui::RpcServer>(std::move(so));
    m.link = std::make_unique<bt::appui::LinkMonitor>(m.node.enforcer(), THIS_SIDECHAIN, [&m] { return m.followed(); });

    // ---- the app RPC's own methods: the LayerTwo reads, as theirs; the reads of the kit's shell; the setup of the wallet.
    for (const std::string& name : l2l_reads()) {
        server_->add(name, {}, [&m, name](const bt::appui::Call& c) { return m.l2l_call(name, c.params); });
    }
    server_->add("getmainchaininfo", {}, [&m](const bt::appui::Call&) { return m.link->info(); });
    server_->add("getbalances", {}, [&m](const bt::appui::Call&) {
        UniValue mine{UniValue::VOBJ};
        Impl::Balances b;
        if (m.wallet.has_seed()) b = m.balances(m.addresses());
        // Both balances: the transparent one and the shielded one (spendable or not yet).
        mine.pushKV("trusted", bt::appui::coins_value(b.available + b.shielded_available));
        mine.pushKV("untrusted_pending", bt::appui::coins_value(b.pending_in + b.shielded_pending_in));
        mine.pushKV("immature", bt::appui::coins_value(b.withdrawing));
        UniValue out{UniValue::VOBJ};
        out.pushKV("mine", mine);
        return out;
    });
    server_->add("getblockchaininfo", {}, [&m](const bt::appui::Call&) {
        UniValue o{UniValue::VOBJ};
        auto h{m.node.height()};
        auto t{m.node.tip()};
        o.pushKV("chain", m.network);
        o.pushKV("blocks", h ? int64_t(*h) : int64_t{-1});
        o.pushKV("headers", h ? int64_t(*h) : int64_t{-1});
        o.pushKV("bestblockhash", t ? bt::hex_encode(*t) : "");
        o.pushKV("initialblockdownload", false);
        o.pushKV("verificationprogress", 1.0);
        o.pushKV("warnings", UniValue{UniValue::VARR});
        return o;
    });
    server_->add("getnetworkinfo", {}, [&m](const bt::appui::Call&) {
        UniValue o{UniValue::VOBJ};
        size_t n{0};
        for (auto& p : m.node.peers()) n += p.connected ? 1 : 0;
        o.pushKV("version", 1800100);
        o.pushKV("subversion", std::string{"/backbone-zside:"} + VERSION_TEXT + "/");
        o.pushKV("connections", static_cast<uint64_t>(n));
        o.pushKV("networkactive", true);
        o.pushKV("warnings", UniValue{UniValue::VARR});
        return o;
    });
    server_->add("uptime", {}, [&m](const bt::appui::Call&) {
        return UniValue(static_cast<int64_t>(std::chrono::duration_cast<std::chrono::seconds>(std::chrono::system_clock::now() - m.started).count()));
    });
    // The setup of the wallet by the unified wallet (doc/app.md "One backup phrase"): its own user (the cookie) sets
    // the phrase it derived; refused when the wallet has another one. Never offered to the pages. zSide's transparent
    // keys and its Orchard spending key both come from the phrase's BIP-39 seed: one phrase covers the whole wallet.
    server_->add("getwalletphraseinfo", {}, [&m](const bt::appui::Call&) { return m.seed_status(); });
    server_->add("setwalletphrase", {"phrase"}, [&m](const bt::appui::Call& c) {
        if (!c[0].isStr()) throw RpcError(bt::appui::RPC_INVALID_PARAMETER, "phrase: the 12 to 24 words");
        std::string phrase{c[0].get_str()};
        const bt::appui::WipeOnExit wipe{phrase};
        try {
            UniValue r{m.set_phrase(phrase, "unified")};
            LOG_INFO("app layer: the wallet's phrase was set by the app (fingerprint %s)", r.find_value("fingerprint").get_str().c_str());
            return r;
        } catch (const HostError& e) {
            throw RpcError(e.code, e.what());
        }
    });
    server_->add("stop", {}, [&m](const bt::appui::Call&) {
        if (m.app.on_stop) m.app.on_stop();
        return UniValue("zSide stopping");
    });
    server_->add("getappmanifest", {}, [this](const bt::appui::Call&) { return manifest(); });

    // ---- the host of the pages
    bt::appui::ChainHost chain;
    chain.name = "zSide";
    chain.stem = "zside";
    chain.network = m.network;
    chain.info = [&m] { return m.info(); };
    chain.wallet_id = [&m] { return m.wallet_id(); };
    for (const char* r : SHELL_READS) chain.page_reads.insert(r);
    for (const std::string& r : l2l_reads()) chain.page_reads.insert(r);
    chain.confirmed = m.confirmed();
    chain.owner_read = WALLET_READ;
    auto& H{chain.host};
    auto& P{chain.privileges};
    H["dropin.overview"] = [&m](const UniValue&, HostEnv&) {
        UniValue o{UniValue::VOBJ};
        const bool has{m.wallet.has_seed()};
        Impl::Balances b;
        if (has) b = m.balances(m.addresses());
        UniValue w{UniValue::VOBJ};
        w.pushKV("hasSeed", has);
        w.pushKV("available", n64(b.available));
        w.pushKV("withdrawing", n64(b.withdrawing));
        w.pushKV("pendingIn", n64(b.pending_in));
        w.pushKV("pendingOut", n64(b.pending_out));
        // The shielded balance (what LayerTwo's `balance`, this method's privilege, says too).
        UniValue z{UniValue::VOBJ};
        z.pushKV("available", n64(b.shielded_available));
        z.pushKV("total", n64(b.shielded_total));
        z.pushKV("spendable", n64(b.shielded_spendable));
        z.pushKV("pendingIn", n64(b.shielded_pending_in));
        w.pushKV("shielded", z);
        o.pushKV("wallet", w);
        auto h{m.node.height()};
        auto t{m.node.tip()};
        UniValue c{UniValue::VOBJ};
        c.pushKV("height", h ? int64_t(*h) : int64_t{-1});
        c.pushKV("tip", t ? bt::hex_encode(*t) : "");
        size_t peers{0};
        for (auto& p : m.node.peers()) peers += p.connected ? 1 : 0;
        c.pushKV("peers", static_cast<uint64_t>(peers));
        c.pushKV("wealth", n64(m.node.sidechain_wealth()));
        c.pushKV("slot", static_cast<int>(THIS_SIDECHAIN));
        c.pushKV("network", m.network);
        o.pushKV("chain", c);
        o.pushKV("mainchain", m.link->info());
        return o;
    };
    P["dropin.overview"] = {"balance", "getblockcount"};
    H["dropin.history"] = [&m](const UniValue& p, HostEnv&) {
        const UniValue& lim{param(p, "limit")};
        const size_t limit{lim.isNum() ? static_cast<size_t>(std::clamp<int64_t>(lim.getInt<int64_t>(), 1, 5000)) : size_t{500}};
        if (!m.wallet.has_seed()) return UniValue{UniValue::VARR};
        return m.history(limit);
    };
    // Its rows say which notes and memos are the wallet's: a reader of both accounts.
    P["dropin.history"] = {"get_wallet_utxos", SHIELDED_READ};
    H["dropin.newAddress"] = [&m](const UniValue&, HostEnv&) {
        if (!m.wallet.has_seed()) throw HostError(bt::appui::RPC_WALLET_ERROR, "The wallet has no backup phrase yet: set it up first");
        const Address a{m.wallet.get_new_transparent_address()};
        UniValue o{UniValue::VOBJ};
        o.pushKV("address", a.to_base58());
        // What an eCash wallet must name in a deposit to credit this address: the address itself (zSide credits a deposit
        // only to a bare address; the s98_… form, format_deposit_address, would burn it).
        o.pushKV("depositAddress", a.to_base58());
        return o;
    };
    P["dropin.newAddress"] = {"get_new_transparent_address"};
    H["dropin.addresses"] = [&m](const UniValue&, HostEnv&) {
        UniValue out{UniValue::VARR};
        if (!m.wallet.has_seed()) return out;
        std::map<Address, std::pair<uint64_t, uint64_t>> got; // balance, received
        const auto mine{m.addresses()};
        for (auto& [op, o] : m.node.utxos_by_addresses(mine)) {
            got[o.address].first += o.get_value();
            got[o.address].second += o.get_value();
        }
        for (auto& [op, s] : m.node.stxos_by_addresses(mine)) got[s.output.address].second += s.output.get_value();
        for (const Address& a : m.wallet.transparent_addresses()) {
            UniValue r{UniValue::VOBJ};
            r.pushKV("address", a.to_base58());
            r.pushKV("depositAddress", a.to_base58());
            r.pushKV("balance", n64(got[a].first));
            r.pushKV("received", n64(got[a].second));
            out.push_back(r);
        }
        return out;
    };
    P["dropin.addresses"] = {WALLET_READ};
    H["dropin.blocks"] = [&m](const UniValue& p, HostEnv&) {
        const UniValue& cnt{param(p, "count")};
        const UniValue& from{param(p, "from")};
        const int64_t count{cnt.isNum() ? std::clamp<int64_t>(cnt.getInt<int64_t>(), 1, 200) : int64_t{20}};
        UniValue out{UniValue::VARR};
        auto h{m.node.height()};
        if (!h) return out;
        int64_t at{from.isNum() ? std::min<int64_t>(from.getInt<int64_t>(), *h) : int64_t(*h)};
        for (; at >= 0 && static_cast<int64_t>(out.size()) < count; --at) {
            auto hash{m.node.block_hash_at(static_cast<uint32_t>(at))};
            if (!hash) break;
            auto hd{m.node.header(*hash)};
            auto b{m.node.body(*hash)};
            if (!hd || !b) continue;
            out.push_back(m.block_summary(static_cast<uint32_t>(at), *hash, *hd, *b));
        }
        return out;
    };
    P["dropin.blocks"] = {"get_block"};
    H["dropin.block"] = [&m](const UniValue& p, HostEnv& env) {
        const UniValue& height{param(p, "height")};
        if (height.isNum()) {
            auto hash{m.node.block_hash_at(static_cast<uint32_t>(std::clamp<int64_t>(height.getInt<int64_t>(), 0, UINT32_MAX)))};
            if (!hash) throw HostError("No block at this height");
            return m.block_detail(*hash, m.mine_for(env));
        }
        auto hash{m.parse_hash(str_param(p, "hash"))};
        if (!hash) throw HostError(bt::appui::HOST_INVALID_REQUEST, "hash: 64 hex digits");
        return m.block_detail(*hash, m.mine_for(env));
    };
    P["dropin.block"] = {"get_block"};
    H["dropin.transaction"] = [&m](const UniValue& p, HostEnv& env) {
        auto txid{m.parse_hash(str_param(p, "txid"))};
        if (!txid) throw HostError(bt::appui::HOST_INVALID_REQUEST, "txid: 64 hex digits");
        return m.tx_detail(*txid, m.mine_for(env));
    };
    P["dropin.transaction"] = {"get_transaction"};
    H["dropin.address"] = [&m](const UniValue& p, HostEnv& env) {
        auto a{Address::from_base58(str_param(p, "address"))};
        if (!a) throw HostError(bt::appui::HOST_INVALID_REQUEST, "Not a zSide transparent address");
        return m.address_detail(*a, m.mine_for(env));
    };
    P["dropin.address"] = {"get_utxos", "get_stxos"};
    H["dropin.search"] = [&m](const UniValue& p, HostEnv&) {
        std::string q{str_param(p, "query")};
        q.erase(0, q.find_first_not_of(" \t"));
        q.erase(q.find_last_not_of(" \t") + 1);
        UniValue o{UniValue::VOBJ};
        if (q.size() > 120) throw HostError(bt::appui::HOST_INVALID_REQUEST, "Too long");
        if (!q.empty() && q.size() <= 10 && q.find_first_not_of("0123456789") == std::string::npos) {
            auto hash{m.node.block_hash_at(static_cast<uint32_t>(std::min<uint64_t>(std::stoull(q), UINT32_MAX)))};
            if (hash) {
                o.pushKV("kind", "block");
                o.pushKV("hash", bt::hex_encode(*hash));
                return o;
            }
        } else if (auto h{m.parse_hash(q)}) {
            if (m.node.header(*h)) {
                o.pushKV("kind", "block");
                o.pushKV("hash", q);
                return o;
            }
            o.pushKV("kind", "transaction");
            o.pushKV("txid", q);
            return o;
        } else if (Address::from_base58(q)) {
            o.pushKV("kind", "address");
            o.pushKV("address", q);
            return o;
        } else if (q.rfind("s98_", 0) == 0) {
            // A formatted deposit address: the zSide address inside.
            const size_t end{q.rfind('_')};
            if (end > 4) {
                const std::string inner{q.substr(4, end - 4)};
                if (Address::from_base58(inner)) {
                    o.pushKV("kind", "address");
                    o.pushKV("address", inner);
                    return o;
                }
            }
        }
        // A shielded address shows nothing on the chain: nothing to look up.
        o.pushKV("kind", "none");
        return o;
    };
    P["dropin.search"] = {"get_block", "get_transaction"};
    H["dropin.checkAddress"] = [&m](const UniValue& p, HostEnv& env) {
        const std::string text{str_param(p, "address")};
        const std::string side{param(p, "side").isStr() ? param(p, "side").get_str() : "zside"};
        UniValue o{UniValue::VOBJ};
        if (side == "mainchain") {
            auto a{bt::btc::Address::parse(text)};
            o.pushKV("valid", a.has_value() && main_address_of_network(*a, m.network));
            if (a && !main_address_of_network(*a, m.network)) o.pushKV("error", "an eCash address of another network");
            else if (!a) o.pushKV("error", Address::from_base58(text) || ShieldedAddress::parse(text) ? "a zSide address, not an eCash one" : "not an eCash address");
            return o;
        }
        if (auto a{Address::from_base58(text)}) {
            o.pushKV("valid", side != "shielded");
            o.pushKV("kind", "transparent");
            if (side == "shielded") o.pushKV("error", "a transparent address: shielded payments go to a shielded one (t-shld1…)");
            // Whether it is the wallet's: only to a caller that may read the wallet's addresses.
            if (env.may_call(WALLET_READ)) o.pushKV("mine", m.addresses().contains(*a));
            return o;
        }
        if (auto z{ShieldedAddress::parse(text)}) {
            o.pushKV("valid", side != "transparent");
            o.pushKV("kind", "shielded");
            if (side == "transparent") o.pushKV("error", "a shielded address: this needs a transparent one");
            if (env.may_call(SHIELDED_READ)) o.pushKV("mine", m.shielded_addresses().contains(*z));
            return o;
        }
        o.pushKV("valid", false);
        o.pushKV("error", bt::btc::Address::parse(text)                  ? "an eCash address, not a zSide one" :
                          text.rfind("s98_", 0) == 0                     ? "a deposit address of eCash: pay zSide's plain address" :
                          text.rfind(SHIELDED_PREFIX, 0) == 0            ? "not a valid shielded address (a character mistyped?)" :
                                                                           "not a zSide address");
        return o;
    };
    P["dropin.checkAddress"] = {};
    H["dropin.peg"] = [&m](const UniValue&, HostEnv&) { return m.peg(); };
    P["dropin.peg"] = {"pending_withdrawal_bundle", "get_wallet_utxos"};
    H["dropin.peers"] = [&m](const UniValue&, HostEnv&) {
        UniValue out{UniValue::VARR};
        for (auto& pv : m.node.peers()) {
            UniValue o{UniValue::VOBJ};
            o.pushKV("address", pv.address.to_string());
            o.pushKV("connected", pv.connected);
            o.pushKV("inbound", pv.inbound);
            out.push_back(o);
        }
        return out;
    };
    P["dropin.peers"] = {"list_peers"};
    H["dropin.peers.connect"] = [&m](const UniValue& p, HostEnv&) {
        std::string a{str_param(p, "address")};
        if (a.rfind(':') == std::string::npos) a += ":" + std::to_string(net::DEFAULT_PORT);
        std::string err;
        if (!m.node.connect_peer(a, err)) throw HostError(err);
        return UniValue{true};
    };
    P["dropin.peers.connect"] = {"connect_peer"};
    H["dropin.peers.forget"] = [&m](const UniValue& p, HostEnv&) {
        std::string a{str_param(p, "address")};
        if (a.rfind(':') == std::string::npos) a += ":" + std::to_string(net::DEFAULT_PORT);
        return UniValue{m.node.forget_peer(a)};
    };
    P["dropin.peers.forget"] = {"forget_peer"};
    // ---- the backup phrase: its words shown only in the app's trusted dialog, never to the pages. It is the whole
    // wallet's: the transparent keys and the Orchard spending key both come from its BIP-39 seed.
    H["dropin.seed.status"] = [&m](const UniValue&, HostEnv&) { return m.seed_status(); };
    P["dropin.seed.status"] = {WALLET_READ};
    H["dropin.seed.prepare"] = [&m](const UniValue&, HostEnv&) {
        if (m.wallet.has_seed()) throw HostError(bt::appui::RPC_WALLET_ERROR, "This wallet has a backup phrase already");
        UniValue o{UniValue::VOBJ};
        o.pushKV("id", m.phrases.put(bt::hd::generate_mnemonic(12)));
        o.pushKV("words", 12);
        return o;
    };
    P["dropin.seed.prepare"] = {"set_seed_from_mnemonic"};
    H["dropin.seed.create"] = [&m](const UniValue& p, HostEnv& env) {
        const std::string id{str_param(p, "id")};
        auto phrase{m.phrases.get(id)};
        if (!phrase) throw HostError(bt::appui::HOST_INVALID_REQUEST, "This new phrase is not known any more (5 minutes): make another");
        const bt::appui::WipeOnExit wipe_phrase{*phrase};
        if (m.wallet.has_seed()) throw HostError(bt::appui::RPC_WALLET_ERROR, "This wallet has a backup phrase already");
        Question q;
        const bt::appui::WipeOnExit wipe_words{q.details};
        q.title = "Your backup phrase";
        q.message = "Write these 12 words down, in order, on paper, and keep them safe. They are the only way to get this wallet back, its "
                    "transparent coins and its shielded ones. Anyone who has them can take its coins. They are not shown to the app's pages.";
        q.details = Impl::words_block(*phrase);
        q.accept = "I wrote them down";
        q.level = "warning";
        q.kind = "phrase.create";
        if (!env.ask(q).accepted) throw HostError(bt::appui::HOST_CANCELLED, "Cancelled");
        UniValue r{m.set_phrase(*phrase, "app")};
        m.phrases.erase(id);
        return r;
    };
    P["dropin.seed.create"] = {"set_seed_from_mnemonic"};
    H["dropin.seed.restore"] = [&m](const UniValue& p, HostEnv& env) {
        std::string phrase{str_param(p, "phrase")};
        const bt::appui::WipeOnExit wipe_typed{phrase};
        auto parsed{bt::hd::parse_mnemonic(phrase)};
        if (!parsed) throw HostError(bt::appui::HOST_INVALID_REQUEST, bt::hd::mnemonic_error(phrase));
        const bt::appui::WipeOnExit wipe_parsed{*parsed};
        if (m.wallet.has_seed()) throw HostError(bt::appui::RPC_WALLET_ERROR, "This wallet has a backup phrase already");
        auto seed{bt::hd::mnemonic_to_seed(*parsed)};
        const std::string fp{bt::appui::seed_fingerprint(seed.span())};
        sodium_memzero(seed.data(), seed.size());
        Question q;
        q.title = "Restore the wallet from this phrase";
        q.message = "The wallet takes the keys of this backup phrase, transparent and shielded. Its coins show once the node has looked at the chain.";
        q.rows = {{"Words", std::to_string(std::count(parsed->begin(), parsed->end(), ' ') + 1), "text"}, {"Fingerprint", fp, "text"}};
        q.accept = "Restore";
        q.kind = "phrase.restore";
        if (!env.ask(q).accepted) throw HostError(bt::appui::HOST_CANCELLED, "Cancelled");
        return m.set_phrase(*parsed, "restored");
    };
    P["dropin.seed.restore"] = {"set_seed_from_mnemonic"};
    // Shown or saved only when named in the whitelist (no privilege stands for it): the most sensitive read there is.
    H["dropin.seed.show"] = [&m](const UniValue&, HostEnv& env) {
        auto phrase{m.kept_phrase()};
        if (!phrase) throw HostError(bt::appui::RPC_WALLET_ERROR, "This wallet's phrase was not set through the app: keep the backup you made then");
        const bt::appui::WipeOnExit wipe_phrase{*phrase};
        Question q;
        const bt::appui::WipeOnExit wipe_words{q.details};
        q.title = "Your backup phrase";
        q.message = "Make sure nobody can see your screen. Anyone who has these words can take this wallet's coins, transparent and shielded.";
        q.details = Impl::words_block(*phrase);
        q.accept = "Done";
        q.cancel = "Close";
        q.level = "warning";
        q.kind = "phrase.show";
        env.ask(q);
        return UniValue{true};
    };
    H["dropin.seed.save"] = [&m](const UniValue& p, HostEnv& env) {
        const std::string path{str_param(p, "path")};
        const auto file{env.file(path, true)};
        auto phrase{m.kept_phrase()};
        if (!phrase) throw HostError(bt::appui::RPC_WALLET_ERROR, "This wallet's phrase was not set through the app: keep the backup you made then");
        const bt::appui::WipeOnExit wipe_phrase{*phrase};
        Question q;
        q.title = "Save your backup phrase to a file";
        q.message = "Anyone who can read this file can take this wallet's coins. Keep it somewhere only you can reach, off this computer if you can.";
        q.rows = {{"File", path, "text"}};
        q.accept = "Save";
        q.kind = "phrase.save";
        if (!env.ask(q).accepted) throw HostError(bt::appui::HOST_CANCELLED, "Cancelled");
        std::string content{"zSide backup phrase (BIP-39, " + m.derivation() + " keys, transparent and shielded)\n" + *phrase + "\n"};
        const bt::appui::WipeOnExit wipe_content{content};
        try {
            bt::appui::ChosenFiles::write(file, content);
        } catch (const std::runtime_error& e) {
            throw HostError(std::string{"The file chosen cannot be written: "} + e.what());
        }
        return UniValue{true};
    };
    // ---- zSide's own: the shielded account (a reader of it only), a new shielded address, its memos, the pool.
    H["zside.shielded"] = [&m](const UniValue&, HostEnv&) {
        UniValue o{UniValue::VOBJ};
        const bool has{m.wallet.has_seed()};
        o.pushKV("hasSeed", has);
        if (!has) return o;
        auto v{m.shielded()};
        UniValue b{UniValue::VOBJ};
        b.pushKV("available", n64(v->available));
        b.pushKV("total", n64(v->total));
        b.pushKV("spendable", n64(v->spendable));
        b.pushKV("pendingIn", n64(v->pending_in));
        o.pushKV("balance", b);
        std::map<ShieldedAddress, uint64_t> received;
        UniValue notes{UniValue::VARR};
        for (auto it{v->notes.rbegin()}; it != v->notes.rend(); ++it) {
            const ShieldedNote& n{*it};
            if (!n.incoming) continue;
            received[n.address] += n.value;
            if (n.spent_in && !n.spent_pending) continue;
            if (notes.size() >= 500) continue;
            UniValue r{UniValue::VOBJ};
            r.pushKV("txid", bt::hex_encode(n.txid));
            r.pushKV("height", n.height ? UniValue(uint64_t(*n.height)) : UniValue{});
            r.pushKV("value", n64(n.value));
            r.pushKV("address", n.address.to_string());
            r.pushKV("change", n.internal);
            r.pushKV("state", !n.height ? "incoming" : n.spent_in ? "spending" : "unspent");
            const MemoView mv{memo_view(n.memo)};
            if (mv.text) r.pushKV("memo", *mv.text);
            else if (!mv.hex.empty()) r.pushKV("memoHex", mv.hex);
            notes.push_back(r);
        }
        o.pushKV("notes", notes);
        UniValue addrs{UniValue::VARR};
        for (const ShieldedAddress& a : m.wallet.shielded_addresses()) {
            UniValue r{UniValue::VOBJ};
            r.pushKV("address", a.to_string());
            r.pushKV("received", n64(received[a]));
            addrs.push_back(r);
        }
        o.pushKV("addresses", addrs);
        return o;
    };
    P["zside.shielded"] = {"balance", SHIELDED_READ};
    H["zside.newShieldedAddress"] = [&m](const UniValue&, HostEnv&) {
        if (!m.wallet.has_seed()) throw HostError(bt::appui::RPC_WALLET_ERROR, "The wallet has no backup phrase yet: set it up first");
        UniValue o{UniValue::VOBJ};
        o.pushKV("address", m.wallet.get_new_shielded_address().to_string());
        return o;
    };
    P["zside.newShieldedAddress"] = {"get_new_shielded_address"};
    H["zside.memos"] = [&m](const UniValue& p, HostEnv&) {
        const UniValue& lim{param(p, "limit")};
        const size_t limit{lim.isNum() ? static_cast<size_t>(std::clamp<int64_t>(lim.getInt<int64_t>(), 1, 5000)) : size_t{500}};
        UniValue out{UniValue::VARR};
        if (!m.wallet.has_seed()) return out;
        auto v{m.shielded()};
        for (auto it{v->notes.rbegin()}; it != v->notes.rend() && out.size() < limit; ++it) {
            const ShieldedNote& n{*it};
            if (n.incoming && n.internal) continue; // change: the wallet's own note
            const MemoView mv{memo_view(n.memo)};
            if (mv.empty()) continue;
            UniValue r{UniValue::VOBJ};
            r.pushKV("txid", bt::hex_encode(n.txid));
            r.pushKV("direction", n.incoming ? "in" : "out");
            r.pushKV("value", n64(n.value));
            r.pushKV("address", n.address.to_string());
            r.pushKV("height", n.height ? UniValue(uint64_t(*n.height)) : UniValue{});
            r.pushKV("pending", !n.height);
            if (n.height) {
                if (auto hash{m.node.block_hash_at(*n.height)}) {
                    if (auto hd{m.node.header(*hash)}) {
                        if (auto tm{m.main_time(hd->prev_main_hash)}) r.pushKV("time", *tm);
                    }
                }
            }
            if (mv.text) r.pushKV("text", *mv.text);
            else r.pushKV("hex", mv.hex);
            out.push_back(r);
        }
        return out;
    };
    P["zside.memos"] = {SHIELDED_READ};
    H["zside.pool"] = [&m](const UniValue&, HostEnv&) { return m.pool(); };
    P["zside.pool"] = {"get_block"};

    // Events: the chain's to a reader of the chain; the wallet's amounts to a reader of them (getbalances: both balances);
    // its transactions (shielded ones too: which shielded transaction is the wallet's) to a reader of both accounts.
    chain.event_privileges = {{"tip", {"getblockchaininfo"}},
                              {"connections", {"getblockchaininfo"}},
                              {"alert", {"getblockchaininfo"}},
                              {"mainlink", {"getblockchaininfo"}},
                              {"wallet.loaded", {"getbalances"}},
                              {"wallet.unloaded", {"getbalances"}},
                              {"wallet.balance", {"getbalances"}},
                              {"wallet.tx", {"getbalances", WALLET_READ, SHIELDED_READ}}};
    chain.snapshot = [&m] { return m.poller ? m.poller->snapshot() : UniValue{UniValue::VOBJ}; };
    host_ = std::make_unique<bt::appui::RemoteHost>(std::move(chain), bt::appui::HostOptions{m.options.chooser, m.options.file_dir}, *server_);
    m.poller = std::make_unique<bt::appui::Poller>(host_->events(), WALLET_NAME, [&m] { return m.look(); });
    if (!server_->listen(err)) return false;
    m.link->start();
    m.poller->start();
    LOG_INFO("app RPC on 127.0.0.1:%u (%zu methods; the LayerTwo RPC is not changed by it)", unsigned(server_->port()), server_->methods().size());
    return true;
}

void AppLayer::stop()
{
    if (!m_) return;
    if (m_->poller) m_->poller->stop();
    if (m_->link) m_->link->stop();
    if (host_) host_->stop();
    if (server_) server_->stop();
}

std::vector<std::string> AppLayer::app_methods() const
{
    std::vector<std::string> out{server_ ? server_->methods() : std::vector<std::string>{}};
    return out;
}

UniValue AppLayer::manifest() const
{
    // What a pack of zSide's pages uses of this node (the unified wallet names it in the app's whitelist): the reads of
    // the pages, the confirmed methods, the host methods, and the host's own methods.
    UniValue o{UniValue::VOBJ};
    o.pushKV("stem", "zside");
    o.pushKV("hostApi", bt::appui::HOST_API);
    UniValue reads{UniValue::VARR};
    for (const char* r : SHELL_READS) reads.push_back(r);
    for (const std::string& r : l2l_reads()) reads.push_back(r);
    o.pushKV("reads", reads);
    UniValue confirmed{UniValue::VARR};
    for (const char* c : CONFIRMED) confirmed.push_back(c);
    o.pushKV("confirmed", confirmed);
    UniValue host{UniValue::VARR};
    for (const char* h : HOST_METHODS) host.push_back(h);
    o.pushKV("host", host);
    UniValue protocol{UniValue::VARR};
    for (const char* p : {"webuihost", "describeconfirmation", "webuievents", "webuichosenfile", "appserverproof"}) protocol.push_back(p);
    o.pushKV("protocol", protocol);
    return o;
}

} // namespace zside
