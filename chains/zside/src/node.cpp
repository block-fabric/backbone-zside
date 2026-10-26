// Copyright (c) 2026 The Backbone developers
// Distributed under the MIT software license.
#include <zside/node.h>

#include <bt/fsperm.h>
#include <bt/log.h>
#include <bt/parse.h>

#include <algorithm>
#include <chrono>
#include <filesystem>

namespace zside {

using bt::kv::Txn;
using bt::mainchain::TwoWayPegData;

static int64_t now_s()
{
    return std::chrono::duration_cast<std::chrono::seconds>(std::chrono::steady_clock::now().time_since_epoch()).count();
}

static constexpr uint8_t T_PEERS = 80;         // known peers (host:port)
static constexpr uint8_t T_MAIN_STAGE = 81;    // ancestor sync staging (height BE -> info)

Node::Node(NodeConfig cfg) : cfg_(std::move(cfg)) {}

Node::~Node() { stop(); }

bool Node::start(std::string& err)
{
    if (!bt::fsperm::private_dir(cfg_.datadir)) {
        err = "cannot create " + cfg_.datadir;
        return false;
    }
    try {
        store_ = bt::kv::open_sqlite(cfg_.datadir + "/backbone-zside.sqlite");
        if (cfg_.rebuild_side_tips) {
            Txn t(*store_);
            side_tips_.clear(t);
            t.commit();
            LOG_INFO("side tips cleared; rebuilt from the mainchain at the first sync");
        }
    } catch (const std::exception& e) {
        err = e.what();
        return false;
    }
    enforcer_ = std::make_unique<bt::enforcer::Client>(cfg_.mainchain_grpc_url, THIS_SIDECHAIN, cfg_.mainchain_grpc_ca_cert);
    magic_ = cfg_.magic_override ? *cfg_.magic_override : net::magic_bytes(cfg_.network);
    running_ = true;
    main_thread_ = std::thread([this] { mainchain_loop(); });
    if (cfg_.p2p) {
        bt::quic::Callbacks cb;
        cb.on_connected = [this](bt::quic::ConnId c, const bt::quic::SockAddr& a, bool inbound) {
            std::unique_lock<std::mutex> l(peers_mu_);
            // Bans hold for inbound connections too (review 2026-10-22: outbound dials only before).
            if (bt::sidechain::ban_active(banned_, a.ip, now_s())) {
                l.unlock();
                LOG_INFO("refusing banned peer %s", a.to_string().c_str());
                ep_->close(c, "banned"); // only queues the drop on the I/O loop
                return;
            }
            auto& p = peers_[c];
            p.conn = c;
            p.addr = a;
            p.inbound = inbound;
            p.connected = true;
            p.name = ep_->peer_name(c);
            LOG_INFO("peer %s connected (%s, %s)", a.to_string().c_str(), inbound ? "inbound" : "outbound", p.name.c_str());
        };
        // never take the node lock on the QUIC I/O thread
        cb.on_request = [this](bt::quic::ConnId c, int64_t s, Bytes p) { post_serve([this, c, s, p = std::move(p)]() mutable { on_request(c, s, std::move(p)); }); };
        cb.on_closed = [this](bt::quic::ConnId c, const std::string& why) {
            std::lock_guard<std::mutex> l(peers_mu_);
            auto it = peers_.find(c);
            if (it != peers_.end()) {
                LOG_INFO("peer %s disconnected: %s", it->second.addr.to_string().c_str(), why.c_str());
                if (!it->second.dial.empty()) dial_targets_[it->second.dial] = now_s() + 10;
                peers_.erase(it);
            }
        };
        bt::quic::Options opt;
        opt.server_names = cfg_.server_names;
        opt.max_request_bytes = net::READ_REQUEST_LIMIT;
        ep_ = std::make_unique<bt::quic::Endpoint>(cb, opt);
        if (!ep_->start(cfg_.net_addr, err)) return false;
        LOG_INFO("P2P listening on %s (magic %s)", ep_->local_address().to_string().c_str(), bt::hex_encode(bt::ByteSpan(magic_.data(), 4)).c_str());
        if (cfg_.use_seeds && cfg_.network == net::Network::Betanet)
            // lib/net/mod.rs:167-178, plus (ours) seed.beta.ecash.eu.com: on 2026-10-22 the only one of
            // the three that served zSide blocks; theirs list only the first two
            for (const char* s : {"seed.beta.ecash.drivecha.in", "seed.beta.ecash.ninja", "seed.beta.ecash.eu.com"})
                dial_targets_[std::string(s) + ":" + std::to_string(net::DEFAULT_PORT)] = 0;
        for (auto& p : cfg_.add_peers)
            if (bt::split_hostport(p, net::DEFAULT_PORT)) dial_targets_[p] = 0;
            else LOG_WARN("ignoring invalid --add-peer '%s'", p.c_str());
        {
            Txn t(*store_);
            t.scan(T_PEERS, [&](bt::ByteSpan k, bt::ByteSpan) {
                std::string hp(k.begin(), k.end());
                if (bt::split_hostport(hp)) dial_targets_[hp] = 0;
                return true;
            });
        }
        net_thread_ = std::thread([this] { net_loop(); });
        worker_thread_ = std::thread([this] { worker_loop(); });
        serve_thread_ = std::thread([this] { serve_loop(); });
    }
    return true;
}

void Node::stop()
{
    if (!running_.exchange(false)) return;
    jobs_cv_.notify_all();
    if (main_thread_.joinable()) main_thread_.join();
    if (net_thread_.joinable()) net_thread_.join();
    if (worker_thread_.joinable()) worker_thread_.join();
    serve_cv_.notify_all();
    if (serve_thread_.joinable()) serve_thread_.join();
    if (ep_) ep_->stop();
    ep_.reset();
}

// ------------------------------------------------------------------ queries
std::optional<Hash32> Node::tip()
{
    std::lock_guard<std::recursive_mutex> l(mu_);
    Txn t(*store_);
    return state_.tip(t);
}
std::optional<uint32_t> Node::height()
{
    std::lock_guard<std::recursive_mutex> l(mu_);
    Txn t(*store_);
    return state_.height(t);
}
std::optional<Hash32> Node::block_hash_at(uint32_t h)
{
    // node/mod.rs:466-486: walk back from the tip
    std::lock_guard<std::recursive_mutex> l(mu_);
    Txn t(*store_);
    auto tp = state_.tip(t);
    auto ht = state_.height(t);
    if (!tp || !ht || h > *ht) return std::nullopt;
    return archive_.nth_ancestor(t, *tp, *ht - h);
}
std::optional<Header> Node::header(const Hash32& h)
{
    std::lock_guard<std::recursive_mutex> l(mu_);
    Txn t(*store_);
    return archive_.header(t, h);
}
std::optional<Body> Node::body(const Hash32& h)
{
    std::lock_guard<std::recursive_mutex> l(mu_);
    Txn t(*store_);
    return archive_.body(t, h);
}
std::optional<Hash32> Node::best_main_verification(const Hash32& side)
{
    std::lock_guard<std::recursive_mutex> l(mu_);
    Txn t(*store_);
    return archive_.best_main_verification(t, side);
}
std::vector<Hash32> Node::bmm_inclusions(const Hash32& side)
{
    std::lock_guard<std::recursive_mutex> l(mu_);
    Txn t(*store_);
    std::vector<Hash32> r;
    for (auto& [m, res] : archive_.bmm_results(t, side))
        if (res == BmmResult::Verified) r.push_back(m);
    return r;
}
std::vector<std::pair<OutPoint, Output>> Node::utxos()
{
    std::lock_guard<std::recursive_mutex> l(mu_);
    Txn t(*store_);
    return state_.utxos(t);
}
std::vector<std::pair<OutPoint, Output>> Node::utxos_by_addresses(const std::set<Address>& a)
{
    std::vector<std::pair<OutPoint, Output>> r;
    for (auto& [op, o] : utxos())
        if (a.count(o.address)) r.emplace_back(op, o);
    return r;
}
std::vector<std::pair<OutPoint, SpentOutput>> Node::stxos_by_addresses(const std::set<Address>& a)
{
    std::lock_guard<std::recursive_mutex> l(mu_);
    Txn t(*store_);
    std::vector<std::pair<OutPoint, SpentOutput>> r;
    for (auto& [op, s] : state_.stxos(t))
        if (a.count(s.output.address)) r.emplace_back(op, s);
    return r;
}
std::optional<std::pair<Transaction, std::optional<Hash32>>> Node::transaction(const Hash32& txid)
{
    std::lock_guard<std::recursive_mutex> l(mu_);
    Txn t(*store_);
    auto tp = state_.tip(t);
    if (tp)
        for (auto& [bh, idx] : archive_.tx_inclusions(t, txid))
            if (archive_.header(t, bh) && archive_.is_descendant(t, bh, *tp)) {
                auto b = archive_.body(t, bh);
                if (b && idx < b->transactions.size()) return std::make_pair(b->transactions[idx], std::optional<Hash32>(bh));
            }
    auto it = mempool_.find(txid);
    if (it != mempool_.end()) return std::make_pair(it->second.transaction, std::optional<Hash32>());
    return std::nullopt;
}
std::optional<std::pair<WithdrawalBundleInfo, BundleStatus>> Node::withdrawal_bundle(const Hash32& m6id)
{
    std::lock_guard<std::recursive_mutex> l(mu_);
    Txn t(*store_);
    auto b = state_.bundle(t, m6id);
    if (!b) return std::nullopt;
    return std::make_pair(b->first, b->second.latest().value);
}
std::optional<WithdrawalBundle> Node::pending_withdrawal_bundle()
{
    std::lock_guard<std::recursive_mutex> l(mu_);
    Txn t(*store_);
    auto p = state_.pending_bundle(t);
    if (!p) return std::nullopt;
    return p->first;
}
std::optional<uint32_t> Node::latest_failed_withdrawal_bundle_height()
{
    std::lock_guard<std::recursive_mutex> l(mu_);
    Txn t(*store_);
    auto f = state_.latest_failed_bundle(t);
    if (!f) return std::nullopt;
    return f->first;
}
uint64_t Node::sidechain_wealth()
{
    std::lock_guard<std::recursive_mutex> l(mu_);
    Txn t(*store_);
    return state_.sidechain_wealth(t);
}
bt::utreexo::MemForest Node::tip_accumulator()
{
    std::lock_guard<std::recursive_mutex> l(mu_);
    Txn t(*store_);
    return state_.accumulator(t);
}
std::vector<PeerView> Node::peers()
{
    std::lock_guard<std::mutex> l(peers_mu_);
    std::vector<PeerView> r;
    for (auto& [c, p] : peers_) r.push_back({p.addr, p.connected, p.inbound, p.name});
    return r;
}

std::string Node::status()
{
    auto h = height();
    size_t np;
    {
        std::lock_guard<std::mutex> l(peers_mu_);
        np = peers_.size();
    }
    return "height " + (h ? std::to_string(*h) : std::string("none")) + ", " + std::to_string(np) + " peers, " + std::to_string(mempool_.size()) + " mempool txs";
}

// ------------------------------------------------------------------ mempool (lib/mempool.rs)
// lib/mempool/mod.rs insert (:57-100): no shared input, no shared nullifier.
void Node::mempool_put(const AuthorizedTransaction& tx)
{
    Hash32 txid = tx.transaction.txid();
    if (mempool_.count(txid)) return;
    if (auto e = tx_self_conflict(tx.transaction)) throw StateError(*e);
    for (auto& [op, _] : tx.transaction.inputs)
        if (mempool_spent_.count(op.key())) throw StateError("UtxoDoubleSpent");
    if (tx.transaction.orchard_bundle)
        for (auto& a : tx.transaction.orchard_bundle->actions)
            if (mempool_nullifiers_.count(a.nf)) throw StateError("NullifierDoubleSpent");
    for (auto& [op, _] : tx.transaction.inputs) mempool_spent_[op.key()] = txid;
    if (tx.transaction.orchard_bundle)
        for (auto& a : tx.transaction.orchard_bundle->actions) mempool_nullifiers_[a.nf] = txid;
    mempool_[txid] = tx;
}

void Node::mempool_delete(const Hash32& txid)
{
    std::deque<Hash32> q{txid};
    while (!q.empty()) {
        Hash32 id = q.front();
        q.pop_front();
        auto it = mempool_.find(id);
        if (it == mempool_.end()) continue;
        for (auto& [op, _] : it->second.transaction.inputs) mempool_spent_.erase(op.key());
        if (it->second.transaction.orchard_bundle)
            for (auto& a : it->second.transaction.orchard_bundle->actions) mempool_nullifiers_.erase(a.nf);
        size_t nout = it->second.transaction.outputs.size();
        mempool_.erase(it);
        for (uint32_t v = 0; v < nout; v++) {
            auto s = mempool_spent_.find(OutPoint{OutPoint::Regular, id, v}.key());
            if (s != mempool_spent_.end()) q.push_back(s->second);
        }
    }
}

void Node::mempool_regenerate_proofs(Txn& t)
{
    auto acc = state_.accumulator(t);
    std::vector<Hash32> ids;
    for (auto& [id, _] : mempool_) ids.push_back(id);
    for (auto& id : ids) {
        auto it = mempool_.find(id);
        if (it == mempool_.end()) continue;
        std::vector<bt::utreexo::NodeHash> targets;
        for (auto& [op, uh] : it->second.transaction.inputs) targets.push_back(bt::utreexo::NodeHash::some(uh));
        auto p = acc.prove(targets);
        if (p) it->second.transaction.proof = *p;
        else mempool_delete(id);
    }
}

std::pair<std::vector<std::pair<AuthorizedTransaction, std::vector<Output>>>, uint64_t> Node::mempool_transactions(size_t n)
{
    std::lock_guard<std::recursive_mutex> l(mu_);
    Txn t(*store_);
    std::vector<std::pair<AuthorizedTransaction, std::vector<Output>>> r;
    uint64_t fee = 0;
    std::set<std::array<uint8_t, 37>> spent;
    std::set<Hash32> nfs;
    auto tip_acc = state_.accumulator(t);
    std::vector<AuthorizedTransaction> take;
    for (auto& [id, tx] : mempool_) {
        if (take.size() >= n) break;
        take.push_back(tx);
    }
    for (auto& tx : take) {
        bool conflict = false;
        for (auto& [op, _] : tx.transaction.inputs)
            if (spent.count(op.key())) conflict = true;
        // Policy (consensus-neutral): a tx re-spending a nullifier already in the chain is not
        // put in a template.
        if (tx.transaction.orchard_bundle)
            for (auto& a : tx.transaction.orchard_bundle->actions)
                if (nfs.count(a.nf) || state_.orchard_nullifier(t, a.nf)) conflict = true;
        Hash32 txid = tx.transaction.txid();
        if (conflict) {
            mempool_delete(txid);
            continue;
        }
        uint64_t f;
        try {
            f = state_.validate_transaction(t, tx);
            // Hardening: a stale utreexo proof would make the whole template invalid.
            std::vector<bt::utreexo::NodeHash> spent;
            for (auto& [op, uh] : tx.transaction.inputs) spent.push_back(bt::utreexo::NodeHash::some(uh));
            auto ok = tip_acc.verify(tx.transaction.proof, spent);
            if (!ok || !*ok) throw StateError("stale utreexo proof");
        } catch (const StateError&) {
            mempool_delete(txid);
            continue;
        }
        std::vector<Output> spent_outs;
        for (auto& [op, _] : tx.transaction.inputs) spent_outs.push_back(*state_.utxo(t, op));
        fee += f;
        for (auto& [op, _] : tx.transaction.inputs) spent.insert(op.key());
        if (tx.transaction.orchard_bundle)
            for (auto& a : tx.transaction.orchard_bundle->actions) nfs.insert(a.nf);
        r.emplace_back(tx, spent_outs);
    }
    return {r, fee};
}

void Node::submit_transaction(AuthorizedTransaction& tx)
{
    {
        std::lock_guard<std::recursive_mutex> l(mu_);
        Txn t(*store_);
        auto acc = state_.accumulator(t);
        std::vector<bt::utreexo::NodeHash> targets;
        for (auto& [op, uh] : tx.transaction.inputs) targets.push_back(bt::utreexo::NodeHash::some(uh));
        auto p = acc.prove(targets);
        if (!p) throw StateError("Utreexo: cannot prove inputs");
        tx.transaction.proof = *p;
        state_.validate_transaction(t, tx);
        // Policy (kept): their validate_transaction does not look at chain nullifiers.
        if (tx.transaction.orchard_bundle)
            for (auto& a : tx.transaction.orchard_bundle->actions)
                if (state_.orchard_nullifier(t, a.nf)) throw StateError("NullifierDoubleSpent (already in the chain)");
        mempool_put(tx);
    }
    relay_tx(tx, std::nullopt);
}

std::vector<AuthorizedTransaction> Node::mempool()
{
    std::lock_guard<std::recursive_mutex> l(mu_);
    std::vector<AuthorizedTransaction> r;
    for (auto& [_, tx] : mempool_) r.push_back(tx);
    return r;
}

void Node::remove_from_mempool(const Hash32& txid)
{
    std::lock_guard<std::recursive_mutex> l(mu_);
    mempool_delete(txid);
}

void Node::invalidate_block(const Hash32& h)
{
    std::lock_guard<std::recursive_mutex> l(mu_);
    Txn t(*store_);
    // node/mod.rs:289-317: disconnect while the tip descends from the block, then mark it
    while (auto tp = state_.tip(t)) {
        if (!archive_.header(t, *tp) || !archive_.header(t, h) || !archive_.is_descendant(t, h, *tp)) break;
        disconnect_tip_(t);
    }
    // out of the side-tips index with its descendants (before mark_invalid drops the successor
    // lists), so the best ordered tip is never an invalidated block
    if (archive_.header(t, h)) side_tips_delete_body(t, archive_, side_tips_, h);
    archive_.mark_invalid(t, h);
    t.commit();
}

// ------------------------------------------------------------------ mainchain
bool Node::request_mainchain_ancestor_infos(const Hash32& main)
{
    std::lock_guard<std::mutex> ml(main_mu_);
    if (main.is_zero()) return true;
    {
        std::lock_guard<std::recursive_mutex> l(mu_);
        Txn t(*store_);
        if (archive_.main_header(t, main)) return true;
    }
    // Fetch ancestors newest-first in batches of 1000 (mainchain_task.rs:129-210), staged
    // on disk by height so the whole mainchain never has to sit in memory.
    Hash32 cur = main;
    uint64_t staged = 0;
    std::optional<uint32_t> lowest;
    for (;;) {
        if (!running_) return false;
        auto r = enforcer_->get_block_infos(cur, 999);
        if (!bt::enforcer::ok(r)) {
            LOG_WARN("GetBlockInfo %s: %s", bt::hex_encode_rev(cur.span()).c_str(), bt::enforcer::err(r).what().c_str());
            return false;
        }
        auto& infos = bt::enforcer::val(r);
        if (infos.empty()) return false;
        {
            Txn st(*store_);
            for (auto& [hi, bi] : infos) {
                Writer k;
                k.u32be(hi.height);
                Writer v;
                v.raw(hi.block_hash);
                v.raw(hi.prev_block_hash);
                v.raw(hi.work);
                enc_block_info(v, bi);
                st.put(T_MAIN_STAGE, k.buf, v.buf);
                staged++;
            }
            st.commit();
        }
        auto& last = infos.back().first;
        lowest = last.height;
        cur = last.prev_block_hash;
        if (staged % 50000 < 1000) LOG_INFO("mainchain sync: fetched back to height %u", last.height);
        if (cur.is_zero()) break;
        std::lock_guard<std::recursive_mutex> l(mu_);
        Txn t(*store_);
        if (archive_.main_header(t, cur)) break;
    }
    // apply oldest-first
    std::lock_guard<std::recursive_mutex> l(mu_);
    std::vector<std::pair<Bytes, Bytes>> rows;
    {
        Txn t(*store_);
        t.scan(T_MAIN_STAGE, [&](bt::ByteSpan k, bt::ByteSpan v) {
            rows.emplace_back(Bytes(k.begin(), k.end()), Bytes(v.begin(), v.end()));
            return true;
        });
    }
    size_t i = 0;
    while (i < rows.size()) {
        Txn t(*store_);
        for (size_t n = 0; n < 20000 && i < rows.size(); n++, i++) {
            Reader kr(rows[i].first);
            Reader r(rows[i].second);
            bt::mainchain::BlockHeaderInfo hi;
            hi.height = uint32_t(rows[i].first[0]) << 24 | uint32_t(rows[i].first[1]) << 16 | uint32_t(rows[i].first[2]) << 8 | rows[i].first[3];
            hi.block_hash = r.array<32>();
            hi.prev_block_hash = r.array<32>();
            hi.work = r.array<32>();
            auto bi = dec_block_info(r);
            if (!archive_.main_header(t, hi.block_hash)) {
                archive_.put_main_header_info(t, hi);
                archive_.put_main_block_info(t, hi.block_hash, bi);
            }
            t.del(T_MAIN_STAGE, rows[i].first);
        }
        t.commit();
    }
    LOG_DEBUG("mainchain sync: stored %zu header infos", rows.size());
    return true;
}

void Node::mainchain_loop()
{
    std::optional<Hash32> last_tip;
    bool checked = false;
    while (running_) {
        if (!checked) {
            // app.rs:179-284: health check per service, falling back to GetChainTip
            auto h = enforcer_->health("cusf.mainchain.v1.ValidatorService");
            if (!h) {
                auto t = enforcer_->get_chain_tip();
                if (!bt::enforcer::ok(t)) LOG_WARN("mainchain: %s", bt::enforcer::err(t).what().c_str());
                else checked = true;
            } else {
                checked = true;
            }
        }
        auto t = enforcer_->get_chain_tip();
        if (bt::enforcer::ok(t)) {
            Hash32 mt = bt::enforcer::val(t).block_hash;
            if (mt != last_tip) {
                // a failed side-tips sync is retried on the next poll, as their mainchain task
                // restarts and fails again the same way
                if (request_mainchain_ancestor_infos(mt) && sync_to_mainchain_tip(mt)) last_tip = mt;
            }
        }
        for (int i = 0; i < 20 && running_; i++) std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }
}

// mainchain_task.rs sync_side_tips_to_tip + handle_block_event, then net_task.rs
// handle_mainchain_block_event (thunder-orchard b225827 has no thunder-rust 4df63d3). A
// mainchain reorg does NOT disconnect sidechain blocks whose BMM block left the active chain
// (quirk reproduced on purpose, side_tips.h): the state tip moves only when reorg_to_tip's
// better_tip prefers the best ordered side tip, or a peer's.
bool Node::sync_to_mainchain_tip(const Hash32& main_tip)
{
    size_t events = 0;
    {
        std::lock_guard<std::recursive_mutex> l(mu_);
        Txn t(*store_);
        {
            Writer w;
            w.raw(main_tip);
            t.put(Archive::A_MAIN_INFO + 100, Bytes{0}, w.buf); // remember the mainchain tip
        }
        try {
            events = sync_side_tips(t, archive_, side_tips_, main_tip);
        } catch (const std::exception& e) {
            LOG_ERROR("Mainchain task error: failed to sync side tips to %s: %s", bt::hex_encode_rev(main_tip.span()).c_str(), e.what());
            return false;
        }
        t.commit();
    }
    if (events) {
        handle_mainchain_block_event();
        // A peer tip seen before our side tips reached its main block was ignored
        // (side_tips_peer_tip_relevant); look at every peer's last tip again, as their peer
        // task does on its next heartbeat.
        std::vector<std::pair<bt::quic::ConnId, net::PeerState>> ps;
        {
            std::lock_guard<std::mutex> pl(peers_mu_);
            for (auto& [c, p] : peers_)
                if (p.state) ps.emplace_back(c, *p.state);
        }
        for (auto& [c, st] : ps) post_job([this, c, st] { handle_peer_state(c, st); });
    }
    return true;
}

// net_task.rs handle_mainchain_block_event
void Node::handle_mainchain_block_event()
{
    std::optional<std::pair<Hash32, SideTipInfo>> best;
    try {
        std::lock_guard<std::recursive_mutex> l(mu_);
        Txn t(*store_);
        while (auto tp = state_.tip(t)) {
            if (side_tips_.contains(t, *tp)) break;
            // theirs calls state.disconnect_tip only; reachable only after
            // --bt-rebuild-side-tips or invalidate_block (a mainchain reorg never gets here)
            LOG_WARN("state tip %s is not a side tip; disconnecting it", bt::hex_encode(*tp).c_str());
            disconnect_tip_(t);
        }
        best = side_tips_.best(t);
        if (best && archive_.invalid(t, best->first)) best.reset();
        t.commit();
    } catch (const std::exception& e) {
        LOG_ERROR("handle mainchain block event: %s", e.what());
        return;
    }
    if (!best) return;
    try {
        reorg_to_tip(TipRef{best->first, best->second.main_block_hash});
    } catch (const std::exception& e) {
        LOG_WARN("rejecting an invalid side tip %s: %s", bt::hex_encode(best->first).c_str(), e.what());
    }
}

/** submit_block: their mainchain task has normally handled the BMM block's ConnectBlock event
 *  before the miner submits, so the side tips first follow the enforcer's tip. */
bool Node::catch_up_mainchain()
{
    if (!enforcer_) return false;
    auto tr = enforcer_->get_chain_tip();
    if (!bt::enforcer::ok(tr)) return false;
    Hash32 mt = bt::enforcer::val(tr).block_hash;
    return request_mainchain_ancestor_infos(mt) && sync_to_mainchain_tip(mt);
}

void Node::put_body_(Txn& t, const Hash32& h, const Body& b)
{
    archive_.put_body(t, h, b);
    side_tips_put_body(t, archive_, side_tips_, h);
}

void Node::delete_body_(Txn& t, const Hash32& h)
{
    archive_.delete_body(t, h);
    side_tips_delete_body(t, archive_, side_tips_, h);
}

// ------------------------------------------------------------------ connect / reorg (net_task.rs)
std::vector<Hash32> Node::main_ancestors(const Txn& t, const Hash32& from, const std::optional<Hash32>& stop)
{
    std::vector<Hash32> r;
    Hash32 cur = from;
    while (!cur.is_zero()) {
        if (stop && cur == *stop) break;
        auto m = archive_.main_header(t, cur);
        if (!m) throw ArchiveError("NoMainHeaderInfo " + bt::hex_encode_rev(cur.span()));
        r.push_back(cur);
        cur = m->prev;
    }
    return r;
}

void Node::connect_tip_(Txn& t, const Header& h, const Body& b, const TwoWayPegData& d)
{
    Hash32 bh = h.hash();
    auto pre = state_.prevalidate(t, h, b);
    state_.connect_prevalidated(t, h, b, pre);
    state_.connect_2wpd(t, d);
    auto acc = state_.accumulator(t);
    archive_.put_header(t, h);
    put_body_(t, bh, b);
    archive_.put_accumulator(t, bh, acc);
    for (auto& tx : b.transactions) mempool_delete(tx.txid());
    mempool_regenerate_proofs(t);
}

// net_task.rs:139-260
void Node::disconnect_tip_(Txn& t)
{
    auto tip_hash = state_.tip(t);
    if (!tip_hash) throw StateError("NoTip");
    Header th = *archive_.header(t, *tip_hash);
    Body tb = *archive_.body(t, *tip_hash);
    uint32_t height = *state_.height(t);
    auto last_applied = [&](const std::vector<std::pair<uint32_t, std::pair<Hash32, uint32_t>>>& rows) -> std::optional<std::pair<Hash32, uint32_t>> {
        // rev_iter in key (memcmp) order, first entry applied below this height
        for (auto it = rows.rbegin(); it != rows.rend(); ++it)
            if (it->second.second < height) return it->second;
        return std::nullopt;
    };
    auto dep = last_applied(state_.deposit_blocks(t));
    auto wd = last_applied(state_.bundle_event_blocks(t));
    std::optional<Hash32> start;
    if (dep && !wd) start = dep->first;
    else if (!dep && wd) start = wd->first;
    else if (dep && wd) {
        if (dep->second < wd->second) start = wd->first;
        else if (dep->second > wd->second) start = dep->first;
        else start = archive_.is_main_descendant(t, wd->first, dep->first) ? wd->first : dep->first;
    }
    TwoWayPegData d;
    auto anc = main_ancestors(t, th.prev_main_hash, start);
    for (auto it = anc.rbegin(); it != anc.rend(); ++it) {
        auto bi = archive_.main_block_info(t, *it);
        if (!bi.events.empty()) d.block_info.emplace_back(*it, bi);
    }
    state_.disconnect_2wpd(t, d);
    state_.disconnect_tip(t, th, tb);
    // restore the accumulator snapshot of the new tip (rustreexo has no undo)
    if (auto nt = state_.tip(t)) {
        auto acc = archive_.accumulator(t, *nt);
        if (!acc) throw StateError("missing accumulator snapshot", true);
        state_.put_accumulator(t, *acc);
    } else {
        t.del(State::T_ACCUMULATOR, Bytes{});
    }
    auto txs = tb.authorized_transactions();
    for (auto it = txs.rbegin(); it != txs.rend(); ++it) {
        try {
            mempool_put(*it);
        } catch (const StateError&) {
        }
    }
    mempool_regenerate_proofs(t);
}

// net_task.rs:267-449
bool Node::reorg_to_tip(const TipRef& new_tip)
{
    std::lock_guard<std::recursive_mutex> l(mu_);
    Txn t(*store_);
    auto tip_hash = state_.tip(t);
    auto tip_height = state_.height(t);
    std::optional<TipRef> tip;
    if (tip_hash) {
        auto bv = archive_.best_main_verification(t, *tip_hash);
        if (!bv) throw ArchiveError("NoBmmResult");
        tip = TipRef{*tip_hash, *bv};
        if (archive_.better_tip(t, *tip, new_tip) != std::optional<TipRef>(new_tip)) return false;
    }
    std::optional<Hash32> common;
    if (tip) common = archive_.last_common_ancestor(t, tip->block_hash, new_tip.block_hash);
    // blocks to apply, newest first
    std::vector<std::pair<Header, Body>> apply;
    {
        std::optional<Hash32> cur = new_tip.block_hash;
        while (cur && cur != common) {
            auto h = archive_.header(t, *cur);
            auto b = archive_.body(t, *cur);
            if (!h || !b) return false;
            apply.emplace_back(*h, *b);
            cur = h->prev_side_hash;
        }
    }
    if (tip_height) {
        uint32_t disconnects = common ? *tip_height - *archive_.height(t, *common) : *tip_height + 1;
        for (uint32_t i = 0; i < disconnects; i++) disconnect_tip_(t);
    }
    std::optional<Hash32> common_prev_main;
    if (common) common_prev_main = archive_.header(t, *common)->prev_main_hash;
    auto batch_hashes = main_ancestors(t, apply.front().first.prev_main_hash, common_prev_main);
    // batch: newest first; pop from the back = oldest first
    for (auto it = apply.rbegin(); it != apply.rend(); ++it) {
        auto& [h, b] = *it;
        TwoWayPegData d;
        while (!batch_hashes.empty()) {
            Hash32 mh = batch_hashes.back();
            batch_hashes.pop_back();
            d.block_info.emplace_back(mh, archive_.main_block_info(t, mh)); // ancestors are distinct: replace == append
            if (mh == h.prev_main_hash) break;
        }
        try {
            connect_tip_(t, h, b, d);
        } catch (const StateError& e) {
            LOG_WARN("block %s rejected: %s%s", bt::hex_encode(h.hash()).c_str(), e.what(), e.panic ? " (their node would panic)" : "");
            Txn dt(*store_);
            delete_body_(dt, h.hash());
            dt.commit();
            return false;
        }
        auto nt = *state_.tip(t);
        auto bv = archive_.best_main_verification(t, nt);
        TipRef ntr{nt, bv ? *bv : Hash32{}};
        if (tip && archive_.better_tip(t, *tip, ntr) != std::optional<TipRef>(ntr)) continue;
        t.commit();
    }
    t.commit();
    LOG_INFO("synced to tip %s (height %u)", bt::hex_encode(new_tip.block_hash).c_str(), *state_.height(t));
    return true;
}

// node/mod.rs:720-858
bool Node::submit_block(const Hash32& main_block_hash, const Header& h, const Body& b)
{
    Hash32 bh = h.hash();
    {
        std::lock_guard<std::recursive_mutex> l(mu_);
        Txn t(*store_);
        if (h.prev_side_hash && !archive_.header(t, *h.prev_side_hash)) {
            LOG_ERROR("Rejecting block %s due to missing ancestor headers", bt::hex_encode(bh).c_str());
            return false;
        }
    }
    if (!request_mainchain_ancestor_infos(main_block_hash)) return false;
    catch_up_mainchain();
    {
        std::lock_guard<std::recursive_mutex> l(mu_);
        Txn t(*store_);
        archive_.put_header(t, h);
        t.commit();
        Txn r(*store_);
        auto res = archive_.bmm_results(r, bh);
        auto it = res.find(main_block_hash);
        if (it == res.end() || it->second != BmmResult::Verified) {
            LOG_ERROR("Rejecting block %s due to failing BMM verification", bt::hex_encode(bh).c_str());
            return false;
        }
        auto tp = state_.tip(r);
        std::optional<Hash32> common;
        if (tp) common = archive_.last_common_ancestor(r, *tp, bh);
        auto missing = archive_.missing_bodies(r, bh, common);
        if (!(missing.empty() || missing == std::vector<Hash32>{bh})) {
            LOG_ERROR("Rejecting block %s due to missing ancestor bodies", bt::hex_encode(bh).c_str());
            return false;
        }
        if (missing == std::vector<Hash32>{bh}) {
            Txn w(*store_);
            put_body_(w, bh, b);
            w.commit();
        }
    }
    bool ready;
    {
        std::lock_guard<std::recursive_mutex> l(mu_);
        Txn t(*store_);
        ready = side_tips_tip_ready(t, archive_, side_tips_, TipRef{bh, main_block_hash}); // NewTipReady
    }
    if (!ready || !reorg_to_tip(TipRef{bh, main_block_hash})) {
        LOG_WARN("Not ready to reorg to %s", bt::hex_encode(bh).c_str());
        return false;
    }
    if (auto p = pending_withdrawal_bundle()) {
        auto r = enforcer_->propose_withdrawal_bundle(p->tx_bytes());
        if (!bt::enforcer::ok(r)) LOG_ERROR("Failed to broadcast withdrawal bundle %s; will retry on next block: %s", bt::hex_encode_rev(p->m6id().span()).c_str(), bt::enforcer::err(r).what().c_str());
    }
    return true;
}

// ------------------------------------------------------------------ P2P
bool Node::connect_peer(const std::string& hostport_in, std::string& err)
{
    auto hp = bt::split_hostport(hostport_in, net::DEFAULT_PORT);
    if (!hp) {
        err = "invalid peer address";
        return false;
    }
    std::string hostport = hp->first.find(':') != std::string::npos ? "[" + hp->first + "]:" + std::to_string(hp->second) : hp->first + ":" + std::to_string(hp->second);
    if (!ep_) {
        err = "P2P disabled";
        return false;
    }
    {
        Txn t(*store_);
        t.put(T_PEERS, bt::ByteSpan((const uint8_t*)hostport.data(), hostport.size()), {});
        t.commit();
    }
    std::lock_guard<std::mutex> l(peers_mu_);
    dial_targets_[hostport] = 0;
    return true;
}

bool Node::forget_peer(const std::string& hostport)
{
    Txn t(*store_);
    bool existed = t.del(T_PEERS, bt::ByteSpan((const uint8_t*)hostport.data(), hostport.size()));
    t.commit();
    std::lock_guard<std::mutex> l(peers_mu_);
    dial_targets_.erase(hostport);
    return existed;
}

void Node::post_job(std::function<void()> f)
{
    {
        std::lock_guard<std::mutex> l(jobs_mu_);
        jobs_.push_back(std::move(f));
    }
    jobs_cv_.notify_one();
}

std::optional<net::TipInfo> Node::our_tip_info()
{
    std::lock_guard<std::recursive_mutex> l(mu_);
    Txn t(*store_);
    auto tp = state_.tip(t);
    if (!tp) return std::nullopt;
    auto bv = archive_.best_main_verification(t, *tp);
    if (!bv) return std::nullopt;
    net::TipInfo ti;
    ti.block_height = *state_.height(t);
    ti.tip = {*tp, *bv};
    ti.total_work_be = archive_.total_work(t, *bv).to_be();
    return ti;
}

void Node::send_request(bt::quic::ConnId c, const net::Request& q, size_t limit, std::function<void(std::optional<net::Response>)> fn)
{
    Bytes payload(magic_.begin(), magic_.end());
    append(payload, net::encode(q));
    if (!limit) {
        ep_->send(c, std::move(payload), 0, std::chrono::milliseconds(0), nullptr);
        return;
    }
    // response_read_timeout: 5 s + limit / 64 KiB/s
    auto timeout = std::chrono::milliseconds(5000 + uint64_t(limit) / (64 * 1024) * 1000);
    auto magic = magic_;
    ep_->send(c, std::move(payload), limit + 4, timeout, [this, fn, magic](std::optional<Bytes> r) {
        if (!r || r->size() < 4 || !std::equal(magic.begin(), magic.end(), r->begin())) {
            post_job([fn] { fn(std::nullopt); });
            return;
        }
        std::optional<net::Response> resp;
        try {
            resp = net::decode_response(bt::ByteSpan(r->data() + 4, r->size() - 4));
        } catch (const std::exception&) {
        }
        post_job([fn, resp] { fn(resp); });
    });
}

void Node::relay_tx(const AuthorizedTransaction& tx, std::optional<bt::quic::ConnId> except)
{
    if (!ep_) return;
    std::vector<bt::quic::ConnId> targets;
    {
        std::lock_guard<std::mutex> l(peers_mu_);
        for (auto& [c, p] : peers_)
            if (p.connected && c != except) targets.push_back(c);
    }
    net::Request q;
    q.kind = net::Request::PushTransaction;
    q.tx = tx;
    for (auto c : targets) send_request(c, q, net::TX_ACK_LIMIT, [](std::optional<net::Response>) {});
}

void Node::ban(bt::quic::ConnId c, const std::string& why)
{
    std::string ip;
    {
        std::lock_guard<std::mutex> l(peers_mu_);
        auto it = peers_.find(c);
        if (it == peers_.end()) return;
        ip = it->second.addr.ip;
        banned_[bt::sidechain::rate_key(ip)] = now_s() + 3600;
    }
    LOG_WARN("banning peer %s: %s", ip.c_str(), why.c_str());
    ep_->close(c, "banned: " + why);
}

void Node::ban_address(const std::string& ip, int64_t seconds)
{
    std::vector<bt::quic::ConnId> close;
    {
        std::lock_guard<std::mutex> l(peers_mu_);
        banned_[bt::sidechain::rate_key(ip)] = now_s() + seconds;
        for (auto& [c, p] : peers_)
            if (bt::sidechain::rate_key(p.addr.ip) == bt::sidechain::rate_key(ip)) close.push_back(c);
    }
    for (auto c : close)
        if (ep_) ep_->close(c, "banned");
}

// Requests from peers (peer/task.rs:640-820)
void Node::on_request(bt::quic::ConnId c, int64_t stream, Bytes payload)
{
    std::string peer_ip;
    {
        // Fail closed: a connection not known as connected, or a banned one, is closed.
        std::lock_guard<std::mutex> l(peers_mu_);
        auto it = peers_.find(c);
        if (it == peers_.end() || !it->second.connected) {
            ep_->close(c, "unknown connection");
            return;
        }
        peer_ip = it->second.addr.ip;
        if (bt::sidechain::ban_active(banned_, peer_ip, now_s())) {
            ep_->close(c, "banned");
            return;
        }
    }
    if (payload.size() < 4 || !std::equal(magic_.begin(), magic_.end(), payload.begin())) {
        ep_->close(c, "bad magic");
        return;
    }
    net::Request q;
    try {
        q = net::decode_request(bt::ByteSpan(payload.data() + 4, payload.size() - 4));
    } catch (const std::exception& e) {
        ep_->close(c, std::string("bad request: ") + e.what());
        return;
    }
    auto respond = [&](const net::Response& r) {
        Bytes out(magic_.begin(), magic_.end());
        append(out, net::encode(r));
        ep_->respond(c, stream, std::move(out));
    };
    switch (q.kind) {
    case net::Request::Heartbeat: {
        ep_->finish(c, stream);
        bool changed;
        {
            std::lock_guard<std::mutex> l(peers_mu_);
            auto it = peers_.find(c);
            if (it == peers_.end()) return; // gone meanwhile: never create entries here
            auto& p = it->second;
            Writer a, b;
            if (p.state) {
                net::Request old;
                old.heartbeat = *p.state;
                a.raw(net::encode(old));
            }
            b.raw(net::encode(q));
            changed = !p.state || a.buf != b.buf;
            // An unchanged peer tip is looked at again every 5 s: the first look can come before our mainchain sync
            // has its mainchain block (handle_peer_state returns at once for a tip that is ours).
            int64_t now = now_s();
            if (!changed && q.heartbeat.tip_info && now - p.last_sync_try >= 5) changed = true;
            if (changed) p.last_sync_try = now;
            p.state = q.heartbeat;
        }
        if (changed) post_job([this, c, ps = q.heartbeat] { handle_peer_state(c, ps); });
        return;
    }
    case net::Request::GetBlock: {
        net::Response r;
        std::lock_guard<std::recursive_mutex> l(mu_);
        Txn t(*store_);
        auto h = archive_.header(t, q.block_hash);
        auto b = archive_.body(t, q.block_hash);
        if (h && b) {
            r.kind = net::Response::Block;
            r.block = Block{*h, *b};
        } else {
            r.kind = net::Response::NoBlock;
            r.hash = q.block_hash;
        }
        respond(r);
        return;
    }
    case net::Request::GetHeaders: {
        {
            // At most GETHEADERS_PER_MINUTE per remote IP (/64 for IPv6, IPv4-mapped as IPv4), kept
            // across reconnects (core sidechain/node.h HeadersBudgets; was per connection): one small
            // request makes us walk and send the whole chain. Theirs asks about once per new peer tip.
            std::lock_guard<std::mutex> pl(peers_mu_);
            if (!headers_budgets_.take(peer_ip, now_s())) {
                LOG_WARN("peer %s: too many GetHeaders requests", peer_ip.c_str());
                ep_->close(c, "too many GetHeaders requests");
                return;
            }
        }
        net::Response r;
        std::lock_guard<std::recursive_mutex> l(mu_);
        Txn t(*store_);
        if (archive_.header(t, q.end)) {
            std::set<Hash32> start(q.start.begin(), q.start.end());
            r.kind = net::Response::Headers;
            std::optional<Hash32> cur = q.end;
            // Bounded walk: at most end's height + 1 headers. Never truncated otherwise: their
            // requester needs the complete answer ending at `end` (requests are rate-limited).
            auto eh = archive_.height(t, q.end);
            size_t max_headers = eh ? size_t(*eh) + 1 : 0;
            while (cur && !start.count(*cur) && r.headers.size() < max_headers) {
                auto h = archive_.header(t, *cur);
                if (!h) break;
                r.headers.push_back(*h);
                cur = h->prev_side_hash;
            }
            std::reverse(r.headers.begin(), r.headers.end());
        } else {
            r.kind = net::Response::NoHeader;
            r.hash = q.end;
        }
        respond(r);
        return;
    }
    case net::Request::PushTransaction: {
        Hash32 txid = q.tx.transaction.txid();
        net::Response r;
        r.hash = txid;
        bool ok = true;
        try {
            std::lock_guard<std::recursive_mutex> l(mu_);
            Txn t(*store_);
            state_.validate_transaction(t, q.tx);
        } catch (const std::exception&) {
            ok = false;
        }
        r.kind = ok ? net::Response::TransactionAccepted : net::Response::TransactionRejected;
        respond(r);
        if (ok) {
            post_job([this, tx = q.tx, c]() mutable {
                try {
                    std::lock_guard<std::recursive_mutex> l(mu_);
                    Txn t(*store_);
                    // Policy (kept): drop a tx re-spending a chain nullifier (their mempool takes it).
                    if (tx.transaction.orchard_bundle)
                        for (auto& a : tx.transaction.orchard_bundle->actions)
                            if (state_.orchard_nullifier(t, a.nf)) return;
                    // Hardening: the peer's utreexo proof is not checked by validate_transaction;
                    // regenerate it from our accumulator (as submit_transaction does) or drop it.
                    auto acc = state_.accumulator(t);
                    std::vector<bt::utreexo::NodeHash> targets;
                    for (auto& [op, uh] : tx.transaction.inputs) targets.push_back(bt::utreexo::NodeHash::some(uh));
                    auto p = acc.prove(targets);
                    if (!p) return;
                    tx.transaction.proof = *p;
                    mempool_put(tx);
                } catch (const std::exception&) {
                    return;
                }
                relay_tx(tx, c);
            });
        }
        return;
    }
    }
}

// peer/task.rs:60-640, simplified: we fetch any peer tip that is not ours and let
// reorg_to_tip's better_tip decide, after the same claimed-work and BMM checks.
void Node::handle_peer_state(bt::quic::ConnId c, const net::PeerState& ps)
{
    if (!ps.tip_info) return;
    const net::TipInfo pt = *ps.tip_info;
    LOG_DEBUG("peer tip %s height %u at main %s", bt::hex_encode(pt.tip.block_hash).c_str(), pt.block_height, bt::hex_encode_rev(pt.tip.main_block_hash.span()).c_str());
    {
        std::lock_guard<std::recursive_mutex> l(mu_);
        Txn t(*store_);
        auto ours = state_.tip(t);
        if (ours && *ours == pt.tip.block_hash) return;
        if (archive_.invalid(t, pt.tip.block_hash)) return;
    }
    if (!request_mainchain_ancestor_infos(pt.tip.main_block_hash)) return;
    {
        std::lock_guard<std::recursive_mutex> l(mu_);
        Txn t(*store_);
        auto mh = archive_.main_header(t, pt.tip.main_block_hash);
        if (!mh) return;
        // peer/task.rs:57-84: a peer tip whose main block is not on our side tips' mainchain is
        // ignored (no ban)
        if (!side_tips_peer_tip_relevant(t, archive_, side_tips_, pt.tip.main_block_hash)) return;
        if (archive_.total_work(t, pt.tip.main_block_hash).to_be() != pt.total_work_be) {
            ban(c, "IncorrectTotalWork");
            return;
        }
        auto info = archive_.main_block_info(t, pt.tip.main_block_hash);
        if (info.bmm_commitment != pt.tip.block_hash) {
            ban(c, "BmmVerificationFailed");
            return;
        }
        if (archive_.header(t, pt.tip.block_hash)) {
            start_body_chain(c, pt);
            return;
        }
        net::Request q;
        q.kind = net::Request::GetHeaders;
        q.end = pt.tip.block_hash;
        if (auto ours = state_.tip(t)) q.start = archive_.block_locator(t, *ours);
        uint32_t hh = std::min(pt.block_height, mh->height);
        send_request(c, q, net::headers_response_limit(hh), [this, c, pt](std::optional<net::Response> r) {
            if (!r || r->kind != net::Response::Headers) {
                LOG_DEBUG("GetHeaders: no headers (%s)", r ? "other response" : "error/timeout");
                return;
            }
            LOG_DEBUG("GetHeaders: %zu headers", r->headers.size());
            on_headers(c, pt, r->headers);
        });
    }
}

void Node::on_headers(bt::quic::ConnId c, const net::TipInfo& target, const std::vector<Header>& hs)
{
    for (auto& h : hs) {
        if (!request_mainchain_ancestor_infos(h.prev_main_hash)) return;
        std::lock_guard<std::recursive_mutex> l(mu_);
        Txn t(*store_);
        Hash32 bh = h.hash();
        if (archive_.header(t, bh)) continue;
        if (archive_.invalid(t, bh)) return;
        if (h.prev_side_hash && !archive_.header(t, *h.prev_side_hash)) {
            LOG_DEBUG("header %s: parent unknown", bt::hex_encode(bh).c_str());
            return;
        }
        archive_.put_header(t, h);
        t.commit();
    }
    {
        std::lock_guard<std::recursive_mutex> l(mu_);
        Txn t(*store_);
        auto r = archive_.bmm_results(t, target.tip.block_hash);
        auto it = r.find(target.tip.main_block_hash);
        if (it == r.end() || it->second != BmmResult::Verified) {
            ban(c, "BmmVerificationFailed");
            return;
        }
    }
    start_body_chain(c, target);
}

// At most one request_bodies chain per peer (review 2026-10-22).
void Node::start_body_chain(bt::quic::ConnId c, const net::TipInfo& target)
{
    {
        std::lock_guard<std::mutex> l(peers_mu_);
        auto it = peers_.find(c);
        if (it == peers_.end() || it->second.bodies_chain) return;
        it->second.bodies_chain = true;
    }
    request_bodies(c, target);
}

void Node::end_body_chain(bt::quic::ConnId c)
{
    std::lock_guard<std::mutex> l(peers_mu_);
    auto it = peers_.find(c);
    if (it != peers_.end()) it->second.bodies_chain = false;
}

// The bodies missing below the peer's tip, 100 a round, then the reorg. Only bodies stored count as progress: a round
// with none (NoBlock, a wrong block, timeouts) ends the chain and closes the connection (review 2026-10-22: a peer
// could keep us looping).
void Node::request_bodies(bt::quic::ConnId c, const net::TipInfo& target)
{
    std::vector<Hash32> missing;
    {
        std::lock_guard<std::recursive_mutex> l(mu_);
        Txn t(*store_);
        auto tp = state_.tip(t);
        std::optional<Hash32> common;
        if (tp) common = archive_.last_common_ancestor(t, *tp, target.tip.block_hash);
        missing = archive_.missing_bodies(t, target.tip.block_hash, common);
    }
    LOG_DEBUG("missing bodies for %s: %zu", bt::hex_encode(target.tip.block_hash).c_str(), missing.size());
    if (missing.empty()) {
        end_body_chain(c);
        try {
            TipRef nt{target.tip.block_hash, target.tip.main_block_hash};
            bool ready;
            {
                std::lock_guard<std::recursive_mutex> l(mu_);
                Txn t(*store_);
                ready = side_tips_tip_ready(t, archive_, side_tips_, nt); // NewTipReady
            }
            if (ready) reorg_to_tip(nt);
        } catch (const std::exception& e) {
            LOG_WARN("reorg failed: %s", e.what());
        }
        return;
    }
    size_t n = std::min<size_t>(missing.size(), 100);
    auto remaining = std::make_shared<std::atomic<size_t>>(n);
    auto stored = std::make_shared<std::atomic<size_t>>(0);
    for (size_t i = 0; i < n; i++) {
        net::Request q;
        q.kind = net::Request::GetBlock;
        q.block_hash = missing[i];
        Hash32 want = missing[i];
        send_request(c, q, net::BLOCK_RESPONSE_LIMIT, [this, c, target, want, remaining, stored](std::optional<net::Response> r) {
            if (r && r->kind == net::Response::Block && r->block.header.hash() == want) {
                std::lock_guard<std::recursive_mutex> l(mu_);
                Txn t(*store_);
                if (!archive_.body(t, want)) {
                    put_body_(t, want, r->block.body);
                    t.commit();
                }
                // The block asked for came: progress, even if another connection of the same peer stored it first
                // (the next round asks only for what is still missing, so this cannot loop).
                ++*stored;
            }
            if (--*remaining != 0) return;
            if (*stored == 0) {
                end_body_chain(c);
                LOG_INFO("peer: no block body delivered in a round; giving up on its tip");
                ep_->close(c, "no block bodies delivered");
                return;
            }
            request_bodies(c, target);
        });
    }
}

void Node::net_loop()
{
    int64_t last_hb = 0, last_status = 0;
    // Never blocks on the node lock or the mainchain: heartbeats must go out every
    // second or their peers drop us after HEARTBEAT_TIMEOUT_INTERVAL (5 s).
    while (running_) {
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
        int64_t now = now_s();
        // dial
        std::vector<std::string> to_dial;
        {
            std::lock_guard<std::mutex> l(peers_mu_);
            for (auto& [hp, when] : dial_targets_) {
                if (when < 0 || when > now) continue;
                bool connected = false;
                for (auto& [cid, p] : peers_)
                    if (p.dial == hp) connected = true;
                if (!connected) {
                    to_dial.push_back(hp);
                    when = -1; // in flight
                }
            }
        }
        for (auto& hp : to_dial) {
            auto parsed = bt::split_hostport(hp, net::DEFAULT_PORT);
            if (!parsed) {
                std::lock_guard<std::mutex> l(peers_mu_);
                LOG_WARN("dropping invalid peer address '%s'", hp.c_str());
                dial_targets_.erase(hp);
                continue;
            }
            std::string host = parsed->first;
            uint16_t port = parsed->second;
            auto addrs = bt::quic::resolve(host, port);
            std::optional<bt::quic::SockAddr> a;
            for (auto& x : addrs)
                if (x.ip.find(':') == std::string::npos) {
                    a = x;
                    break;
                }
            std::lock_guard<std::mutex> l(peers_mu_);
            if (!a || bt::sidechain::ban_active(banned_, a->ip, now)) {
                dial_targets_[hp] = now + 60;
                continue;
            }
            bool numeric = host.find_first_not_of("0123456789.") == std::string::npos;
            auto cid = ep_->connect(*a, numeric ? "localhost" : host);
            auto& p = peers_[cid];
            p.conn = cid;
            p.addr = *a;
            p.dial = hp;
        }
        // heartbeat every second (peer/mod.rs:137)
        if (now != last_hb) {
            last_hb = now;
            net::Request q;
            q.kind = net::Request::Heartbeat;
            {
                std::unique_lock<std::recursive_mutex> nl(mu_, std::try_to_lock);
                if (nl.owns_lock()) cached_tip_info_ = our_tip_info();
            }
            q.heartbeat.tip_info = cached_tip_info_;
            std::vector<bt::quic::ConnId> targets;
            {
                std::lock_guard<std::mutex> l(peers_mu_);
                for (auto& [c, p] : peers_)
                    if (p.connected) targets.push_back(c);
            }
            for (auto c : targets) send_request(c, q, 0, nullptr);
        }
        if (now - last_status >= 60) {
            last_status = now;
            LOG_INFO("%s", status().c_str());
        }
    }
}

void Node::post_serve(std::function<void()> f)
{
    {
        std::lock_guard<std::mutex> l(serve_mu_);
        serve_.push_back(std::move(f));
    }
    serve_cv_.notify_one();
}

void Node::serve_loop()
{
    while (running_) {
        std::function<void()> job;
        {
            std::unique_lock<std::mutex> l(serve_mu_);
            serve_cv_.wait_for(l, std::chrono::milliseconds(200), [&] { return !serve_.empty() || !running_; });
            if (!serve_.empty()) {
                job = std::move(serve_.front());
                serve_.pop_front();
            }
        }
        if (job) {
            try {
                job();
            } catch (const std::exception& e) {
                LOG_WARN("serve: %s", e.what());
            }
        }
    }
}

void Node::worker_loop()
{
    while (running_) {
        std::function<void()> job;
        {
            std::unique_lock<std::mutex> l(jobs_mu_);
            jobs_cv_.wait_for(l, std::chrono::milliseconds(200), [&] { return !jobs_.empty() || !running_; });
            if (!jobs_.empty()) {
                job = std::move(jobs_.front());
                jobs_.pop_front();
            }
        }
        if (job) {
            try {
                job();
            } catch (const std::exception& e) {
                LOG_WARN("net task: %s", e.what());
            }
        }
    }
}

} // namespace zside
