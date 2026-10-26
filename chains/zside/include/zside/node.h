// Copyright (c) 2026 The Backbone developers
// Distributed under the MIT software license.
//
// zSide node: state + archive + mempool on one store, the mainchain link (enforcer
// gRPC), block connection with two-way-peg windows and reorgs (port of thunder-orchard
// b225827 lib/node/{mod.rs, net_task.rs}), and the QUIC P2P layer.
#pragma once

#include <zside/archive.h>
#include <zside/net.h>
#include <zside/side_tips.h>
#include <zside/state.h>

// The P2P hardening shared with the sidechain template (rate_key, ban_active, HeadersBudgets).
#include <bt/sidechain/node.h>

#include <bt/enforcer.h>
#include <bt/kv.h>
#include <bt/quic.h>

#include <atomic>
#include <condition_variable>
#include <deque>
#include <functional>
#include <map>
#include <memory>
#include <mutex>
#include <set>
#include <thread>

namespace zside {

struct NodeConfig {
    std::string datadir;
    net::Network network = net::Network::Betanet;
    std::optional<std::array<uint8_t, 4>> magic_override;
    bt::quic::SockAddr net_addr{"0.0.0.0", net::DEFAULT_PORT};
    std::string mainchain_grpc_url = "http://localhost:50051";
    std::string mainchain_grpc_ca_cert;
    std::vector<std::string> add_peers; // host:port
    std::vector<std::string> server_names;
    bool use_seeds = true;
    bool p2p = true;
    bool rebuild_side_tips = false; // --bt-rebuild-side-tips
};

struct PeerView {
    bt::quic::SockAddr address;
    bool connected = false;
    bool inbound = false;
    std::string name; // bt::quic::Endpoint::peer_name: "<Name> <version>", "unknown (upstream)", "unknown"; empty until connected
    /** The height of the tip the peer last told of (its PeerState), unchecked: what the app's sync status compares ours
     *  with (bt::appui::sync_state), never what the node follows. */
    std::optional<uint32_t> tip_height;
};

class Node {
public:
    explicit Node(NodeConfig cfg);
    ~Node();
    bool start(std::string& err);
    void stop();
    /** Ban a remote address (keyed by bt::sidechain::rate_key) for `seconds`, as a misbehaving peer
     *  is banned; connected peers from it are closed. Used by the tests. */
    void ban_address(const std::string& ip, int64_t seconds);

    // ---- queries (all take the node lock)
    std::optional<Hash32> tip();
    std::optional<uint32_t> height();
    /** The height of our block last anchored on the mainchain that we know (bt::sidechain::anchored_height): the floor of
     *  the network's height in the app's sync status, display only. */
    std::optional<uint32_t> anchored_height();
    std::optional<Hash32> block_hash_at(uint32_t height);
    std::optional<Header> header(const Hash32& h);
    std::optional<Body> body(const Hash32& h);
    std::optional<Hash32> best_main_verification(const Hash32& side);
    std::vector<Hash32> bmm_inclusions(const Hash32& side);
    std::vector<std::pair<OutPoint, Output>> utxos();
    std::vector<std::pair<OutPoint, Output>> utxos_by_addresses(const std::set<Address>& a);
    std::vector<std::pair<OutPoint, SpentOutput>> stxos_by_addresses(const std::set<Address>& a);
    std::optional<std::pair<Transaction, std::optional<Hash32>>> transaction(const Hash32& txid);
    std::optional<std::pair<WithdrawalBundleInfo, BundleStatus>> withdrawal_bundle(const Hash32& m6id);
    std::optional<WithdrawalBundle> pending_withdrawal_bundle();
    std::optional<uint32_t> latest_failed_withdrawal_bundle_height();
    uint64_t sidechain_wealth();
    bt::utreexo::MemForest tip_accumulator();
    std::vector<PeerView> peers();
    std::vector<AuthorizedTransaction> mempool();

    // ---- actions
    /** Node::submit_block (node/mod.rs:720-858). Returns accepted-as-new-tip. */
    bool submit_block(const Hash32& main_block_hash, const Header& h, const Body& b);
    /** regenerate proof, validate, add to mempool, relay. Throws StateError. */
    void submit_transaction(AuthorizedTransaction& tx);
    void remove_from_mempool(const Hash32& txid);
    void invalidate_block(const Hash32& h);
    bool connect_peer(const std::string& hostport, std::string& err);
    bool forget_peer(const std::string& hostport);
    /** Ensure mainchain header/block infos for `main` and its ancestors. */
    bool request_mainchain_ancestor_infos(const Hash32& main);
    /** Mempool selection for templates (get_transactions(1000)). */
    std::pair<std::vector<std::pair<AuthorizedTransaction, std::vector<Output>>>, uint64_t> mempool_transactions(size_t n);

    bt::enforcer::Client& enforcer() { return *enforcer_; }
    Archive& archive() { return archive_; }
    State& state() { return state_; }
    SideTips& side_tips() { return side_tips_; }
    std::recursive_mutex& lock() { return mu_; }
    bt::kv::Store& store() { return *store_; }
    const NodeConfig& config() const { return cfg_; }

    /** Status line for logs. */
    std::string status();

private:
    NodeConfig cfg_;
    std::unique_ptr<bt::kv::Store> store_;
    State state_;
    Archive archive_;
    SideTips side_tips_;
    std::unique_ptr<bt::enforcer::Client> enforcer_;
    std::recursive_mutex mu_;
    std::map<Hash32, AuthorizedTransaction> mempool_;
    std::map<std::array<uint8_t, 37>, Hash32> mempool_spent_;
    std::map<Hash32, Hash32> mempool_nullifiers_; // lib/mempool/mod.rs used_nullifiers
    std::atomic<bool> running_{false};
    std::thread main_thread_, net_thread_, worker_thread_, serve_thread_;
    std::mutex main_mu_;

    // reorg / connect (net_task.rs)
    void connect_tip_(bt::kv::Txn& t, const Header& h, const Body& b, const bt::mainchain::TwoWayPegData& d);
    void disconnect_tip_(bt::kv::Txn& t);
    bool reorg_to_tip(const TipRef& new_tip);
    std::vector<Hash32> main_ancestors(const bt::kv::Txn& t, const Hash32& from, const std::optional<Hash32>& stop);
    void mempool_put(const AuthorizedTransaction& tx);
    void mempool_delete(const Hash32& txid);
    void mempool_regenerate_proofs(bt::kv::Txn& t);
    void mainchain_loop();
    /** mainchain_task.rs sync_side_tips_to_tip, then (when it moved) handle_mainchain_block_event. */
    bool sync_to_mainchain_tip(const Hash32& main_tip);
    void handle_mainchain_block_event();
    bool catch_up_mainchain();
    void put_body_(bt::kv::Txn& t, const Hash32& h, const Body& b);
    void delete_body_(bt::kv::Txn& t, const Hash32& h);

    // P2P
    struct Peer {
        bt::quic::ConnId conn = 0;
        bt::quic::SockAddr addr;
        std::string dial; // host:port we dialed (empty for inbound)
        bool connected = false, inbound = false;
        std::string name; // bt::quic::Endpoint::peer_name
        std::optional<net::PeerState> state;
        std::set<Hash32> requested_blocks;
        bool headers_pending = false;
        bool bodies_chain = false; // a request_bodies chain is running for this peer
        int64_t last_sync_try = 0; // when its tip was last looked at (handle_peer_state)
    };
    std::unique_ptr<bt::quic::Endpoint> ep_;
    std::mutex peers_mu_;
    std::map<bt::quic::ConnId, Peer> peers_;
    std::map<std::string, int64_t> dial_targets_; // host:port -> next dial time
    std::map<std::string, int64_t> banned_;       // bt::sidechain::rate_key(ip) -> until
    bt::sidechain::HeadersBudgets headers_budgets_; // GetHeaders per remote IP, under peers_mu_
    std::array<uint8_t, 4> magic_{};
    std::optional<net::TipInfo> cached_tip_info_;
    std::mutex jobs_mu_;
    std::condition_variable jobs_cv_;
    std::deque<std::function<void()>> jobs_;
    void post_job(std::function<void()> f);
    void net_loop();
    void worker_loop();
    void serve_loop();
    void post_serve(std::function<void()> f);
    std::mutex serve_mu_;
    std::condition_variable serve_cv_;
    std::deque<std::function<void()>> serve_;
    void on_request(bt::quic::ConnId c, int64_t stream, Bytes payload);
    void send_request(bt::quic::ConnId c, const net::Request& q, size_t limit, std::function<void(std::optional<net::Response>)> fn);
    void handle_peer_state(bt::quic::ConnId c, const net::PeerState& ps);
    void on_headers(bt::quic::ConnId c, const net::TipInfo& target, const std::vector<Header>& hs);
    void request_bodies(bt::quic::ConnId c, const net::TipInfo& target);
    void start_body_chain(bt::quic::ConnId c, const net::TipInfo& target);
    void end_body_chain(bt::quic::ConnId c);
    void ban(bt::quic::ConnId c, const std::string& why);
    std::optional<net::TipInfo> our_tip_info();
    void relay_tx(const AuthorizedTransaction& tx, std::optional<bt::quic::ConnId> except);
};

} // namespace zside
