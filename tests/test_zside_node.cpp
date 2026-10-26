// P2P hardening of the zSide node (core bt/sidechain/node.h helpers, review 2026-10-22), over real QUIC
// on loopback:
//   - GetHeaders: at most GETHEADERS_PER_MINUTE per remote IP, kept across reconnects;
//   - bans: an inbound connection from a banned address is closed at connect and none of its
//     requests is answered; keys are rate_key()s (IPv4-mapped IPv6 as its IPv4, IPv6 by /64).
#include "test.h"

#include <zside/net.h>
#include <zside/node.h>

#include <bt/quic.h>
#include <bt/sidechain/node.h>

#include <atomic>
#include <chrono>
#include <filesystem>
#include <thread>
#include <unistd.h>

using namespace zside;

namespace {

template <class P>
bool wait_for(P pred)
{
    for (int i = 0; i < 100 && !pred(); i++) std::this_thread::sleep_for(std::chrono::milliseconds(50));
    return pred();
}

struct Client {
    std::atomic<int> connected{0}, closed{0};
    bt::quic::Endpoint ep;
    static bt::quic::Callbacks callbacks(Client* self)
    {
        bt::quic::Callbacks cb;
        cb.on_connected = [self](bt::quic::ConnId, const bt::quic::SockAddr&, bool) { ++self->connected; };
        cb.on_request = [](bt::quic::ConnId, int64_t, bt::Bytes) {};
        cb.on_closed = [self](bt::quic::ConnId, const std::string&) { ++self->closed; };
        return cb;
    }
    static bt::quic::Options options()
    {
        bt::quic::Options opt;
        opt.accept_inbound = false;
        return opt;
    }
    Client() : ep(callbacks(this), options()) {}
    /** Connects, sends `requests` copies of `payload`, closes; returns how many got an answer
     *  (-1 = no connection). `*was_closed` = the node closed it before we did. */
    int session(uint16_t port, const bt::Bytes& payload, int requests, bool* was_closed = nullptr)
    {
        int before_conn = connected, before_closed = closed;
        auto c = ep.connect({"127.0.0.1", port}, "localhost");
        if (!wait_for([&] { return connected > before_conn || closed > before_closed; })) return -1;
        std::atomic<int> answered{0}, failed{0};
        for (int i = 0; i < requests; i++) {
            ep.send(c, payload, 1 << 20, std::chrono::milliseconds(3000), [&](std::optional<bt::Bytes> r) { r ? ++answered : ++failed; });
            std::this_thread::sleep_for(std::chrono::milliseconds(5));
        }
        wait_for([&] { return answered + failed == requests; });
        if (was_closed) *was_closed = closed > before_closed;
        ep.close(c, "done");
        wait_for([&] { return closed > before_closed; });
        return int(answered);
    }
};

NodeConfig regtest_config(const std::string& dir, uint16_t port)
{
    NodeConfig cfg;
    cfg.datadir = dir;
    cfg.network = net::Network::Regtest;
    cfg.use_seeds = false;
    cfg.net_addr = {"127.0.0.1", port};
    cfg.mainchain_grpc_url = "http://127.0.0.1:9"; // no enforcer: the P2P side is what is tested
    return cfg;
}

bt::Bytes request_payload(const net::Request& q)
{
    auto magic = net::magic_bytes(net::Network::Regtest);
    bt::Bytes payload(magic.begin(), magic.end());
    bt::append(payload, net::encode(q));
    return payload;
}

} // namespace

TEST(zside_node_getheaders_limit_per_ip_survives_reconnect)
{
    const uint16_t port = 49231;
    std::string dir = std::filesystem::temp_directory_path().string() + "/bt-zside-p2p-gh-" + std::to_string(::getpid());
    std::filesystem::remove_all(dir);
    {
        Node n(regtest_config(dir, port));
        std::string err;
        REQUIRE(n.start(err));
        Client cl;
        REQUIRE(cl.ep.start({"127.0.0.1", 0}, err));
        net::Request q;
        q.kind = net::Request::GetHeaders; // unknown `end`: answered NoHeader, still charged
        auto payload = request_payload(q);
        bool was_closed = false;
        int first = cl.session(port, payload, int(bt::sidechain::GETHEADERS_PER_MINUTE) + 5, &was_closed);
        CHECK_EQ(first, int(bt::sidechain::GETHEADERS_PER_MINUTE));
        CHECK(was_closed); // the node closed the connection past the budget
        int second = cl.session(port, payload, 3);
        CHECK_EQ(second, 0); // a new connection from the same IP is still limited (was per connection)
        cl.ep.stop();
        n.stop();
    }
    std::filesystem::remove_all(dir);
}

TEST(zside_node_banned_address_is_refused_inbound)
{
    const uint16_t port = 49232;
    std::string dir = std::filesystem::temp_directory_path().string() + "/bt-zside-p2p-ban-" + std::to_string(::getpid());
    std::filesystem::remove_all(dir);
    {
        Node n(regtest_config(dir, port));
        std::string err;
        REQUIRE(n.start(err));
        Client cl;
        REQUIRE(cl.ep.start({"127.0.0.1", 0}, err));
        net::Request q;
        q.kind = net::Request::GetBlock; // cheap request, answered NoBlock when allowed
        auto payload = request_payload(q);
        CHECK_EQ(cl.session(port, payload, 2), 2); // not banned: answered
        // Banned as its IPv4-mapped IPv6 spelling: the same key as 127.0.0.1.
        n.ban_address("::ffff:127.0.0.1", 3600);
        bool was_closed = false;
        int answered = cl.session(port, payload, 2, &was_closed);
        CHECK_EQ(answered, 0);
        CHECK(was_closed);
        cl.ep.stop();
        n.stop();
    }
    std::filesystem::remove_all(dir);
}

TEST(zside_node_rate_keys)
{
    using bt::sidechain::rate_key;
    CHECK_EQ(rate_key("::ffff:1.2.3.4"), std::string("1.2.3.4"));
    CHECK_EQ(rate_key("2001:db8:1:2:aaaa::1"), std::string("2001:db8:1:2::/64"));
    std::map<std::string, int64_t> banned{{rate_key("1.2.3.4"), 100}};
    CHECK(bt::sidechain::ban_active(banned, "::ffff:1.2.3.4", 50));
    CHECK(!bt::sidechain::ban_active(banned, "1.2.3.4", 100)); // expired
    bt::sidechain::HeadersBudgets b;
    for (uint32_t i = 0; i < bt::sidechain::GETHEADERS_PER_MINUTE; i++) CHECK(b.take("::ffff:9.9.9.9", 0));
    CHECK(!b.take("9.9.9.9", 1)); // same key, same window
    CHECK(b.take("9.9.9.9", 61));  // next window
}
