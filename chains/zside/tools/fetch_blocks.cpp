// Copyright (c) 2026 The Backbone developers
// Distributed under the MIT software license.
//
// zside-fetch-blocks: download full zSide blocks from a public betanet peer over the
// thunder-orchard QUIC protocol (client role only), for known-answer tests and archiving.
//
//   zside-fetch-blocks --peer seed.beta.ecash.eu.com:4098 --index blocks.jsonl \
//                        --out blocks.bin [--from 0] [--to 115] [--parallel 8]
//
// blocks.bin records: u32 height, u32 length, bincode(Block) as received (without magic).
#include <zside/net.h>

#include <bt/parse.h>
#include <bt/quic.h>

#include <univalue.h>

#include <algorithm>
#include <atomic>
#include <condition_variable>
#include <deque>
#include <cstdio>
#include <fstream>
#include <map>
#include <mutex>
#include <sstream>
#include <thread>

using namespace zside;

int main(int argc, char** argv)
{
    std::string peer = "seed.beta.ecash.eu.com:4098", index, out;
    uint32_t from = 0, to = UINT32_MAX;
    int parallel = 8;
    for (int i = 1; i + 1 < argc; i += 2) {
        std::string a = argv[i], v = argv[i + 1];
        if (a == "--peer") peer = v;
        else if (a == "--index") index = v;
        else if (a == "--out") out = v;
        else if (a == "--from") from = uint32_t(bt::parse_u64(v).value_or(0));
        else if (a == "--to") to = uint32_t(std::min<uint64_t>(bt::parse_u64(v).value_or(UINT32_MAX), UINT32_MAX));
        else if (a == "--parallel") parallel = int(std::clamp<uint64_t>(bt::parse_u64(v).value_or(8), 1, 100));
    }
    if (index.empty() || out.empty()) {
        std::fprintf(stderr, "usage: zside-fetch-blocks --index blocks.jsonl --out blocks.bin [--peer host:port] [--from N] [--to N]\n");
        return 2;
    }
    // block ids by height from the index dump; height 0 is the real genesis (block 1's parent)
    std::map<uint32_t, Hash32> ids;
    {
        std::ifstream f(index);
        std::string line;
        std::map<uint32_t, Hash32> prevs;
        while (std::getline(f, line)) {
            UniValue v;
            if (!v.read(line)) continue;
            uint32_t h = uint32_t(v["height"].getInt<int64_t>());
            ids[h] = *bt::hex_to_array<32>(v["id"].get_str());
            if (v["previousblockhash"].isStr()) prevs[h] = *bt::hex_to_array<32>(v["previousblockhash"].get_str());
        }
        if (prevs.count(1)) ids[0] = prevs[1];
    }
    auto hp = bt::split_hostport(peer, net::DEFAULT_PORT);
    if (!hp) {
        std::fprintf(stderr, "invalid --peer\n");
        return 2;
    }
    std::string host = hp->first;
    uint16_t port = hp->second;
    auto addrs = bt::quic::resolve(host, port);
    if (addrs.empty()) {
        std::fprintf(stderr, "cannot resolve %s\n", host.c_str());
        return 1;
    }
    bt::quic::SockAddr remote;
    for (auto& a : addrs)
        if (a.ip.find(':') == std::string::npos) {
            remote = a;
            break;
        }
    std::fprintf(stderr, "peer %s -> %s\n", host.c_str(), remote.to_string().c_str());

    auto magic = net::magic_bytes(net::Network::Betanet);
    std::mutex mu;
    std::condition_variable cv;
    bool connected = false, closed = false;
    std::string close_reason;
    bt::quic::Callbacks cb;
    cb.on_connected = [&](bt::quic::ConnId, const bt::quic::SockAddr&, bool) {
        std::lock_guard<std::mutex> l(mu);
        connected = true;
        cv.notify_all();
    };
    cb.on_request = [&](bt::quic::ConnId, int64_t, Bytes) {};
    cb.on_closed = [&](bt::quic::ConnId, const std::string& r) {
        std::lock_guard<std::mutex> l(mu);
        closed = true;
        close_reason = r;
        cv.notify_all();
    };
    bt::quic::Options opt;
    opt.accept_inbound = false;
    bt::quic::Endpoint ep(cb, opt);
    std::string err;
    if (!ep.start({"0.0.0.0", 0}, err)) {
        std::fprintf(stderr, "endpoint: %s\n", err.c_str());
        return 1;
    }
    auto conn = ep.connect(remote, host);
    {
        std::unique_lock<std::mutex> l(mu);
        cv.wait_for(l, std::chrono::seconds(15), [&] { return connected || closed; });
        if (!connected) {
            std::fprintf(stderr, "connect failed: %s\n", close_reason.c_str());
            ep.stop();
            return 1;
        }
    }
    std::fprintf(stderr, "connected\n");
    auto with_magic = [&](const Bytes& b) {
        Bytes r(magic.begin(), magic.end());
        r.insert(r.end(), b.begin(), b.end());
        return r;
    };
    std::atomic<bool> stop_hb{false};
    std::thread hb([&] {
        net::Request q;
        q.kind = net::Request::Heartbeat; // tip_info None, version 0.18.2
        Bytes payload = with_magic(net::encode(q));
        while (!stop_hb) {
            ep.send(conn, payload, 0, std::chrono::milliseconds(0), nullptr);
            for (int i = 0; i < 10 && !stop_hb; i++) std::this_thread::sleep_for(std::chrono::milliseconds(100));
        }
    });

    std::ofstream of(out, std::ios::binary | std::ios::app);
    std::map<uint32_t, Bytes> done;
    int inflight = 0, failures = 0;
    uint32_t written = 0, next_write = from;
    uint32_t last = std::min<uint32_t>(to, ids.empty() ? 0 : ids.rbegin()->first);
    std::deque<uint32_t> todo;
    for (uint32_t h = from; h <= last; h++) todo.push_back(h);
    std::unique_lock<std::mutex> l(mu);
    while ((!todo.empty() || inflight > 0) && !closed && failures < 20) {
        while (inflight < parallel && !todo.empty()) {
            uint32_t h = todo.front();
            todo.pop_front();
            net::Request q;
            q.kind = net::Request::GetBlock;
            q.block_hash = ids[h];
            inflight++;
            l.unlock();
            ep.send(conn, with_magic(net::encode(q)), net::BLOCK_RESPONSE_LIMIT, std::chrono::seconds(60), [&, h](std::optional<Bytes> resp) {
                std::lock_guard<std::mutex> g(mu);
                inflight--;
                if (!resp || resp->size() < 4 || !std::equal(magic.begin(), magic.end(), resp->begin())) {
                    std::fprintf(stderr, "height %u: no/invalid response\n", h);
                    failures++;
                    todo.push_back(h); // retry
                } else {
                    done[h] = Bytes(resp->begin() + 4, resp->end());
                }
                cv.notify_all();
            });
            l.lock();
        }
        cv.wait_for(l, std::chrono::seconds(1));
        // write contiguous completed heights
        while (!done.empty() && done.begin()->first == next_write) {
            auto it = done.begin();
            uint32_t h = it->first;
            next_write++;
            try {
                auto r = net::decode_response(it->second);
                if (r.kind != net::Response::Block) {
                    std::fprintf(stderr, "height %u: peer answered kind %u\n", h, unsigned(r.kind));
                } else if (r.block.header.hash() != ids[h]) {
                    std::fprintf(stderr, "height %u: header hash mismatch\n", h);
                    failures++;
                } else {
                    uint32_t len = uint32_t(it->second.size());
                    of.write((const char*)&h, 4);
                    of.write((const char*)&len, 4);
                    of.write((const char*)it->second.data(), len);
                    written++;
                    if (written % 100 == 0) std::fprintf(stderr, "  %u blocks\n", written);
                }
            } catch (const std::exception& e) {
                std::fprintf(stderr, "height %u: decode error %s\n", h, e.what());
                failures++;
            }
            done.erase(it);
        }
    }
    l.unlock();
    stop_hb = true;
    hb.join();
    ep.close(conn, "done");
    std::this_thread::sleep_for(std::chrono::milliseconds(200));
    ep.stop();
    std::fprintf(stderr, "wrote %u blocks, %d failures%s%s\n", written, failures, closed ? ", closed: " : "", close_reason.c_str());
    return failures ? 1 : 0;
}
