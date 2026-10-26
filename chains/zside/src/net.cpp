// Copyright (c) 2026 The Backbone developers
// Distributed under the MIT software license.
#include <zside/net.h>

namespace zside::net {

using bt::DecodeError;

std::array<uint8_t, 4> magic_bytes(Network n)
{
    std::array<uint8_t, 4> m{0b1000'1101, 0b0001'1001, 0b0010'1000, 0b0000'0000}; // "ZSIDE" (message.rs:19-37)
    switch (n) {
    case Network::Regtest: m[3] |= 0; break;
    case Network::Signet: m[3] |= 1; break;
    case Network::Forknet: m[3] |= 2; break;
    case Network::Betanet: m[3] |= 4; break;
    }
    return m;
}

static void enc_peer_state(Writer& w, const PeerState& p)
{
    if (p.tip_info) {
        w.u8(1);
        w.u32(p.tip_info->block_height);
        w.raw(p.tip_info->tip.block_hash);
        w.bincode_bytes(p.tip_info->tip.main_block_hash.span());
        w.bincode_bytes(p.tip_info->total_work_be.span());
    } else {
        w.u8(0);
    }
    w.u64(p.version.major);
    w.u64(p.version.minor);
    w.u64(p.version.patch);
}

static PeerState dec_peer_state(Reader& r)
{
    PeerState p;
    uint8_t opt = r.u8();
    if (opt == 1) {
        TipInfo t;
        t.block_height = r.u32();
        t.tip.block_hash = r.array<32>();
        Bytes mb = r.bincode_bytes();
        if (mb.size() != 32) throw DecodeError("bad main block hash");
        t.tip.main_block_hash = Hash32::from_span(mb);
        Bytes wb = r.bincode_bytes();
        if (wb.size() != 32) throw DecodeError("bad work");
        t.total_work_be = Hash32::from_span(wb);
        p.tip_info = t;
    } else if (opt != 0) {
        throw DecodeError("bad Option tag");
    }
    p.version.major = r.u64();
    p.version.minor = r.u64();
    p.version.patch = r.u64();
    return p;
}

Bytes encode(const Request& q)
{
    Writer w;
    w.u32(q.kind);
    switch (q.kind) {
    case Request::Heartbeat: enc_peer_state(w, q.heartbeat); break;
    case Request::GetBlock: w.raw(q.block_hash); break;
    case Request::GetHeaders:
        w.bincode_len(q.start.size());
        for (auto& h : q.start) w.raw(h);
        w.raw(q.end);
        break;
    case Request::PushTransaction: bincode(w, q.tx); break;
    }
    return w.buf;
}

Request decode_request(ByteSpan b)
{
    Reader r(b);
    Request q;
    uint32_t tag = r.u32();
    switch (tag) {
    case Request::Heartbeat:
        q.kind = Request::Heartbeat;
        q.heartbeat = dec_peer_state(r);
        break;
    case Request::GetBlock:
        q.kind = Request::GetBlock;
        q.block_hash = r.array<32>();
        break;
    case Request::GetHeaders: {
        q.kind = Request::GetHeaders;
        size_t n = r.bincode_len(32);
        for (size_t i = 0; i < n; i++) q.start.push_back(r.array<32>());
        q.end = r.array<32>();
        break;
    }
    case Request::PushTransaction:
        q.kind = Request::PushTransaction;
        q.tx = de_authorized_transaction(r);
        break;
    default: throw DecodeError("unknown request tag");
    }
    // bincode::deserialize (legacy config) ignores trailing bytes
    return q;
}

Bytes encode(const Response& s)
{
    Writer w;
    w.u32(s.kind);
    switch (s.kind) {
    case Response::Block: bincode(w, s.block); break;
    case Response::Headers:
        w.bincode_len(s.headers.size());
        for (auto& h : s.headers) bincode(w, h);
        break;
    case Response::NoBlock:
    case Response::NoHeader:
    case Response::TransactionAccepted:
    case Response::TransactionRejected: w.raw(s.hash); break;
    }
    return w.buf;
}

Response decode_response(ByteSpan b)
{
    Reader r(b);
    Response s;
    uint32_t tag = r.u32();
    switch (tag) {
    case Response::Block:
        s.kind = Response::Block;
        s.block.header = de_header(r);
        s.block.body = de_body(r);
        break;
    case Response::Headers: {
        s.kind = Response::Headers;
        size_t n = r.bincode_len(32 + 1 + 40 + 8);
        for (size_t i = 0; i < n; i++) s.headers.push_back(de_header(r));
        break;
    }
    case Response::NoBlock:
    case Response::NoHeader:
    case Response::TransactionAccepted:
    case Response::TransactionRejected:
        s.kind = Response::Kind(tag);
        s.hash = r.array<32>();
        break;
    default: throw DecodeError("unknown response tag");
    }
    return s;
}

} // namespace zside::net
